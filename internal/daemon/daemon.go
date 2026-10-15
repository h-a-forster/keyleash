// Package daemon wires keyleash's engine packages together (docs/DAEMON.md):
// it owns the Locked / Unlocked / Away / Tripped state machine, implements the
// proxy's policy interfaces (Authenticator, Gate, KeySource, Meter adapter,
// PeerResolver), keeps the ledger and audit log authenticated with keys held
// only while unlocked, and serves the admin channel (HTTP/JSON over an
// owner-only named pipe or Unix socket).
//
// Start opens everything and returns a running *Daemon (the in-process
// handle tests use); Run is Start plus waiting for ctx and shutting down.
// Init creates a new data directory offline (vault, recovery code, config).
//
// Fail-closed rules applied throughout: anything that cannot be verified
// (integrity of the ledger or state file, audit writes, process binding,
// pricing) denies, trips or charges the reserved amount; secrets never reach
// logs, errors, audit records or argv.
package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/h-a-forster/keyleash/internal/approval"
	"github.com/h-a-forster/keyleash/internal/audit"
	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/meter"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/presence"
	"github.com/h-a-forster/keyleash/internal/procinfo"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/proxy"
	"github.com/h-a-forster/keyleash/internal/runjob"
	"github.com/h-a-forster/keyleash/internal/secmem"
	"github.com/h-a-forster/keyleash/internal/vault"
	"github.com/h-a-forster/keyleash/internal/winhello"
)

// File and directory names inside the data directory (docs/DAEMON.md).
const (
	VaultFile    = "vault.json"
	PassesFile   = "passes.json"
	LedgerDir    = "ledger"
	AuditDir     = "audit"
	StateFile    = "state.json"
	ConfigFile   = "config.toml"
	InstanceLock = "daemon.lock"
)

// ShutdownGrace bounds the wait for in-flight requests at shutdown (a
// variable so tests can shorten it).
var ShutdownGrace = 30 * time.Second

// Tunables of the daemon's background work.
const (
	// InFlightMaxAge is how old a reservation may get before it is settled
	// at its reserved amount (fail closed). It exceeds the proxy's response
	// header timeout plus its stream idle timeout.
	InFlightMaxAge = 30 * time.Minute
	// StateSaveEvery is how often the ledger checkpoint (vault) and state.json are saved while
	// unlocked (it is also saved on lock and shutdown).
	StateSaveEvery = VaultCheckpointEvery
	expireEvery    = time.Minute
	passSweepEvery = 30 * time.Second
	housekeepTick  = time.Second
	adminBodyLimit = 1 << 20
)

// Clock supplies time and timers. Tests inject a fake one.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Options configures Start. Zero fields take production defaults.
type Options struct {
	// DataDir is the data directory (default: DefaultDataDir()).
	DataDir string
	// Config is the effective configuration (default: config.Load of
	// <data>/config.toml). It is validated either way.
	Config *config.Config
	// Clock defaults to the system clock.
	Clock Clock
	// PresenceSource defaults to the OS source (presence.NewOSSourceWithOptions).
	PresenceSource presence.Source
	// Approver defaults to the one named by config approval.method.
	Approver approval.Approver
	// HelloAvailable defaults to winhello.Available.
	HelloAvailable func() (bool, string)
	// Upstream and Transport override the proxy's upstream (tests).
	Upstream  func(*provider.Provider) *url.URL
	Transport http.RoundTripper
	// ProxyListener defaults to 127.0.0.1:<proxy.port>. It must be loopback.
	ProxyListener net.Listener
	// AdminListener defaults to the owner-only named pipe (Windows) or
	// <data>/admin.sock (elsewhere).
	AdminListener net.Listener
	// Logger receives operational messages (never secrets). Default: stderr.
	Logger *slog.Logger
	// PeerResolver maps a proxy connection to its client process (default:
	// procinfo.PeerPID + procinfo.Lookup). Errors mean "unknown client".
	PeerResolver proxy.PeerResolver
	// IsDescendant checks pass process binding (default procinfo.IsDescendant).
	IsDescendant func(pid int, ancestor procinfo.Process) (bool, error)
	// LookupProcess resolves a PID for pass binding (default procinfo.Lookup).
	LookupProcess func(pid int) (procinfo.Process, error)
	// ConsoleIn / ConsoleOut are used by the "console" approver (default
	// os.Stdin / os.Stderr).
	ConsoleIn  io.Reader
	ConsoleOut io.Writer
	// AdminPeerPID returns the client PID of an admin connection (default:
	// GetNamedPipeClientProcessId on Windows, SO_PEERCRED / LOCAL_PEERPID on
	// Unix). An error means "unknown": the caller is then confined for
	// mutating calls (spec §12).
	AdminPeerPID func(net.Conn) (int, error)
	// Jobs confines run passes' process trees (default: Windows job
	// objects via internal/runjob; none elsewhere).
	Jobs JobManager

	// manualPresence (tests) disables the presence goroutine; tests drive
	// the monitor with stepPresence.
	manualPresence bool
	// manualHousekeeping (tests) disables the housekeeping ticker; tests
	// call housekeep.
	manualHousekeeping bool
}

// Daemon is a running keyleash daemon. Create it with Start.
type Daemon struct {
	opts    Options
	cfg     *config.Config
	dataDir string
	log     *slog.Logger
	clk     Clock

	instance io.Closer
	vault    *vault.Vault
	passes   *pass.Store
	ledger   *budget.Ledger
	audit    *audit.Log
	meter    *meter.Meter
	queue    *approval.Queue

	presSrc  presence.Source
	osSource *presence.OSSource
	monitor  *presence.Monitor

	proxy    *proxy.Server
	proxyLn  net.Listener
	adminLn  net.Listener
	adminSrv *http.Server

	isDescendant   func(int, procinfo.Process) (bool, error)
	lookupProcess  func(int) (procinfo.Process, error)
	helloAvailable func() (bool, string)
	adminPeerPID   func(net.Conn) (int, error)
	jobs           JobManager

	// configured is the approver config.approval.method names (or
	// Options.Approver); console is the shared console approver.
	configured approval.Approver
	consoleMu  sync.Mutex
	console    approval.Approver

	// overrideSHA is the hex SHA-256 of the pricing override file's bytes
	// as loaded ("" without an override); overridePath its resolved path.
	overridePath, overrideSHA string

	// vsMu guards vs, the cached daemon-state vault entry (vaultstate.go).
	vsMu sync.Mutex
	vs   *vaultState

	// secretMu guards the rate limit on secrets entered to approve.
	secretMu       sync.Mutex
	secretInFlight bool
	secretCallers  map[string]*secretFailures
	secretGlobal   secretFailures

	// unlockMu serialises slow vault operations (unlock, re-key).
	unlockMu sync.Mutex

	// auditMu guards the audit health flag.
	auditMu     sync.Mutex
	auditBroken bool

	mu sync.RWMutex
	st stateData

	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	proxyWG  sync.WaitGroup
	closeMu  sync.Mutex
	closed   bool
	closeErr error
	fatalCh  chan error
	// stopCh is closed when an admin caller asks the daemon to stop
	// (POST /v1/shutdown); Run then shuts down as on a signal.
	stopCh   chan struct{}
	stopOnce sync.Once
}

// DefaultDataDir returns the data directory: $KEYLEASH_HOME if set, else
// %LOCALAPPDATA%\keyleash on Windows, ~/Library/Application Support/keyleash
// on macOS and $XDG_CONFIG_HOME/keyleash (or ~/.config/keyleash) elsewhere.
func DefaultDataDir() (string, error) {
	if h := os.Getenv("KEYLEASH_HOME"); h != "" {
		return filepath.Abs(h)
	}
	switch runtime.GOOS {
	case "windows":
		if la := os.Getenv("LOCALAPPDATA"); la != "" {
			return filepath.Join(la, "keyleash"), nil
		}
		return "", errors.New("keyleash: LOCALAPPDATA is not set; set KEYLEASH_HOME")
	case "darwin":
		d, err := os.UserConfigDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(d, "keyleash"), nil
	default:
		if x := os.Getenv("XDG_CONFIG_HOME"); x != "" && filepath.IsAbs(x) {
			return filepath.Join(x, "keyleash"), nil
		}
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, ".config", "keyleash"), nil
	}
}

// Run starts the daemon and serves until ctx is done, a server fails or an
// admin caller asks it to stop (keyleash stop), then shuts down.
func Run(ctx context.Context, opts Options) error {
	d, err := Start(ctx, opts)
	if err != nil {
		return err
	}
	var runErr error
	select {
	case <-ctx.Done():
	case <-d.stopCh:
	case runErr = <-d.fatalCh:
	}
	if err := d.Close(); err != nil && runErr == nil {
		runErr = err
	}
	return runErr
}

// Start performs the start-up sequence of docs/DAEMON.md and returns a
// running daemon in state Locked. ctx bounds the daemon's lifetime; Close
// shuts it down explicitly.
func Start(ctx context.Context, opts Options) (_ *Daemon, err error) {
	d := &Daemon{opts: opts, fatalCh: make(chan error, 4), stopCh: make(chan struct{})}
	d.log = opts.Logger
	if d.log == nil {
		d.log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	d.clk = opts.Clock
	if d.clk == nil {
		d.clk = realClock{}
	}
	d.isDescendant = opts.IsDescendant
	if d.isDescendant == nil {
		d.isDescendant = procinfo.IsDescendant
	}
	d.lookupProcess = opts.LookupProcess
	if d.lookupProcess == nil {
		d.lookupProcess = procinfo.Lookup
	}
	d.helloAvailable = opts.HelloAvailable
	if d.helloAvailable == nil {
		d.helloAvailable = winhello.Available
	}
	d.adminPeerPID = opts.AdminPeerPID
	if d.adminPeerPID == nil {
		d.adminPeerPID = connPeerPID
	}
	d.secretCallers = map[string]*secretFailures{}

	var cleanup []func()
	defer func() {
		if err != nil {
			for i := len(cleanup) - 1; i >= 0; i-- {
				cleanup[i]()
			}
		}
	}()

	// 1. Harden, resolve and secure the data dir.
	if herr := secmem.HardenProcess(); herr != nil {
		d.log.Warn("process hardening incomplete", "err", herr)
	}
	d.dataDir = opts.DataDir
	if d.dataDir == "" {
		if d.dataDir, err = DefaultDataDir(); err != nil {
			return nil, err
		}
	}
	if d.dataDir, err = filepath.Abs(d.dataDir); err != nil {
		return nil, fmt.Errorf("keyleash: data dir: %w", err)
	}
	if err = vault.SecureDir(d.dataDir); err != nil {
		return nil, fmt.Errorf("keyleash: secure data dir: %w", err)
	}

	// 2. Single instance.
	if d.instance, err = acquireInstanceLock(filepath.Join(d.dataDir, InstanceLock)); err != nil {
		return nil, err
	}
	cleanup = append(cleanup, func() { d.instance.Close() })

	// 3. Config.
	d.cfg = opts.Config
	if d.cfg == nil {
		if d.cfg, err = config.Load(filepath.Join(d.dataDir, ConfigFile)); err != nil {
			return nil, fmt.Errorf("keyleash: refusing to start with an invalid config: %w", err)
		}
	} else if err = d.cfg.Validate(); err != nil {
		return nil, fmt.Errorf("keyleash: refusing to start with an invalid config: %w", err)
	}

	// 4. Vault (locked), passes, ledger, audit, pricing.
	vpath := filepath.Join(d.dataDir, VaultFile)
	if d.vault, err = vault.Open(vpath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("keyleash: no vault in %s; run `keyleash init` first", d.dataDir)
		}
		return nil, fmt.Errorf("keyleash: open vault: %w", err)
	}
	cleanup = append(cleanup, d.vault.Lock)
	if d.passes, err = pass.OpenStore(filepath.Join(d.dataDir, PassesFile), d.clk); err != nil {
		return nil, fmt.Errorf("keyleash: open pass store: %w", err)
	}
	d.passes.SetCommitHook(d.onPassCommit)
	d.jobs = opts.Jobs
	if d.jobs == nil && runjob.Supported() {
		if m := runjob.New(d.cfg.Run.KillOnDaemonExit); m != nil {
			d.jobs = m
		}
	}
	if d.jobs != nil {
		cleanup = append(cleanup, d.jobs.Close)
	}
	if d.ledger, err = budget.Open(budget.Options{Dir: filepath.Join(d.dataDir, LedgerDir), Clock: d.clk}); err != nil {
		return nil, fmt.Errorf("keyleash: open ledger: %w", err)
	}
	cleanup = append(cleanup, func() { d.ledger.Close() })
	if err = os.MkdirAll(filepath.Join(d.dataDir, AuditDir), 0o700); err != nil {
		return nil, fmt.Errorf("keyleash: audit dir: %w", err)
	}
	if d.audit, err = audit.Open(filepath.Join(d.dataDir, AuditDir), d.clk); err != nil {
		return nil, fmt.Errorf("keyleash: open audit log: %w", err)
	}
	cleanup = append(cleanup, func() { d.audit.Close() })
	override := d.cfg.Pricing.Override
	if override != "" && !filepath.IsAbs(override) {
		override = filepath.Join(d.dataDir, override)
	}
	// The override's bytes are read once: they are what is priced with and
	// what the accepted config covers (spec §14).
	var overrideData []byte
	if override != "" {
		if overrideData, err = meter.ReadPricingOverride(override); err != nil {
			return nil, fmt.Errorf("keyleash: load pricing: %w", err)
		}
		sum := sha256.Sum256(overrideData)
		d.overridePath, d.overrideSHA = override, hex.EncodeToString(sum[:])
	}
	pricing, err := meter.LoadPricingData(overrideData, override)
	if err != nil {
		return nil, fmt.Errorf("keyleash: load pricing: %w", err)
	}
	d.meter = &meter.Meter{
		Pricing:               pricing,
		AssumeMaxOutputTokens: d.cfg.Models.AssumeMaxOutputTokens,
		AddStreamUsage:        d.cfg.Proxy.AddStreamUsage,
	}

	// Approvals.
	d.configured = opts.Approver
	if d.configured == nil {
		d.configured = d.approverFor(d.cfg.Approval.Method, false)
	}
	d.queue = approval.NewQueue(d.configured, d.cfg.Approval.Timeout.Duration, d.clk)

	// 5. Limits.
	d.st = stateData{state: StateLocked, concScopes: map[string]bool{}, modelsSeen: map[string]bool{}}
	d.applyLimits()
	if d.cfg.Tripwire.Threshold != nil && d.cfg.Tripwire.Window.Duration > 0 {
		d.ledger.SetTripwire(d.cfg.Tripwire.Window.Duration, d.cfg.Tripwire.Threshold.Micros, func(spent money.Micros) {
			go d.trip("velocity", fmt.Sprintf("spend %s in %s crossed the tripwire", spent, d.cfg.Tripwire.Window.Duration))
		})
	}

	// 6. Presence, admin server, proxy.
	d.presSrc = opts.PresenceSource
	if d.presSrc == nil {
		src, perr := presence.NewOSSourceWithOptions(presence.Options{CountInjected: d.cfg.Presence.CountInjectedInput})
		if perr != nil {
			// Fail closed: a source that always errors reads as Idle.
			d.log.Warn("presence source unavailable; treating the owner as away", "err", perr)
			src = presence.NewOSSource()
		}
		d.presSrc = src
	}
	if osrc, ok := d.presSrc.(*presence.OSSource); ok {
		d.osSource = osrc
		cleanup = append(cleanup, func() { osrc.Close() })
	}
	d.monitor = presence.NewMonitor(d.presSrc, d.clk, presence.Config{
		IdleAfter: d.cfg.Presence.IdleAfter.Duration,
		Poll:      d.cfg.Presence.Poll.Duration,
	})

	d.ctx, d.cancel = context.WithCancel(ctx)
	cleanup = append(cleanup, d.cancel)

	d.adminLn = opts.AdminListener
	if d.adminLn == nil {
		if d.adminLn, err = listenAdmin(d.dataDir); err != nil {
			return nil, err
		}
	}
	cleanup = append(cleanup, func() { d.adminLn.Close() })

	d.proxyLn = opts.ProxyListener
	if d.proxyLn == nil {
		if d.proxyLn, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", d.cfg.Proxy.Port)); err != nil {
			return nil, fmt.Errorf("keyleash: proxy listen: %w", err)
		}
	}
	cleanup = append(cleanup, func() { d.proxyLn.Close() })

	peers := opts.PeerResolver
	if peers == nil {
		peers = d.resolvePeer
	}
	d.proxy, err = proxy.New(proxy.Config{
		Addr:           d.proxyLn.Addr().String(),
		BodyLimit:      d.cfg.Proxy.BodyLimit,
		AllowedOrigins: d.cfg.Proxy.AllowedOrigins,
		Upstream:       opts.Upstream,
		Transport:      opts.Transport,
		ErrorLog:       slog.NewLogLogger(d.log.Handler(), slog.LevelWarn),
	}, authenticator{d}, gate{d}, keySource{d}, meterAdapter{d.meter}, peers)
	if err != nil {
		return nil, fmt.Errorf("keyleash: proxy: %w", err)
	}

	d.adminSrv = &http.Server{
		Handler:           d.guard(d.adminHandler()),
		ConnContext:       d.connContext,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext:       func(net.Listener) context.Context { return d.ctx },
	}

	// 7. Audit daemon_start; state Locked. Everything below only starts
	// goroutines.
	d.auditEvent("daemon_start", map[string]any{
		"vault_id": d.vault.ID(), "recovered_from_prev": d.vault.RecoveredFromPrev(),
		"proxy": d.proxyLn.Addr().String(), "profile": d.cfg.Profile,
	})
	// Run passes from an earlier daemon have no job here, so their processes
	// cannot be confined any more: end those passes (spec §12).
	if d.jobs != nil {
		d.revokeOrphanedRunPasses()
	}
	if d.vault.RecoveredFromPrev() {
		d.log.Warn("vault was recovered from vault.prev (main file missing or corrupt)")
	}

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		if serr := d.adminSrv.Serve(d.adminLn); serr != nil && !errors.Is(serr, http.ErrServerClosed) && d.ctx.Err() == nil {
			d.fatal(fmt.Errorf("keyleash: admin server: %w", serr))
		}
	}()
	d.proxyWG.Add(1)
	go func() {
		defer d.proxyWG.Done()
		if serr := d.proxy.Serve(d.ctx, d.proxyLn); serr != nil && d.ctx.Err() == nil {
			d.fatal(fmt.Errorf("keyleash: proxy: %w", serr))
		}
	}()
	if !opts.manualPresence {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.monitor.Run(d.ctx, d.onPresence)
		}()
	}
	if !opts.manualHousekeeping {
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			t := time.NewTicker(housekeepTick)
			defer t.Stop()
			for {
				select {
				case <-d.ctx.Done():
					return
				case <-t.C:
					d.housekeep()
				}
			}
		}()
	}
	d.log.Info("keyleash daemon started", "proxy", d.proxyLn.Addr().String(), "data", d.dataDir, "state", string(StateLocked))
	return d, nil
}

func (d *Daemon) fatal(err error) {
	d.log.Error("fatal", "err", err)
	select {
	case d.fatalCh <- err:
	default:
	}
}

// Done returns a channel that receives a fatal server error, if any.
func (d *Daemon) Done() <-chan error { return d.fatalCh }

// StopRequested returns a channel that is closed once an admin caller has
// asked the daemon to stop (POST /v1/shutdown). Run then calls Close; a
// caller that uses Start directly should do the same.
func (d *Daemon) StopRequested() <-chan struct{} { return d.stopCh }

// requestStop asks Run to shut down. It is idempotent.
func (d *Daemon) requestStop() { d.stopOnce.Do(func() { close(d.stopCh) }) }

// ProxyAddr returns the proxy's listen address.
func (d *Daemon) ProxyAddr() string { return d.proxyLn.Addr().String() }

// DataDir returns the data directory.
func (d *Daemon) DataDir() string { return d.dataDir }

// State returns the current state.
func (d *Daemon) State() State {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.st.state
}

// Close shuts the daemon down (docs/DAEMON.md "Shutdown"): stop accepting
// proxy connections and let in-flight requests finish (bounded), save the
// ledger checkpoint, close ledger and audit, lock the vault, remove the
// socket and release the instance lock. It is idempotent.
func (d *Daemon) Close() error {
	d.closeMu.Lock()
	defer d.closeMu.Unlock()
	if d.closed {
		return d.closeErr
	}
	d.closed = true

	d.cancel()
	done := make(chan struct{})
	go func() { d.proxyWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(ShutdownGrace):
		d.log.Warn("in-flight requests did not finish within the shutdown grace period")
	}
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = d.adminSrv.Shutdown(sctx)
	scancel()
	d.wg.Wait()

	var errs []error
	d.unlockMu.Lock()
	d.mu.Lock()
	unlocked := d.st.state != StateLocked
	// Locked before settling: a request still being admitted (after the
	// grace period) cannot reserve once in-flight reservations are expired.
	d.st.state = StateLocked
	d.mu.Unlock()
	if unlocked {
		// Requests still in flight after the grace period are charged at
		// their reserved amount while the MAC key is set (fail closed), so
		// the spend survives the restart.
		if n, err := d.ledger.ExpireInFlight(-1); err != nil {
			errs = append(errs, fmt.Errorf("settle in-flight: %w", err))
		} else if n > 0 {
			d.log.Warn("in-flight requests charged at their reserved amount on shutdown", "count", n)
		}
		if err := d.ledger.Flush(); err != nil {
			errs = append(errs, err)
		}
		d.saveState()
		d.auditEvent("lock", map[string]any{"reason": "shutdown", "session": d.sessionID()})
		d.anchor()
	}
	d.auditEvent("daemon_stop", nil)
	if err := d.ledger.Close(); err != nil {
		errs = append(errs, fmt.Errorf("ledger close: %w", err))
	}
	if err := d.audit.Close(); err != nil {
		errs = append(errs, fmt.Errorf("audit close: %w", err))
	}
	d.passes.SetMACKey(nil)
	d.vault.Lock()
	d.mu.Lock()
	d.st.keys.destroy()
	d.st.keys = nil
	d.st.state = StateLocked
	d.mu.Unlock()
	d.unlockMu.Unlock()
	if d.jobs != nil {
		d.jobs.Close()
	}
	if d.osSource != nil {
		d.osSource.Close()
	}
	d.adminLn.Close()
	cleanupAdmin(d.dataDir, d.opts.AdminListener != nil)
	if err := d.instance.Close(); err != nil {
		errs = append(errs, err)
	}
	d.closeErr = errors.Join(errs...)
	return d.closeErr
}

func approverMethod(a approval.Approver) string {
	if m, ok := a.(interface{ Method() string }); ok {
		return m.Method()
	}
	return "approver"
}

// approverFor returns the approver for an approval method. Options.Approver
// (tests) overrides every method. For a resume (forResume), the console is
// never used, and a method that cannot prompt here (console, deny, or
// Windows Hello while it is unavailable) waits for the vault passphrase or
// recovery code over the admin API instead (spec §14).
func (d *Daemon) approverFor(method string, forResume bool) approval.Approver {
	if d.opts.Approver != nil {
		return d.opts.Approver
	}
	switch method {
	case "console":
		if forResume {
			return approval.PassphraseApprover()
		}
		d.consoleMu.Lock()
		defer d.consoleMu.Unlock()
		if d.console == nil {
			in, out := d.opts.ConsoleIn, d.opts.ConsoleOut
			if in == nil {
				in = os.Stdin
			}
			if out == nil {
				out = os.Stderr
			}
			d.console = approval.ConsoleApprover(in, out)
		}
		return d.console
	case "hello":
		if forResume {
			if ok, _ := d.helloAvailable(); !ok {
				return approval.PassphraseApprover()
			}
		}
		return approval.HelloApprover(&helloConfirmer{available: d.helloAvailable})
	case "passphrase":
		return approval.PassphraseApprover()
	default:
		if forResume {
			return approval.PassphraseApprover()
		}
		return approval.DenyApprover{}
	}
}

// revokeOrphanedRunPasses ends the active run passes a previous daemon
// issued: their job objects died with it.
func (d *Daemon) revokeOrphanedRunPasses() {
	now := d.clk.Now()
	var ids []string
	for _, p := range d.passes.List() {
		if p.Kind == pass.KindRun && !p.Revoked && !p.Expired(now) {
			ids = append(ids, p.ID)
		}
	}
	if len(ids) == 0 {
		return
	}
	if _, err := d.passes.RevokeIDs(ids); err != nil {
		d.log.Warn("revoking run passes of a previous daemon (revoked in memory)", "err", err)
	}
	for _, id := range ids {
		d.auditEvent("pass_revoke", map[string]any{"pass": id, "reason": "daemon_restart"})
	}
}

// resolvePeer is the default proxy.PeerResolver: TCP owner table, then the
// process image. Any error leaves the client unknown (PID 0), which denies
// bound passes.
func (d *Daemon) resolvePeer(local, remote netip.AddrPort) proxy.ClientInfo {
	ci := proxy.ClientInfo{Remote: remote}
	pid, err := procinfo.PeerPID(local, remote)
	if err != nil || pid <= 0 {
		return ci
	}
	ci.PID = pid
	if p, err := d.lookupProcess(pid); err == nil {
		ci.Image = p.Image
	}
	return ci
}
