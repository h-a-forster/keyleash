package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/daemon"
	"github.com/h-a-forster/keyleash/internal/meter"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// Pricing freshness thresholds for doctor.
const (
	pricingStaleAfter  = 90 * 24 * time.Hour
	promoExpiringSoon  = 30 * 24 * time.Hour
	clockSkewTolerance = 5 * time.Minute
)

var cmdConfig = &command{
	name:    "config",
	args:    "show|check|path [--local]",
	summary: "show, check or locate the configuration",
	help: `
  keyleash config path    print the config file path
  keyleash config check   validate config.toml and print the effective config
  keyleash config show    print the running daemon's effective config
                          (--local: the file on disk, daemon or not)

Edit config.toml, run 'keyleash config check', then restart the daemon.`,
	run: runConfig,
}

func runConfig(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return usagef("config", "missing subcommand: show, check or path")
	}
	sub, args := args[0], args[1:]
	flags := newFlagSet("config")
	local := flags.Bool("local", false, "show: read the file on disk instead of asking the daemon")
	if pos, err := parseFlags(flags, args, true); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("config", "unexpected argument")
	}
	dir, err := a.dataDir()
	if err != nil {
		return err
	}
	path := filepath.Join(dir, daemon.ConfigFile)
	switch sub {
	case "path":
		fmt.Fprintln(a.stdout, path)
		return nil
	case "check":
		cfg, err := config.Load(path)
		if err != nil {
			return fmt.Errorf("%s is invalid: %w", path, err)
		}
		text, err := cfg.Encode()
		if err != nil {
			return err
		}
		if _, serr := os.Stat(path); errors.Is(serr, fs.ErrNotExist) {
			fmt.Fprintf(a.stderr, "%s does not exist: the recommended defaults apply.\n", path)
		} else {
			fmt.Fprintf(a.stderr, "%s is valid (profile %s). Restart the daemon to apply changes.\n", path, cfg.Profile)
		}
		fmt.Fprint(a.stdout, text)
		return nil
	case "show":
		if !*local {
			if c, err := a.client(); err == nil {
				defer c.Close()
				cctx, cancel := withTimeout(ctx)
				text, err := c.Config(cctx)
				cancel()
				if err == nil {
					fmt.Fprintln(a.stderr, "# effective config of the running daemon")
					fmt.Fprint(a.stdout, text)
					return nil
				}
				if friendly(err) != errDaemonDown {
					return err
				}
			}
		}
		cfg, err := config.Load(path)
		if err != nil {
			return fmt.Errorf("%s is invalid: %w", path, err)
		}
		text, err := cfg.Encode()
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stderr, "# effective config from %s\n", path)
		fmt.Fprint(a.stdout, text)
		return nil
	}
	return usagef("config", "unknown subcommand %q (want show, check or path)", sanitizeArg(sub))
}

// Doctor check levels.
const (
	levelOK   = "ok"
	levelWarn = "warn"
	levelFail = "fail"
	levelInfo = "info"
)

// check is one doctor finding.
type check struct {
	Name   string `json:"name"`
	Level  string `json:"level"`
	Detail string `json:"detail"`
}

var cmdDoctor = &command{
	name:    "doctor",
	args:    "[--json]",
	summary: "check the environment (Hello, permissions, daemon, port, clock, pricing)",
	help: `
Checks Windows Hello availability, the data directory's permissions, the
vault and config, whether the daemon is reachable, whether the proxy port is
free or used by keyleash, the clock, presence detection, and the age of the
pricing table (warns when a price is more than 90 days old or a promotional
price ends within 30 days). Exits 1 if any check fails.`,
	run: runDoctor,
}

func runDoctor(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("doctor")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, err := parseFlags(fs, args, true); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("doctor", "unexpected argument")
	}
	checks := a.doctorChecks(ctx, time.Now())
	failed := false
	for _, c := range checks {
		failed = failed || c.Level == levelFail
	}
	if *asJSON {
		if err := a.printJSON(checks); err != nil {
			return err
		}
	} else {
		tw := newTable(a.stdout)
		for _, c := range checks {
			fmt.Fprintf(tw, "[%s]\t%s\t%s\n", strings.ToUpper(c.Level), c.Name, c.Detail)
		}
		tw.Flush()
	}
	if failed {
		return &exitCodeError{code: exitError}
	}
	return nil
}

// doctorChecks runs every check; none of them changes anything.
func (a *app) doctorChecks(ctx context.Context, now time.Time) []check {
	var out []check
	add := func(name, level, format string, args ...any) {
		out = append(out, check{Name: name, Level: level, Detail: fmt.Sprintf(format, args...)})
	}

	helloOK, helloWhy := helloAvailable()
	switch {
	case helloOK:
		add("windows hello", levelOK, "available")
	case runtime.GOOS == "windows":
		add("windows hello", levelWarn, "not available (%s); passphrase unlock only", helloWhy)
	default:
		add("windows hello", levelInfo, "not available on %s; passphrase unlock", runtime.GOOS)
	}

	dir, err := a.dataDir()
	if err != nil {
		add("data dir", levelFail, "%v", err)
		return out
	}
	if _, err := os.Stat(dir); err != nil {
		add("data dir", levelWarn, "%s does not exist; run: keyleash init", dir)
	} else if err := checkPrivateDir(dir); err != nil {
		add("data dir", levelFail, "%s is not private: %v (the daemon restricts it on start)", dir, err)
	} else {
		add("data dir", levelOK, "%s (owner-only)", dir)
	}
	if vaultExists(dir) {
		add("vault", levelOK, "present")
	} else {
		add("vault", levelWarn, "no vault yet; run: keyleash init")
	}

	cfg, cfgErr := config.Load(filepath.Join(dir, daemon.ConfigFile))
	if cfgErr != nil {
		add("config", levelFail, "%v", cfgErr)
		cfg, _ = config.Default("recommended")
	} else {
		add("config", levelOK, "valid (profile %s)", cfg.Profile)
		if cfg.Approval.Method == "hello" && !helloOK {
			add("approvals", levelWarn, "approval.method is hello but Windows Hello is unavailable: every step-up will be denied (set approval.method = \"passphrase\")")
		}
	}

	var st *client.Status
	if c, err := a.client(); err == nil {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		s, serr := c.Status(cctx)
		cancel()
		c.Close()
		if serr == nil {
			st = &s
			add("daemon", levelOK, "running, %s", s.State)
		} else if fe := friendly(serr); fe == errDaemonDown {
			add("daemon", levelWarn, "not running; start it with: keyleash daemon")
		} else {
			add("daemon", levelFail, "%v", fe)
		}
	} else {
		add("daemon", levelFail, "%v", err)
	}

	out = append(out, portCheck(cfg.Proxy.Port, st))
	out = append(out, clockCheck(dir, now))

	if st != nil {
		switch {
		case st.PresenceDegraded:
			add("presence", levelWarn, "degraded: %s", st.PresenceDegradedReason)
		default:
			add("presence", levelOK, "idle, screen-lock and sleep detection active")
		}
		if !st.AuditHealthy {
			add("audit", levelFail, "audit log writes are failing; keyleash is tripped until fixed")
		}
		if strings.HasPrefix(st.Integrity, "failed") {
			add("integrity", levelFail, "%s", st.Integrity)
		}
		for _, w := range st.Warnings {
			add("daemon warning", levelWarn, "%s", w)
		}
	}

	override := cfg.Pricing.Override
	if override != "" && !filepath.IsAbs(override) {
		override = filepath.Join(dir, override)
	}
	if p, err := meter.LoadPricing(override); err != nil {
		add("pricing", levelFail, "cannot load pricing: %v", err)
	} else {
		out = append(out, pricingCheck(p, now))
	}
	return out
}

// portCheck reports whether the proxy port is free or held by keyleash.
func portCheck(port int, st *client.Status) check {
	c := check{Name: "proxy port"}
	if st != nil && st.ProxyAddr != "" {
		ap, err := netip.ParseAddrPort(st.ProxyAddr)
		if err == nil && int(ap.Port()) == port {
			c.Level, c.Detail = levelOK, fmt.Sprintf("%d in use by keyleash", port)
			return c
		}
		c.Level, c.Detail = levelWarn, fmt.Sprintf("the daemon listens on %s but config says port %d; restart the daemon", st.ProxyAddr, port)
		return c
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		c.Level, c.Detail = levelFail, fmt.Sprintf("127.0.0.1:%d is used by another program; stop it or set [proxy] port", port)
		return c
	}
	ln.Close()
	c.Level, c.Detail = levelOK, fmt.Sprintf("%d is free", port)
	return c
}

// clockCheck flags a clock that is implausible or behind the newest
// ledger/audit write (the clock was moved back, which skews time windows).
func clockCheck(dir string, now time.Time) check {
	c := check{Name: "clock"}
	if now.Year() < 2025 {
		c.Level, c.Detail = levelFail, "system clock reads "+now.Format(time.RFC3339)+"; fix the date"
		return c
	}
	var newest time.Time
	for _, sub := range []string{daemon.LedgerDir, daemon.AuditDir} {
		entries, err := os.ReadDir(filepath.Join(dir, sub))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if info, err := e.Info(); err == nil && info.ModTime().After(newest) {
				newest = info.ModTime()
			}
		}
	}
	if !newest.IsZero() && newest.Sub(now) > clockSkewTolerance {
		c.Level = levelFail
		c.Detail = fmt.Sprintf("the clock is %s behind the newest ledger/audit write; was it moved back?", fmtDuration(newest.Sub(now)))
		return c
	}
	_, offset := now.Zone()
	c.Level, c.Detail = levelOK, fmt.Sprintf("%s (UTC%+d)", now.Format("2006-01-02 15:04"), offset/3600)
	return c
}

// pricingFindings lists priced models whose as_of date is older than
// pricingStaleAfter, promotional prices ending within promoExpiringSoon,
// and listed models that are no longer priced (an expired promotion).
// Entries are "provider/model (detail)".
func pricingFindings(p *meter.Pricing, now time.Time) (stale, expiring, unpriced []string) {
	for _, prov := range provider.Names() {
		for _, m := range p.Models(prov) {
			pr, ok := p.Lookup(prov, m)
			id := prov + "/" + m
			if !ok {
				unpriced = append(unpriced, id)
				continue
			}
			if asOf, err := time.Parse("2006-01-02", pr.AsOf); err != nil {
				stale = append(stale, id+" (no as_of date)")
			} else if age := now.Sub(asOf); age > pricingStaleAfter {
				stale = append(stale, fmt.Sprintf("%s (as of %s)", id, pr.AsOf))
			}
			if pr.ValidUntil != "" {
				if until, err := time.Parse("2006-01-02", pr.ValidUntil); err == nil && until.AddDate(0, 0, 1).Sub(now) <= promoExpiringSoon {
					expiring = append(expiring, fmt.Sprintf("%s (until %s)", id, pr.ValidUntil))
				}
			}
		}
	}
	sort.Strings(stale)
	sort.Strings(expiring)
	sort.Strings(unpriced)
	return stale, expiring, unpriced
}

// pricingCheck summarises pricingFindings.
func pricingCheck(p *meter.Pricing, now time.Time) check {
	stale, expiring, unpriced := pricingFindings(p, now)
	c := check{Name: "pricing", Level: levelOK}
	var parts []string
	if len(stale) > 0 {
		parts = append(parts, fmt.Sprintf("%d prices older than 90 days: %s", len(stale), listSome(stale, 3)))
	}
	if len(expiring) > 0 {
		parts = append(parts, fmt.Sprintf("%d promotional prices end within 30 days: %s", len(expiring), listSome(expiring, 3)))
	}
	if len(unpriced) > 0 {
		parts = append(parts, fmt.Sprintf("%d expired promotions (now unpriced; approval or denial applies): %s", len(unpriced), listSome(unpriced, 3)))
	}
	if len(parts) == 0 {
		c.Detail = "all prices checked within 90 days; no promotion ends within 30 days"
		return c
	}
	c.Level = levelWarn
	c.Detail = strings.Join(parts, "; ") + ". Update keyleash or add a pricing override."
	return c
}

func listSome(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(", and %d more", len(items)-n)
}
