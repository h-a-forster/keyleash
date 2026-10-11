package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/daemon"
)

// Timeouts for admin calls. Calls that wait for a step-up approval or a
// Windows Hello prompt use the command context only (cancelled by Ctrl-C).
const (
	adminTimeout  = 30 * time.Second
	revokeTimeout = 10 * time.Second
)

// app carries the CLI's I/O and environment so commands can be tested.
type app struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	// stdinFile is the real standard input when it may be a terminal; nil
	// in tests (then no hidden prompts are possible).
	stdinFile *os.File
	// getenv and environ read the process environment.
	getenv  func(string) string
	environ func() []string
	// dial returns an admin client (default: client.Dial on the data dir).
	dial func() (*client.Client, error)
}

func newApp() *app {
	a := &app{
		stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, stdinFile: os.Stdin,
		getenv: os.Getenv, environ: os.Environ,
	}
	a.dial = func() (*client.Client, error) {
		dir, err := a.dataDir()
		if err != nil {
			return nil, err
		}
		return client.Dial(dir)
	}
	return a
}

// dataDir resolves the data directory: $KEYLEASH_HOME (as seen through
// a.getenv) or the OS default (daemon.DefaultDataDir).
func (a *app) dataDir() (string, error) {
	if h := a.getenv("KEYLEASH_HOME"); h != "" {
		return filepath.Abs(h)
	}
	return daemon.DefaultDataDir()
}

// client returns an admin client; the caller closes it.
func (a *app) client() (*client.Client, error) {
	c, err := a.dial()
	if err != nil {
		return nil, fmt.Errorf("cannot set up the admin channel: %w", err)
	}
	return c, nil
}

// interactive reports whether standard input is a terminal.
func (a *app) interactive() bool {
	return a.stdinFile != nil && isTerminal(a.stdinFile)
}

// printJSON writes v as indented JSON to stdout.
func (a *app) printJSON(v any) error {
	enc := json.NewEncoder(a.stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// withTimeout bounds a quick admin call.
func withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, adminTimeout)
}

// Errors with actionable messages.
var (
	errDaemonDown = errors.New("the keyleash daemon is not running or not reachable — start it with: keyleash daemon")
	errLocked     = errors.New("keyleash is locked — run: keyleash unlock")
	errTripped    = errors.New("keyleash is tripped (a spend tripwire or integrity check fired) — check `keyleash status`, then run: keyleash resume")
)

// friendly turns client and daemon errors into short, actionable messages.
// It never adds secret material: daemon messages are secret-free by design.
func friendly(err error) error {
	var ae *client.APIError
	if errors.As(err, &ae) {
		switch ae.Code {
		case client.CodeLocked:
			return errLocked
		case client.CodeWrongSecret:
			return errors.New("wrong passphrase or recovery code (the attempt is recorded in the audit log)")
		case client.CodeStepUpDenied:
			return errors.New("step-up approval was denied")
		case client.CodeStepUpTimeout:
			return errors.New("step-up approval timed out — approve with Windows Hello or in the daemon console, or from a terminal with: keyleash approvals approve <id> (asks for your passphrase or recovery code)")
		case client.CodeConfined:
			return errors.New("refused: this command runs inside a `keyleash run` session (or could not be identified); from there keyleash allows only `keyleash status` and revoking the session's own pass. Run it from a normal terminal")
		case client.CodeRateLimited:
			if ae.Message != "" {
				return errors.New(ae.Message)
			}
			return errors.New("too many wrong passphrases or recovery codes; wait and try again")
		case client.CodeConflict:
			if strings.Contains(ae.Message, "tripped") {
				return errTripped
			}
		}
		if ae.Message != "" {
			return errors.New(ae.Message)
		}
		return fmt.Errorf("daemon error %s (HTTP %d)", ae.Code, ae.Status)
	}
	if isPipeOwnerError(err) {
		return errors.New("the keyleash admin pipe is owned by another account; refusing to use it. Something may be impersonating the daemon: stop it and start `keyleash daemon` again")
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("the keyleash daemon did not answer in time")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		if errors.Is(err, context.Canceled) {
			return errInterrupted
		}
		return errDaemonDown
	}
	return err
}

// newTable returns a tabwriter for aligned human output.
func newTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

// fmtTime renders a timestamp in local time, compactly.
func fmtTime(t time.Time, now time.Time) string {
	if t.IsZero() {
		return "-"
	}
	t = t.Local()
	n := now.Local()
	if t.Year() == n.Year() && t.YearDay() == n.YearDay() {
		return t.Format("15:04")
	}
	if t.Year() == n.Year() {
		return t.Format("Jan 2 15:04")
	}
	return t.Format("2006-01-02 15:04")
}

// fmtDuration renders a duration rounded for humans ("2h05m", "45s").
func fmtDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return d.Round(time.Second).String()
	case d < 48*time.Hour:
		d = d.Round(time.Minute)
		h, m := int(d.Hours()), int(d.Minutes())%60
		if h == 0 {
			return fmt.Sprintf("%dm", m)
		}
		return fmt.Sprintf("%dh%02dm", h, m)
	default:
		return fmt.Sprintf("%dd%02dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}

// activePasses filters out revoked and expired passes.
func activePasses(ps []client.PassInfo) []client.PassInfo {
	var out []client.PassInfo
	for _, p := range ps {
		if !p.Revoked && !p.Expired {
			out = append(out, p)
		}
	}
	return out
}
