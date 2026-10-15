package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/daemon"
)

var cmdDaemon = &command{
	name:    "daemon",
	args:    "[--background] [--verbose]",
	summary: "run the keyleash daemon (foreground, or --background)",
	help: `
Runs the daemon (proxy, vault, budgets, presence lock, admin channel) until
Ctrl-C or logoff. It starts Locked; run 'keyleash unlock' from another
terminal. Logs go to stderr and never contain keys, passes or passphrases.

With approval.method = "console", step-up prompts are asked in this
terminal. When the daemon has no terminal (started in the background),
console approvals wait for 'keyleash approvals approve|deny <id>' instead
(approving there asks for your passphrase or recovery code).

--background starts the daemon detached from this terminal, logging to
daemon.log in the data directory, and returns once it answers.`,
	run: runDaemon,
}

func runDaemon(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("daemon")
	verbose := fs.Bool("verbose", false, "log debug messages")
	background := fs.Bool("background", false, "start detached and return")
	pos, err := parseFlags(fs, args, true)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("daemon", "unexpected argument")
	}
	dir, err := a.dataDir()
	if err != nil {
		return err
	}
	if *background {
		return a.daemonBackground(ctx, dir)
	}
	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	opts := daemon.Options{
		DataDir: dir,
		Logger:  slog.New(slog.NewTextHandler(a.stderr, &slog.HandlerOptions{Level: level})),
	}
	// A console approver reading a stdin that is not a terminal would see
	// EOF and deny every step-up at once, leaving no chance to approve
	// from `keyleash approvals`. Give it an input that never answers, so
	// the admin API (or the timeout) decides.
	if !a.interactive() {
		if cfg, err := config.Load(filepath.Join(dir, daemon.ConfigFile)); err == nil && cfg.Approval.Method == "console" {
			opts.ConsoleIn = blockingReader{ctx: ctx}
		}
	}
	return daemon.Run(ctx, opts)
}

// daemonBackground starts a detached daemon for dir unless one is already
// running, and waits until it answers.
func (a *app) daemonBackground(ctx context.Context, dir string) error {
	if !vaultExists(dir) {
		return fmt.Errorf("no vault in %s; run: keyleash init", dir)
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	_, serr := c.Status(qctx)
	cancel()
	if serr == nil {
		fmt.Fprintln(a.stdout, "The keyleash daemon is already running.")
		return nil
	}
	logPath := filepath.Join(dir, "daemon.log")
	if err := startBackgroundDaemon(dir, logPath, a.environ()); err != nil {
		return fmt.Errorf("could not start the daemon: %w", err)
	}
	if err := waitForDaemon(ctx, c, daemonStartWait); err != nil {
		return fmt.Errorf("the daemon did not answer; see %s", logPath)
	}
	fmt.Fprintf(a.stdout, "keyleash daemon running in the background (log: %s). Next: keyleash unlock\n", logPath)
	return nil
}

// stopWait bounds how long `keyleash stop` waits for the daemon to go away:
// the daemon's shutdown grace for in-flight requests plus time to save.
var stopWait = daemon.ShutdownGrace + 15*time.Second

var cmdStop = &command{
	name:    "stop",
	args:    "",
	summary: "stop the running daemon gracefully",
	help: `
Asks the running daemon to shut down, the same way Ctrl-C in its terminal
does: it stops accepting proxy connections, lets in-flight requests finish
(up to 30 s; any still running are charged at their reserved amount), saves
the ledger checkpoint, locks the vault and exits. With [run]
kill_on_daemon_exit (the default) processes started by 'keyleash run' end
too. The request is recorded in the audit log. The command waits until
the daemon has finished shutting down (it has released its instance lock,
the last step) and reports an error if that takes longer than 45 s.

No step-up is needed: stopping only takes keyleash offline. It is refused
from inside a 'keyleash run' session (use 'keyleash lock' or 'keyleash
panic' there). If no daemon is running, it says so and exits successfully.`,
	run: runStop,
}

func runStop(ctx context.Context, a *app, args []string) error {
	if pos, err := parseFlags(newFlagSet("stop"), args, true); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("stop", "unexpected argument")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	cctx, cancel := withTimeout(ctx)
	err = c.Shutdown(cctx)
	cancel()
	if err != nil {
		if errors.Is(friendly(err), errDaemonDown) {
			fmt.Fprintln(a.stdout, "The keyleash daemon is not running.")
			return nil
		}
		return err
	}
	fmt.Fprintln(a.stderr, "Stopping the keyleash daemon (in-flight requests may take up to 30 s)...")
	// The daemon closes its admin channel early in its shutdown and
	// releases the instance lock last, after saving the ledger and state,
	// locking the vault and ending run sessions: wait for both.
	dir, err := a.dataDir()
	if err != nil {
		return err
	}
	deadline := time.Now().Add(stopWait)
	adminGone := false
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return errInterrupted
		case <-time.After(stopPoll):
		}
		if !adminGone {
			qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
			_, serr := c.Status(qctx)
			qcancel()
			adminGone = serr != nil && errors.Is(friendly(serr), errDaemonDown)
		}
		if adminGone {
			if running, rerr := daemon.Running(dir); rerr == nil && !running {
				fmt.Fprintln(a.stdout, "keyleash daemon stopped.")
				return nil
			}
		}
	}
	if adminGone {
		return errors.New("the daemon stopped answering but has not finished shutting down (it still holds its instance lock); check its log")
	}
	return errors.New("the daemon accepted the stop request but is still answering; check its log or `keyleash status`")
}

// stopPoll is how often `keyleash stop` checks whether the daemon is gone.
var stopPoll = 200 * time.Millisecond

// blockingReader never yields data; Read returns io.EOF once ctx is done.
type blockingReader struct{ ctx context.Context }

func (r blockingReader) Read([]byte) (int, error) {
	<-r.ctx.Done()
	return 0, io.EOF
}
