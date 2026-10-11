package main

import (
	"context"
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
console approvals wait for 'keyleash approvals approve|deny <id>' instead.

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

// blockingReader never yields data; Read returns io.EOF once ctx is done.
type blockingReader struct{ ctx context.Context }

func (r blockingReader) Read([]byte) (int, error) {
	<-r.ctx.Done()
	return 0, io.EOF
}
