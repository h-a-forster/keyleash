// Command keyleash is the command-line client for the keyleash daemon: a
// local credential broker and spend governor for LLM API keys (docs/SPEC.md
// §13, docs/USAGE.md).
//
// The CLI is a thin client over the daemon's admin channel
// (internal/client). It never prints provider keys, and it never accepts a
// secret (provider key, pass, passphrase, recovery code) as a command-line
// argument: secrets come from a hidden terminal prompt or, with --stdin, from
// standard input.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
)

// version is set at build time:
//
//	go build -ldflags "-X main.version=v0.1.0" ./cmd/keyleash
var version = "dev"

// Exit codes.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
	// exitInterrupted is returned when the user aborts a prompt with Ctrl-C.
	exitInterrupted = 130
)

// command is one subcommand.
type command struct {
	name    string
	args    string // usage synopsis after the command name
	summary string
	help    string // extra detail for `keyleash help <cmd>`
	run     func(ctx context.Context, a *app, args []string) error
}

// commands is the subcommand table, in the order `keyleash help` lists them.
var commands []*command

func init() {
	commands = []*command{
		cmdInit, cmdDaemon, cmdStop, cmdStatus, cmdUnlock, cmdLock, cmdAdd, cmdKeys, cmdRmKey,
		cmdRun, cmdEnv, cmdPass, cmdLimits, cmdAway, cmdResume, cmdUsage, cmdApprovals,
		cmdAudit, cmdConfig, cmdRecovery, cmdDoctor, cmdPanic, cmdVersion, cmdHelp,
	}
}

func lookupCommand(name string) *command {
	for _, c := range commands {
		if c.name == name {
			return c
		}
	}
	return nil
}

// usageError is a mistake in how the CLI was invoked (exit code 2).
type usageError struct {
	cmd string
	msg string
}

func (e *usageError) Error() string { return e.msg }

func usagef(cmd, format string, args ...any) error {
	return &usageError{cmd: cmd, msg: fmt.Sprintf(format, args...)}
}

// exitCodeError ends the CLI with a specific exit code and no message (for
// example the child's exit code after `keyleash run`).
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

func main() {
	a := newApp()
	os.Exit(a.main(os.Args[1:]))
}

// main runs the CLI with args (without the program name) and returns the
// process exit code.
func (a *app) main(args []string) int {
	if len(args) == 0 {
		a.printUsage(a.stderr)
		return exitUsage
	}
	name := args[0]
	switch name {
	case "-h", "--help", "-help":
		name = "help"
	case "-v", "--version", "-version":
		name = "version"
	}
	cmd := lookupCommand(name)
	if cmd == nil {
		fmt.Fprintf(a.stderr, "keyleash: unknown command %q\n", sanitizeArg(name))
		fmt.Fprintln(a.stderr, "Run 'keyleash help' for the list of commands.")
		return exitUsage
	}
	rest := args[1:]
	// Secrets never come from argv. Arguments after "--" belong to the
	// child of `keyleash run` and are not ours to judge.
	if err := rejectSecretArgs(rest); err != nil {
		fmt.Fprintf(a.stderr, "keyleash %s: %v\n", cmd.name, err)
		return exitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err := a.invoke(ctx, cmd, rest)
	return a.report(cmd, err)
}

// invoke runs cmd, converting a panic into an error after deferred cleanup
// (for example pass revocation in `run`) has run.
func (a *app) invoke(ctx context.Context, cmd *command, args []string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("internal error: %v\n%s", r, debug.Stack())
		}
	}()
	return cmd.run(ctx, a, args)
}

// report prints err (if any) and returns the exit code.
func (a *app) report(cmd *command, err error) int {
	if err == nil {
		return exitOK
	}
	var ec *exitCodeError
	if errors.As(err, &ec) {
		return ec.code
	}
	var ue *usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(a.stderr, "keyleash %s: %s\n", cmd.name, ue.msg)
		fmt.Fprintf(a.stderr, "Usage: keyleash %s %s\n", cmd.name, cmd.args)
		fmt.Fprintf(a.stderr, "Run 'keyleash help %s' for details.\n", cmd.name)
		return exitUsage
	}
	if errors.Is(err, errInterrupted) {
		fmt.Fprintln(a.stderr, "keyleash: interrupted")
		return exitInterrupted
	}
	fmt.Fprintf(a.stderr, "keyleash %s: %v\n", cmd.name, friendly(err))
	return exitError
}

func (a *app) printUsage(w io.Writer) {
	fmt.Fprintln(w, "keyleash: a local credential broker and spend governor for LLM API keys.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: keyleash <command> [flags] [args]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	width := 0
	for _, c := range commands {
		width = max(width, len(c.name))
	}
	for _, c := range commands {
		fmt.Fprintf(w, "  %-*s  %s\n", width, c.name, c.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Secrets are never taken from the command line: keys and passphrases are")
	fmt.Fprintln(w, "read from a hidden prompt, or from standard input with --stdin.")
	fmt.Fprintln(w, "Run 'keyleash help <command>' for details, and see docs/USAGE.md.")
}

var cmdHelp = &command{
	name:    "help",
	args:    "[command]",
	summary: "show help for keyleash or one command",
	run: func(_ context.Context, a *app, args []string) error {
		if len(args) == 0 {
			a.printUsage(a.stdout)
			return nil
		}
		if len(args) > 1 {
			return usagef("help", "expected at most one command name")
		}
		c := lookupCommand(args[0])
		if c == nil {
			return usagef("help", "unknown command %q", sanitizeArg(args[0]))
		}
		fmt.Fprintf(a.stdout, "Usage: keyleash %s %s\n\n%s.\n", c.name, c.args, upperFirst(c.summary))
		if c.help != "" {
			fmt.Fprintf(a.stdout, "\n%s\n", strings.TrimSpace(c.help))
		}
		return nil
	},
}

var cmdVersion = &command{
	name:    "version",
	args:    "[--json]",
	summary: "print the keyleash version",
	run: func(_ context.Context, a *app, args []string) error {
		fs := newFlagSet("version")
		asJSON := fs.Bool("json", false, "print JSON")
		if _, err := parseFlags(fs, args, false); err != nil {
			return err
		}
		info := map[string]string{"version": version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH}
		if *asJSON {
			return a.printJSON(info)
		}
		fmt.Fprintf(a.stdout, "keyleash %s (%s, %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		return nil
	},
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
