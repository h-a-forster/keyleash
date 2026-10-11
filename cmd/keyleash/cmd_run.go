package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// Exit codes for `run` failures that are not the child's own.
const (
	exitCommandNotFound = 127
	exitCannotRun       = 126
)

var cmdRun = &command{
	name:    "run",
	args:    "[--budget <amount>] [--ttl <duration>] [--providers a,b] [--models globs] [--name n] -- <command> [args...]",
	summary: "run a command with its own budgeted, process-bound pass",
	help: `
Creates an ephemeral pass bound to this keyleash process (the command and
everything it starts can use it; nothing else can), points the command at
the proxy through its environment, runs it, and revokes the pass when it
exits. The exit code is the command's.

    keyleash run -- claude
    keyleash run --budget 5 --models 'claude-sonnet-*' -- claude -p "fix the tests"
    keyleash run --providers openai --budget 2 -- codex
    keyleash run -- python agent.py

For each allowed provider the child gets its base-URL variable (e.g.
ANTHROPIC_BASE_URL=http://127.0.0.1:47114/anthropic,
OPENAI_BASE_URL=http://127.0.0.1:47114/openai/v1), KEYLEASH_<NAME>_BASE_URL,
and the API-key variable set to the pass. Conflicting credentials such as
ANTHROPIC_AUTH_TOKEN are removed. By default the pass covers the providers
you stored keys for that have a standard base-URL variable (anthropic,
openai); name others with --providers.

Ctrl-C goes to the command; keyleash waits for it to exit. If keyleash itself
is killed, the daemon revokes the pass when it notices the process is gone.`,
	run: runRun,
}

func runRun(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("run")
	pf := addPassFlags(fs, "")
	argv, err := parseFlags(fs, args, false)
	if err != nil {
		return err
	}
	if len(argv) == 0 {
		return usagef("run", "missing command; put it after --, e.g. keyleash run -- claude")
	}
	if *pf.name == "" {
		*pf.name = "run: " + filepath.Base(argv[0])
	}

	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	st, err := c.Status(cctx)
	if err != nil {
		return err
	}
	switch st.State {
	case client.StateLocked:
		return errLocked
	case client.StateTripped:
		return errTripped
	}
	if _, err := proxyRoot(st.ProxyAddr); err != nil {
		return err
	}
	keys, err := c.Keys(cctx)
	if err != nil {
		return err
	}
	providers, err := resolveProviders(pf.providers, keys, true)
	if err != nil {
		return err
	}
	req, err := pf.request("run", pass.KindRun, providers)
	if err != nil {
		return err
	}
	req.BindPID = os.Getpid()
	resp, err := c.CreatePass(cctx, req)
	if err != nil {
		return err
	}
	cancel()

	// From here on the pass exists: revoke it on every path, including a
	// panic (deferred calls run while panicking) and termination signals.
	revoke := sync.OnceFunc(func() {
		rctx, rcancel := context.WithTimeout(context.Background(), revokeTimeout)
		defer rcancel()
		if err := c.RevokePass(rctx, resp.Pass.ID); err != nil && !client.IsCode(err, client.CodeNotFound) {
			fmt.Fprintf(a.stderr, "keyleash: warning: could not revoke pass %s (%v); it is bound to this process, so the daemon revokes it once the process is gone\n",
				resp.Pass.ID, friendly(err))
		}
	})
	defer revoke()

	if miss := missingKeys(resp.Pass.Providers, keys); len(miss) > 0 {
		fmt.Fprintf(a.stderr, "keyleash: warning: no key stored for %s; requests to it will fail\n", strings.Join(miss, ", "))
	}
	warnRealKeysInEnv(a, resp.Pass.Providers)
	plan, err := buildEnvPlan(st.ProxyAddr, resp.Pass.Providers, resp.Token, resp.Pass.ID, a.environ())
	if err != nil {
		return err
	}
	env := applyEnvPlan(a.environ(), plan)

	code, err := runChild(ctx, a, argv, env, revoke)
	if err != nil {
		return err
	}
	revoke()
	if code != 0 {
		return &exitCodeError{code: code}
	}
	return nil
}

// runChild starts argv with env and inherited stdio, forwards termination
// signals, waits, and returns the child's exit code. onTerminate runs when
// keyleash itself is asked to terminate (before the child is stopped).
func runChild(_ context.Context, a *app, argv []string, env []string, onTerminate func()) (int, error) {
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = a.stdin, a.stdout, a.stderr
	if a.stdinFile != nil {
		// Hand the real terminal to the child (not a pipe copy), so
		// interactive tools see a TTY.
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	}

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, forwardedSignals...)
	defer signal.Stop(sigs)

	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(a.stderr, "keyleash run: %s: command not found\n", sanitizeArg(argv[0]))
			return exitCommandNotFound, nil
		}
		fmt.Fprintf(a.stderr, "keyleash run: cannot start %s: %v\n", sanitizeArg(argv[0]), err)
		return exitCannotRun, nil
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case sig := <-sigs:
			handleRunSignal(cmd, sig, onTerminate)
		case err := <-done:
			return exitCode(cmd, err), nil
		}
	}
}

// exitCode maps the child's wait result to an exit code.
func exitCode(cmd *exec.Cmd, waitErr error) int {
	if cmd.ProcessState != nil {
		if code := cmd.ProcessState.ExitCode(); code >= 0 {
			return code
		}
		if code, ok := signalExitCode(cmd.ProcessState); ok {
			return code
		}
	}
	if waitErr != nil {
		return exitError
	}
	return 0
}

// warnRealKeysInEnv warns when the environment holds what looks like a
// real key for a provider the pass does not cover (the child inherits it).
func warnRealKeysInEnv(a *app, covered []string) {
	for _, name := range provider.Names() {
		p, _ := provider.Get(name)
		if p.KeyEnv == "" {
			continue
		}
		skip := false
		for _, c := range covered {
			skip = skip || c == name
		}
		if skip {
			continue
		}
		if v := a.getenv(p.KeyEnv); v != "" && looksLikeSecret(v) && !pass.LooksLikePass(v) {
			fmt.Fprintf(a.stderr, "keyleash: warning: %s holds a real-looking key that the command will inherit; store it with `keyleash add %s` and remove it from your environment\n", p.KeyEnv, name)
		}
	}
}
