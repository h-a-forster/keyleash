package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/daemon"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/secmem"
	"github.com/h-a-forster/keyleash/internal/vault"
	"github.com/h-a-forster/keyleash/internal/winhello"
)

// minNewPassphrase is the minimum length (in characters) the CLI accepts
// for a new passphrase. It is stricter than vault.MinPassphraseLen.
const minNewPassphrase = 12

// daemonStartWait bounds the wait for a background daemon to answer.
const daemonStartWait = 15 * time.Second

// helloAvailable is winhello.Available; tests replace it.
var helloAvailable = winhello.Available

var cmdInit = &command{
	name:    "init",
	args:    "[--method auto|hello|passphrase] [--profile recommended|strict|relaxed] [--approval hello|passphrase|console|deny] [--stdin] [--no-add]",
	summary: "create the vault, recovery code and recommended config",
	help: `
Creates the encrypted vault in the data directory ($KEYLEASH_HOME, or
%LOCALAPPDATA%\keyleash on Windows, ~/.config/keyleash on Linux).

The first key slot is Windows Hello when it is available, otherwise a
passphrase (at least 12 characters, typed twice). A recovery code is shown
exactly once: write it down and store it offline, then re-type its last
group to confirm. A config.toml with the chosen profile is written (an
existing one is kept). Finally keyleash offers to start the daemon and add
your first provider key.

Step-up approvals (new keys, passes beyond the run defaults, unattended
grants, leaving Tripped, ...) need proof that you are present: Windows Hello
when available, otherwise your passphrase or recovery code, typed into
'keyleash approvals approve <id>' (or the command that asked). Override
with --approval (console: the daemon's own terminal also answers).

--stdin reads the passphrase from the first line of standard input (for
scripts); the recovery code is then printed without the re-type check.`,
	run: runInit,
}

func runInit(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("init")
	method := fs.String("method", "auto", "first key slot: auto, hello or passphrase")
	profile := fs.String("profile", "recommended", "config profile: recommended, strict or relaxed")
	approvalMethod := fs.String("approval", "", "step-up approver: hello, passphrase, console or deny (default: hello if available, else passphrase)")
	fromStdin := fs.Bool("stdin", false, "read the passphrase from stdin (non-interactive)")
	noAdd := fs.Bool("no-add", false, "do not offer to add a first key")
	pos, err := parseFlags(fs, args, true)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return usagef("init", "unexpected argument")
	}
	if !slices.Contains(config.Profiles, *profile) {
		return usagef("init", "--profile must be one of %s", strings.Join(config.Profiles, ", "))
	}
	dir, err := a.dataDir()
	if err != nil {
		return err
	}
	if vaultExists(dir) {
		return fmt.Errorf("%s already holds a keyleash vault; nothing was changed (set KEYLEASH_HOME to use another directory)", dir)
	}
	interactive := a.interactive() && !*fromStdin
	if !interactive && !*fromStdin {
		return errors.New("init needs a terminal; run it interactively, or pass --stdin with the passphrase on standard input")
	}

	helloOK, helloWhy := helloAvailable()
	slot := *method
	switch slot {
	case "auto":
		slot = "passphrase"
		if helloOK && !*fromStdin {
			slot = "hello"
		}
	case "hello":
		if *fromStdin {
			return usagef("init", "--stdin supplies a passphrase; it cannot be used with --method hello")
		}
		if !helloOK {
			return fmt.Errorf("Windows Hello is not available (%s); use --method passphrase", helloWhy)
		}
	case "passphrase":
	default:
		return usagef("init", "--method must be auto, hello or passphrase")
	}
	appr := *approvalMethod
	switch appr {
	case "":
		appr = "passphrase"
		if helloOK {
			appr = "hello"
		}
	case "hello":
		if !helloOK {
			return fmt.Errorf("--approval hello needs Windows Hello, which is not available (%s)", helloWhy)
		}
	case "passphrase", "console", "deny":
	default:
		return usagef("init", "--approval must be hello, passphrase, console or deny")
	}

	var pw []byte
	defer func() { secmem.Wipe(pw) }()
	if slot == "passphrase" {
		if pw, err = a.newPassphrase(*fromStdin); err != nil {
			return err
		}
	}

	cpath := filepath.Join(dir, daemon.ConfigFile)
	_, statErr := os.Stat(cpath)
	configExisted := statErr == nil
	if slot == "hello" {
		fmt.Fprintln(a.stderr, "Creating the vault. Windows Hello will ask you to confirm.")
	} else {
		fmt.Fprintln(a.stderr, "Creating the vault (deriving the key takes a moment)...")
	}
	code, err := daemon.Init(dir, daemon.InitOptions{Method: slot, Passphrase: pw, Profile: *profile, Context: ctx})
	if err != nil {
		if errors.Is(err, daemon.ErrAlreadyInitialized) {
			return fmt.Errorf("%s already holds a keyleash vault; nothing was changed", dir)
		}
		return err
	}
	if !configExisted && appr != "hello" {
		if err := setApprovalMethod(cpath, appr); err != nil {
			fmt.Fprintf(a.stderr, "warning: could not set approval.method = %q in %s: %v\n", appr, cpath, err)
		}
	}

	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "Recovery code (shown once; write it down and keep it offline):")
	fmt.Fprintln(a.stdout)
	fmt.Fprintf(a.stdout, "    %s\n", code)
	fmt.Fprintln(a.stdout)
	if interactive {
		if err := a.confirmRecovery(code, "recovery code not confirmed; the vault was created, so keep the code you were shown"); err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, "Recovery code confirmed. Clear your terminal scrollback if others can see this screen.")
	} else {
		fmt.Fprintln(a.stderr, "note: --stdin skips the recovery-code check; make sure the code above is stored safely.")
	}

	fmt.Fprintf(a.stdout, "\nVault created in %s (first slot: %s, plus the recovery code).\n", dir, slot)
	if configExisted {
		fmt.Fprintf(a.stdout, "Kept the existing config %s.\n", cpath)
	} else {
		fmt.Fprintf(a.stdout, "Config: %s (profile %s, step-up approvals: %s).\n", cpath, *profile, appr)
	}

	if interactive && !*noAdd {
		ok, err := a.askYesNo("\nStart the daemon in the background and add a provider key now? [Y/n] ", true)
		if err != nil {
			return err
		}
		if ok {
			return a.firstKey(ctx, dir, slot, pw)
		}
	}
	printNextSteps(a, false)
	return nil
}

// vaultExists reports whether dir already has a vault (or its crash copy).
func vaultExists(dir string) bool {
	vp := filepath.Join(dir, daemon.VaultFile)
	for _, p := range []string{vp, vault.PrevPath(vp)} {
		if _, err := os.Stat(p); err == nil {
			return true
		}
	}
	return false
}

// newPassphrase reads a new passphrase: typed twice at a hidden prompt, or
// the first line of stdin.
func (a *app) newPassphrase(fromStdin bool) ([]byte, error) {
	if fromStdin {
		pw, err := readLineBounded(a.stdin)
		if err != nil {
			return nil, err
		}
		if err := checkNewPassphrase(pw); err != nil {
			secmem.Wipe(pw)
			return nil, err
		}
		return pw, nil
	}
	for range 3 {
		p1, err := a.readSecret(fmt.Sprintf("Choose a passphrase (at least %d characters): ", minNewPassphrase), false)
		if err != nil {
			return nil, err
		}
		if err := checkNewPassphrase(p1); err != nil {
			secmem.Wipe(p1)
			fmt.Fprintln(a.stderr, err)
			continue
		}
		p2, err := a.readSecret("Type it again: ", false)
		if err != nil {
			secmem.Wipe(p1)
			return nil, err
		}
		same := bytes.Equal(p1, p2)
		secmem.Wipe(p2)
		if same {
			return p1, nil
		}
		secmem.Wipe(p1)
		fmt.Fprintln(a.stderr, "The passphrases do not match.")
	}
	return nil, errors.New("no passphrase set; nothing was changed")
}

// checkNewPassphrase enforces the CLI's rules for new passphrases.
func checkNewPassphrase(pw []byte) error {
	if !utf8.Valid(pw) {
		return errors.New("the passphrase is not valid UTF-8")
	}
	if n := utf8.RuneCount(pw); n < minNewPassphrase {
		return fmt.Errorf("the passphrase is too short (%d characters; at least %d)", n, minNewPassphrase)
	}
	if len(bytes.TrimSpace(pw)) == 0 {
		return errors.New("the passphrase is blank")
	}
	if len(pw) > 1024 {
		return errors.New("the passphrase is too long (1024 bytes at most)")
	}
	return nil
}

// normalizeRecovery uppercases a recovery code fragment, drops spaces and
// dashes and applies the Crockford aliases (O→0, I/L→1).
func normalizeRecovery(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		switch r {
		case ' ', '-', '\t', '\r', '\n':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// recoveryConfirmed reports whether typed matches the code's last group
// (or the whole code).
func recoveryConfirmed(code, typed string) bool {
	t := normalizeRecovery(typed)
	if t == "" {
		return false
	}
	last := code
	if i := strings.LastIndexByte(code, '-'); i >= 0 {
		last = code[i+1:]
	}
	return t == normalizeRecovery(last) || t == normalizeRecovery(code)
}

// confirmRecovery asks for the last group of the recovery code until it
// matches (or input ends, which returns an error with message notConfirmed).
func (a *app) confirmRecovery(code, notConfirmed string) error {
	for i := 0; ; i++ {
		fmt.Fprint(a.stderr, "To confirm you saved it, type the LAST group of the recovery code: ")
		line, err := readLineBounded(a.stdin)
		if err != nil {
			return errors.New(notConfirmed)
		}
		ok := recoveryConfirmed(code, string(line))
		secmem.Wipe(line)
		if ok {
			return nil
		}
		fmt.Fprintln(a.stderr, "That does not match.")
		if i >= 1 {
			fmt.Fprintln(a.stderr, "Type the four characters after the final dash, exactly as you wrote them down.")
		}
	}
}

// askYesNo asks a yes/no question on the terminal.
func (a *app) askYesNo(question string, def bool) (bool, error) {
	fmt.Fprint(a.stderr, question)
	line, err := readLineBounded(a.stdin)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(string(line))) {
	case "":
		return def, nil
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// setApprovalMethod appends an [approval] method override to a config file
// freshly written by Init, and reverts if the result does not load.
func setApprovalMethod(path, method string) error {
	orig, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var add strings.Builder
	add.WriteString("\n# Set by `keyleash init`.")
	switch method {
	case "passphrase":
		add.WriteString(" Step-up approvals need your passphrase or recovery code,\n")
		add.WriteString("# typed into `keyleash approvals approve <id>`.\n")
	case "console":
		add.WriteString(" Step-up approvals are answered in the daemon's console\n")
		add.WriteString("# or with `keyleash approvals approve <id>` (passphrase or recovery code).\n")
	case "deny":
		add.WriteString(" Every step-up approval is denied.\n")
	default:
		add.WriteString("\n")
	}
	add.WriteString("# (Remove this table before uncommenting the [approval] lines above.)\n")
	fmt.Fprintf(&add, "[approval]\nmethod = %q\n", method)
	updated := append(slices.Clone(orig), add.String()...)
	if err := writeFilePrivate(path, updated); err != nil {
		return err
	}
	if _, err := config.Load(path); err != nil {
		_ = writeFilePrivate(path, orig)
		return err
	}
	return nil
}

// writeFilePrivate writes data to path (owner-only permissions) via a
// temporary file and rename.
func writeFilePrivate(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_ = os.Chmod(name, 0o600)
	return os.Rename(name, path)
}

// printNextSteps prints what to do after init.
func printNextSteps(a *app, daemonRunning bool) {
	fmt.Fprintln(a.stdout, "\nNext steps:")
	if !daemonRunning {
		fmt.Fprintln(a.stdout, "  keyleash daemon               # start the daemon (leave it running)")
		fmt.Fprintln(a.stdout, "  keyleash unlock               # in another terminal")
		fmt.Fprintln(a.stdout, "  keyleash add anthropic        # paste the key at the hidden prompt")
	}
	fmt.Fprintln(a.stdout, "  keyleash run -- claude        # run any agent with a budgeted, process-bound pass")
	fmt.Fprintln(a.stdout, "See docs/USAGE.md for editors, limits and approvals.")
}

// firstKey starts the daemon in the background, unlocks it with the slot
// just created and adds a provider key.
func (a *app) firstKey(ctx context.Context, dir, slot string, pw []byte) error {
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	_, serr := c.Status(qctx)
	cancel()
	if serr == nil {
		fmt.Fprintln(a.stderr, "A keyleash daemon is already running (probably for another data directory); stop it, then start `keyleash daemon` for this one.")
		printNextSteps(a, false)
		return nil
	}
	logPath := filepath.Join(dir, "daemon.log")
	if err := startBackgroundDaemon(dir, logPath, a.environ()); err != nil {
		return fmt.Errorf("could not start the daemon: %w", err)
	}
	if err := waitForDaemon(ctx, c, daemonStartWait); err != nil {
		return fmt.Errorf("the daemon did not start; see %s", logPath)
	}
	fmt.Fprintf(a.stderr, "Daemon started in the background (log: %s).\n", logPath)
	method := client.MethodPassphrase
	if slot == "hello" {
		method = client.MethodHello
		fmt.Fprintln(a.stderr, "Unlocking: confirm with Windows Hello...")
	}
	if _, err := c.Unlock(ctx, method, pw); err != nil {
		return err
	}
	// The provider name is read in the clear, so a pasted secret (the
	// recovery code or an API key still on the clipboard) is never echoed
	// back; unknown input re-prompts with a hint instead of aborting.
	var name string
	for try := 0; ; try++ {
		fmt.Fprint(a.stderr, "Provider ("+strings.Join(provider.Names(), ", ")+") [anthropic]: ")
		line, err := readLineBounded(a.stdin)
		if err != nil {
			return err
		}
		raw := strings.TrimSpace(string(line))
		secmem.Wipe(line)
		name = strings.ToLower(raw)
		if name == "" {
			name = "anthropic"
		}
		if _, ok := provider.Get(name); ok {
			break
		}
		if looksLikeSecret(raw) || len(raw) > 32 {
			fmt.Fprintln(a.stderr, "That looks like a key or recovery code, not a provider name. It was not stored; clear your terminal scrollback.")
		} else {
			fmt.Fprintln(a.stderr, "Unknown provider; type one of the names above.")
		}
		if try == 2 {
			return errors.New("no provider chosen; add a key later with: keyleash add <provider>")
		}
	}
	if err := a.addKey(ctx, c, name, "default", false); err != nil {
		return err
	}
	printNextSteps(a, true)
	return nil
}

// startBackgroundDaemon runs `keyleash daemon` detached, logging to
// logPath, with KEYLEASH_HOME pointing at dir.
func startBackgroundDaemon(dir, logPath string, environ []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	logf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(exe, "daemon")
	cmd.Env = applyEnvPlan(environ, envPlan{Set: []envVar{{"KEYLEASH_HOME", dir}}})
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = detachedProcAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// waitForDaemon polls the daemon's status until it answers or d elapses.
func waitForDaemon(ctx context.Context, c *client.Client, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		qctx, cancel := context.WithTimeout(ctx, time.Second)
		_, err := c.Status(qctx)
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}
