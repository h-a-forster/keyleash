package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/glob"
	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/procinfo"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/vault"
)

// passFlags are the scope flags shared by `pass create`, `env` and `run`.
type passFlags struct {
	name        *string
	providers   listFlag
	models      listFlag
	denyModels  listFlag
	budget      moneyFlag
	limits      limitsFlag
	ttl         durationFlag
	concurrency *int
}

func addPassFlags(fs *flag.FlagSet, defaultName string) *passFlags {
	pf := &passFlags{}
	pf.name = fs.String("name", defaultName, "pass name (shown in usage and audit)")
	fs.Var(&pf.providers, "providers", "providers the pass may use, comma-separated (default: those with a stored key)")
	fs.Var(&pf.providers, "provider", "alias of --providers")
	fs.Var(&pf.models, "models", "allowed model globs, comma-separated (e.g. 'claude-*,gpt-5*')")
	fs.Var(&pf.denyModels, "deny-models", "denied model globs, comma-separated")
	fs.Var(&pf.budget, "budget", "total spend allowed for this pass (e.g. 5)")
	fs.Var(&pf.limits, "limit", "per-window limit window=amount (request|minute|hour|day|month|session), repeatable")
	fs.Var(&pf.ttl, "ttl", "lifetime (e.g. 8h, 7d; default from config)")
	pf.concurrency = fs.Int("concurrency", 0, "max parallel requests (default from config)")
	return pf
}

// request builds the create request. providers must already be resolved.
func (pf *passFlags) request(cmd, kind string, providers []string) (client.PassCreateRequest, error) {
	for _, g := range append(slices.Clone(pf.models), pf.denyModels...) {
		if !glob.Valid(g) {
			return client.PassCreateRequest{}, usagef(cmd, "invalid model pattern %q", sanitizeArg(g))
		}
	}
	if *pf.concurrency < 0 {
		return client.PassCreateRequest{}, usagef(cmd, "--concurrency cannot be negative")
	}
	name := strings.TrimSpace(*pf.name)
	if len(name) > 64 {
		name = name[:64]
	}
	req := client.PassCreateRequest{
		Name: name, Kind: kind, Providers: providers,
		Models: pf.models, DenyModels: pf.denyModels,
		Limits: slices.Clone([]client.PassLimit(pf.limits)), Concurrency: *pf.concurrency,
	}
	if pf.budget.set {
		req.Limits = append(req.Limits, budgetLimits(pf.budget.v)...)
	}
	if pf.ttl.set {
		req.TTL = pf.ttl.v
	}
	return req, nil
}

// resolveProviders validates explicit providers, or picks the providers
// that have a stored API key. With needBaseURL, the default excludes
// providers without a standard base-URL variable (their tools must be
// pointed at the proxy by hand, so they are opt-in).
func resolveProviders(explicit []string, keys []client.KeyInfo, needBaseURL bool) ([]string, error) {
	have := map[string]bool{}
	for _, k := range keys {
		if k.Kind == "" || k.Kind == vault.KindAPIKey {
			have[k.Provider] = true
		}
	}
	if len(explicit) > 0 {
		var out []string
		for _, n := range explicit {
			n = strings.ToLower(strings.TrimSpace(n))
			if n == pass.AllProviders {
				return nil, errors.New(`list providers explicitly instead of "*"`)
			}
			if _, ok := provider.Get(n); !ok {
				return nil, fmt.Errorf("unknown provider %q (want %s)", sanitizeArg(n), strings.Join(provider.Names(), ", "))
			}
			if !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
		return out, nil
	}
	var out []string
	for _, n := range provider.Names() {
		p, _ := provider.Get(n)
		if have[n] && (!needBaseURL || p.BaseURLEnv != "") {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		if len(have) > 0 && needBaseURL {
			return nil, errors.New("none of your stored keys is for a provider with a standard base-URL variable; name it with --providers")
		}
		return nil, errors.New("no provider keys stored yet; add one with: keyleash add <provider>")
	}
	return out, nil
}

// missingKeys lists providers that have no stored API key.
func missingKeys(providers []string, keys []client.KeyInfo) []string {
	var out []string
	for _, p := range providers {
		found := false
		for _, k := range keys {
			found = found || (k.Provider == p && (k.Kind == "" || k.Kind == vault.KindAPIKey))
		}
		if !found {
			out = append(out, p)
		}
	}
	return out
}

var cmdPass = &command{
	name:    "pass",
	args:    "create|list|revoke [flags]",
	summary: "create, list or revoke named passes",
	help: `
  keyleash pass create --name vscode [--providers anthropic] [--models 'claude-*']
                       [--budget 5] [--limit day=2] [--ttl 7d] [--concurrency 2] [--json]
      Prints the pass token once on stdout (details on stderr). Store it like
      a password; it only works against this machine's keyleash proxy.
  keyleash pass list [--all] [--json]
      Active passes (--all includes revoked and expired ones).
  keyleash pass revoke <id>

--budget caps the pass's total spend (it holds across unlocks and month
boundaries unless both happen together); --limit adds window limits.
For editors, 'keyleash env' creates a pass and prints shell exports.`,
	run: runPass,
}

func runPass(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return usagef("pass", "missing subcommand: create, list or revoke")
	}
	switch args[0] {
	case "create":
		return runPassCreate(ctx, a, args[1:])
	case "list", "ls":
		return runPassList(ctx, a, args[1:])
	case "revoke", "rm":
		return runPassRevoke(ctx, a, args[1:])
	}
	return usagef("pass", "unknown subcommand %q (want create, list or revoke)", sanitizeArg(args[0]))
}

func runPassCreate(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("pass")
	pf := addPassFlags(fs, "pass")
	asJSON := fs.Bool("json", false, "print JSON (includes the token)")
	if pos, err := parseFlags(fs, args, true); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("pass", "unexpected argument")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	keys, err := c.Keys(cctx)
	if err != nil {
		return err
	}
	providers, err := resolveProviders(pf.providers, keys, false)
	if err != nil {
		return err
	}
	req, err := pf.request("pass", pass.KindNamed, providers)
	if err != nil {
		return err
	}
	var resp client.PassCreateResponse
	err = a.withStepUp(ctx, c, func(ctx context.Context) error {
		var err error
		resp, err = c.CreatePass(ctx, req)
		return err
	})
	if err != nil {
		return err
	}
	if *asJSON {
		return a.printJSON(resp)
	}
	p := resp.Pass
	fmt.Fprintf(a.stderr, "Created pass %s (%s) for %s, expires %s.\n", p.ID, p.Name, strings.Join(p.Providers, ", "), fmtTime(p.Expires, time.Now()))
	if miss := missingKeys(p.Providers, keys); len(miss) > 0 {
		fmt.Fprintf(a.stderr, "warning: no key stored for %s yet (keyleash add %s)\n", strings.Join(miss, ", "), miss[0])
	}
	fmt.Fprintln(a.stderr, "Token (shown once; it only works against this machine's keyleash):")
	fmt.Fprintln(a.stdout, resp.Token)
	return nil
}

func runPassList(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("pass")
	all := fs.Bool("all", false, "include revoked and expired passes")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, err := parseFlags(fs, args, true); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("pass", "unexpected argument")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	ps, err := c.Passes(cctx)
	if err != nil {
		return err
	}
	if !*all {
		ps = activePasses(ps)
	}
	if *asJSON {
		if ps == nil {
			ps = []client.PassInfo{}
		}
		return a.printJSON(ps)
	}
	if len(ps) == 0 {
		fmt.Fprintln(a.stdout, "No active passes.")
		return nil
	}
	printPassTable(a.stdout, ps, time.Now())
	return nil
}

// printPassTable prints pass metadata (never tokens).
func printPassTable(w io.Writer, ps []client.PassInfo, now time.Time) {
	tw := newTable(w)
	fmt.Fprintln(tw, "ID\tNAME\tKIND\tPROVIDERS\tEXPIRES\tLAST USED\tBOUND TO\tSTATUS")
	for _, p := range ps {
		status := "active"
		switch {
		case p.Revoked:
			status = "revoked"
		case p.Expired:
			status = "expired"
		}
		bound := "-"
		if p.BindPID > 0 {
			bound = fmt.Sprintf("%s (%d)", p.BindImage, p.BindPID)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", p.ID, p.Name, p.Kind, strings.Join(p.Providers, ","),
			fmtTime(p.Expires, now), fmtTime(p.LastUsed, now), bound, status)
	}
	tw.Flush()
}

func runPassRevoke(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("pass")
	pos, err := parseFlags(fs, args, true)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("pass", "revoke takes exactly one pass id (see 'keyleash pass list')")
	}
	id := pos[0]
	if pass.LooksLikePass(id) {
		// Unreachable via main (argv secrets are rejected), kept for safety.
		return usagef("pass", "give the pass id, not the token")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	if err := c.RevokePass(cctx, id); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Revoked pass %s.\n", id)
	return nil
}

var cmdEnv = &command{
	name:    "env",
	args:    "[--shell bash|zsh|fish|powershell|cmd] [--name editor] [--providers a,b] [pass flags]",
	summary: "create a named pass and print shell exports for it",
	help: `
Creates a named pass and prints the commands that point SDKs at the proxy
with it (base URL and API-key variables; never a real key):

    PowerShell:  keyleash env --name vscode | Invoke-Expression
    bash/zsh:    eval "$(keyleash env --name vscode)"
    fish:        keyleash env --name vscode --shell fish | source
    cmd:         keyleash env --shell cmd > kl.cmd && call kl.cmd && del kl.cmd

The shell is detected from the parent process (or $SHELL) unless --shell is
given. Pass details go to stderr, exports to stdout. Accepts the same scope
flags as 'pass create' (--models, --budget, --limit, --ttl, --concurrency).`,
	run: runEnv,
}

func runEnv(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("env")
	pf := addPassFlags(fs, "env")
	shellFlag := fs.String("shell", "", "bash, zsh, fish, powershell or cmd (default: detect)")
	if pos, err := parseFlags(fs, args, true); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("env", "unexpected argument")
	}
	shell := ""
	if *shellFlag != "" {
		s, err := normalizeShell(*shellFlag)
		if err != nil {
			return usagef("env", "%v", err)
		}
		shell = s
	} else {
		shell = detectShell(parentImage(), a.getenv("SHELL"), runtime.GOOS)
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
	if st.State == client.StateLocked {
		return errLocked
	}
	keys, err := c.Keys(cctx)
	if err != nil {
		return err
	}
	providers, err := resolveProviders(pf.providers, keys, true)
	if err != nil {
		return err
	}
	req, err := pf.request("env", pass.KindNamed, providers)
	if err != nil {
		return err
	}
	// Validate the address before creating a pass we could not print.
	if _, err := proxyRoot(st.ProxyAddr); err != nil {
		return err
	}
	var resp client.PassCreateResponse
	err = a.withStepUp(ctx, c, func(ctx context.Context) error {
		var err error
		resp, err = c.CreatePass(ctx, req)
		return err
	})
	if err != nil {
		return err
	}
	plan, err := buildEnvPlan(st.ProxyAddr, resp.Pass.Providers, resp.Token, resp.Pass.ID, a.environ())
	if err == nil {
		var text string
		if text, err = renderEnv(shell, plan); err == nil {
			fmt.Fprint(a.stdout, text)
		}
	}
	if err != nil {
		// Never leave an unprinted, unusable pass behind.
		rctx, rcancel := context.WithTimeout(context.Background(), revokeTimeout)
		_ = c.RevokePass(rctx, resp.Pass.ID)
		rcancel()
		return err
	}
	fmt.Fprintf(a.stderr, "# keyleash: pass %s (%s) for %s, expires %s; revoke with: keyleash pass revoke %s\n",
		resp.Pass.ID, resp.Pass.Name, strings.Join(resp.Pass.Providers, ", "), fmtTime(resp.Pass.Expires, time.Now()), resp.Pass.ID)
	return nil
}

// parentImage returns the executable path of this process's parent, or ""
// when it cannot be determined.
func parentImage() string {
	p, err := procinfo.Lookup(os.Getppid())
	if err != nil {
		return ""
	}
	return p.Image
}
