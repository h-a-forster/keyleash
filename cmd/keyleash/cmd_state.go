package main

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/secmem"
	"github.com/h-a-forster/keyleash/internal/vault"
)

var cmdStatus = &command{
	name:    "status",
	args:    "[--json]",
	summary: "show state, lease, spend vs limits and active passes",
	run: func(ctx context.Context, a *app, args []string) error {
		fs := newFlagSet("status")
		asJSON := fs.Bool("json", false, "print JSON")
		if pos, err := parseFlags(fs, args, true); err != nil {
			return err
		} else if len(pos) > 0 {
			return usagef("status", "unexpected argument")
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
		passes, perr := c.Passes(cctx)
		if *asJSON {
			out := struct {
				client.Status
				Passes []client.PassInfo `json:"active_passes"`
			}{Status: st, Passes: activePasses(passes)}
			if out.Passes == nil {
				out.Passes = []client.PassInfo{}
			}
			return a.printJSON(out)
		}
		printStatus(a.stdout, st, activePasses(passes), perr == nil, time.Now())
		return nil
	},
}

// printStatus renders a human status report.
func printStatus(w io.Writer, st client.Status, passes []client.PassInfo, passesOK bool, now time.Time) {
	state := st.State
	switch st.State {
	case client.StateUnlocked:
		state += fmt.Sprintf("  (lease until %s, %s left)", fmtTime(st.LeaseUntil, now), fmtDuration(st.LeaseUntil.Sub(now)))
	case client.StateAway:
		state += fmt.Sprintf("  (since %s; locks at %s)", fmtTime(st.AwaySince, now), fmtTime(st.AwayUntil, now))
	case client.StateTripped:
		state += "  (" + st.TripReason + "; run: keyleash resume)"
	case client.StateLocked:
		state += "  (run: keyleash unlock)"
	}
	fmt.Fprintf(w, "state:      %s\n", state)
	if st.ProxyAddr != "" {
		fmt.Fprintf(w, "proxy:      http://%s\n", st.ProxyAddr)
	}
	var slots []string
	for _, s := range st.Vault.Slots {
		slots = append(slots, s.Type)
	}
	fmt.Fprintf(w, "vault:      %s, slots: %s\n", map[bool]string{true: "unlocked", false: "locked"}[st.Vault.Unlocked], strings.Join(slots, ", "))
	if st.Grant != nil {
		g := st.Grant
		scope := "all passes"
		if g.Pass != "" {
			scope = "pass " + g.Pass
		}
		fmt.Fprintf(w, "grant:      %s while away until %s (%s)\n", g.Amount, fmtTime(g.Until, now), scope)
	}
	presence := "ok"
	if st.PresenceDegraded {
		presence = "degraded: " + st.PresenceDegradedReason
	}
	fmt.Fprintf(w, "presence:   %s\n", presence)
	if st.Integrity != "" && st.Integrity != "ok" {
		fmt.Fprintf(w, "integrity:  %s\n", st.Integrity)
	}
	if !st.AuditHealthy {
		fmt.Fprintln(w, "audit:      FAILING (writes to the audit log failed)")
	}
	if st.ApprovalMethod != "" {
		fmt.Fprintf(w, "step-up:    %s\n", st.ApprovalMethod)
	}
	if st.PendingApprovals > 0 {
		fmt.Fprintf(w, "approvals:  %d pending (keyleash approvals)\n", st.PendingApprovals)
	}
	if len(st.ConfigChanges) > 0 {
		fmt.Fprintln(w, "config:     changed since last accepted (`keyleash resume` accepts):")
		for _, ch := range st.ConfigChanges {
			fmt.Fprintf(w, "              %s\n", ch)
		}
	}
	if passesOK {
		fmt.Fprintf(w, "passes:     %d active\n", len(passes))
	}
	if len(st.InFlight) > 0 {
		var held money.Micros
		for _, f := range st.InFlight {
			held += f.Amount
		}
		fmt.Fprintf(w, "in flight:  %d requests holding %s\n", len(st.InFlight), held)
	}
	if len(st.Limits) > 0 {
		fmt.Fprintln(w)
		printLimitTable(w, st.Limits)
	}
	if passesOK && len(passes) > 0 {
		fmt.Fprintln(w)
		printPassTable(w, passes, now)
	}
	for _, warn := range st.Warnings {
		fmt.Fprintf(w, "\nwarning: %s", warn)
	}
	if len(st.Warnings) > 0 {
		fmt.Fprintln(w)
	}
}

// printLimitTable prints budget limits, global first.
func printLimitTable(w io.Writer, limits []client.LimitStatus) {
	ls := append([]client.LimitStatus(nil), limits...)
	order := map[string]int{"request": 0, "minute": 1, "hour": 2, "session": 3, "day": 4, "month": 5}
	sort.SliceStable(ls, func(i, j int) bool {
		si, sj := scopeRank(ls[i].Scope), scopeRank(ls[j].Scope)
		if si != sj {
			return si < sj
		}
		if ls[i].Scope != ls[j].Scope {
			return ls[i].Scope < ls[j].Scope
		}
		return order[ls[i].Window] < order[ls[j].Window]
	})
	tw := newTable(w)
	fmt.Fprintln(tw, "SCOPE\tWINDOW\tLIMIT\tSPENT\tRESERVED\tREMAINING")
	for _, l := range ls {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", l.Scope, l.Window, l.Limit, l.Settled, l.Reserved, l.Remaining)
	}
	tw.Flush()
}

func scopeRank(scope string) int {
	switch {
	case scope == "global":
		return 0
	case strings.HasPrefix(scope, "session:"):
		return 1
	case strings.HasPrefix(scope, "provider:"):
		return 2
	case strings.HasPrefix(scope, "model:"):
		return 3
	case scope == "away" || strings.HasPrefix(scope, "grant:"):
		return 4
	case strings.HasPrefix(scope, "pass:"):
		return 5
	}
	return 6
}

var cmdUnlock = &command{
	name:    "unlock",
	args:    "[--method auto|hello|passphrase|recovery|dpapi] [--recovery] [--stdin] [--accept-rollback]",
	summary: "unlock the vault (Windows Hello, passphrase or recovery code)",
	help: `
Unlocks the vault so passes work again. By default keyleash uses Windows
Hello when the vault has a Hello slot and Hello is available, otherwise it
asks for the passphrase at a hidden prompt. --recovery uses the recovery
code instead; --stdin reads the passphrase or code from standard input.

--accept-rollback accepts a vault file that is older than the last recorded
state (only after you restored a backup on purpose).`,
	run: runUnlock,
}

func runUnlock(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("unlock")
	method := fs.String("method", "auto", "auto, hello, passphrase, recovery or dpapi")
	recovery := fs.Bool("recovery", false, "unlock with the recovery code")
	fromStdin := fs.Bool("stdin", false, "read the passphrase or recovery code from stdin")
	acceptRollback := fs.Bool("accept-rollback", false, "accept an older vault file (after restoring a backup on purpose)")
	if pos, err := parseFlags(fs, args, true); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("unlock", "unexpected argument; the passphrase is read from a hidden prompt or --stdin")
	}
	m := *method
	if *recovery {
		if m != "auto" && m != client.MethodRecovery {
			return usagef("unlock", "--recovery conflicts with --method %s", m)
		}
		m = client.MethodRecovery
	}
	switch m {
	case "auto", client.MethodHello, client.MethodPassphrase, client.MethodRecovery, client.MethodDPAPI:
	default:
		return usagef("unlock", "--method must be auto, hello, passphrase, recovery or dpapi")
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	sctx, cancel := withTimeout(ctx)
	st, err := c.Status(sctx)
	cancel()
	if err != nil {
		return err
	}
	if st.State != client.StateLocked {
		fmt.Fprintf(a.stdout, "keyleash is already %s.\n", st.State)
		return nil
	}
	if m == "auto" {
		m = chooseUnlockMethod(st.Vault.Slots, *fromStdin)
	}
	if *acceptRollback {
		actx, cancel := withTimeout(ctx)
		err := c.AcceptRollback(actx)
		cancel()
		if err != nil {
			return err
		}
		fmt.Fprintln(a.stderr, "Rollback override armed for this unlock.")
	}
	var secret []byte
	defer func() { secmem.Wipe(secret) }()
	switch m {
	case client.MethodPassphrase:
		if secret, err = a.readSecret("Passphrase: ", *fromStdin); err != nil {
			return err
		}
	case client.MethodRecovery:
		if secret, err = a.readSecret("Recovery code: ", *fromStdin); err != nil {
			return err
		}
	case client.MethodHello:
		fmt.Fprintln(a.stderr, "Confirm with Windows Hello...")
	}
	// No timeout: Argon2 and Windows Hello prompts take their time; Ctrl-C
	// cancels.
	st, err = c.Unlock(ctx, m, secret)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "Unlocked (lease until %s).\n", fmtTime(st.LeaseUntil, time.Now()))
	if st.State == client.StateAway {
		fmt.Fprintln(a.stderr, "note: no recent keyboard or mouse input, so keyleash is in away mode (away limits apply until you are active).")
	}
	for _, w := range st.Warnings {
		fmt.Fprintf(a.stderr, "warning: %s\n", w)
	}
	for _, ch := range st.ConfigChanges {
		fmt.Fprintf(a.stderr, "config change: %s\n", ch)
	}
	if st.State == client.StateTripped {
		fmt.Fprintf(a.stderr, "warning: keyleash is tripped (%s); check `keyleash status`, then run: keyleash resume\n", st.TripReason)
	}
	return nil
}

// chooseUnlockMethod picks Windows Hello when the vault has a Hello slot
// and Hello works (and no secret is being piped in), else the passphrase.
func chooseUnlockMethod(slots []client.Slot, fromStdin bool) string {
	hasHello, hasPass := false, false
	for _, s := range slots {
		switch s.Type {
		case vault.SlotHello:
			hasHello = true
		case vault.SlotPassphrase:
			hasPass = true
		}
	}
	if hasHello && !fromStdin {
		if ok, _ := helloAvailable(); ok || !hasPass {
			return client.MethodHello
		}
	}
	if !hasPass && !hasHello {
		return client.MethodRecovery
	}
	return client.MethodPassphrase
}

var cmdLock = &command{
	name:    "lock",
	args:    "",
	summary: "lock the vault now (passes stop working until unlock)",
	run: func(ctx context.Context, a *app, args []string) error {
		if pos, err := parseFlags(newFlagSet("lock"), args, true); err != nil {
			return err
		} else if len(pos) > 0 {
			return usagef("lock", "unexpected argument")
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		defer c.Close()
		cctx, cancel := withTimeout(ctx)
		defer cancel()
		if _, err := c.Lock(cctx); err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, "Locked.")
		return nil
	},
}

var cmdPanic = &command{
	name:    "panic",
	args:    "[--revoke-upstream]",
	summary: "lock immediately and revoke every pass",
	help: `
Locks the vault and revokes all passes at once. --revoke-upstream will also
deactivate keys at the provider once that is implemented; until then rotate
the keys in the provider console if you suspect a leak.`,
	run: func(ctx context.Context, a *app, args []string) error {
		fs := newFlagSet("panic")
		upstream := fs.Bool("revoke-upstream", false, "also revoke keys at the provider (not implemented yet)")
		if pos, err := parseFlags(fs, args, true); err != nil {
			return err
		} else if len(pos) > 0 {
			return usagef("panic", "unexpected argument")
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		defer c.Close()
		cctx, cancel := withTimeout(ctx)
		defer cancel()
		sum, err := c.Panic(cctx, *upstream)
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "Locked; %d passes revoked.\n", sum.PassesRevoked)
		if sum.Note != "" {
			fmt.Fprintf(a.stderr, "note: %s\n", sum.Note)
		}
		return nil
	},
}

var cmdAway = &command{
	name:    "away",
	args:    "--budget <amount> --for <duration> [--pass <id>]",
	summary: "pre-authorise spend while you are away (step-up approval)",
	help: `
Grants an unattended budget, for example before leaving an agent running
overnight:

    keyleash away --budget 20 --for 8h

While the grant is active, Away mode uses this budget instead of the away
limits, and the lock that normally follows away_max waits until the grant
ends. --pass limits the grant to one pass. Needs a step-up approval.
In bash, write amounts as 20 or '$20' ("$20" would be expanded by the shell).`,
	run: func(ctx context.Context, a *app, args []string) error {
		fs := newFlagSet("away")
		var budget moneyFlag
		var dur durationFlag
		fs.Var(&budget, "budget", "amount allowed while away")
		fs.Var(&dur, "for", "how long the grant lasts (e.g. 8h)")
		passID := fs.String("pass", "", "limit the grant to this pass id")
		if pos, err := parseFlags(fs, args, true); err != nil {
			return err
		} else if len(pos) > 0 {
			return usagef("away", "unexpected argument")
		}
		if !budget.set || !dur.set {
			return usagef("away", "both --budget and --for are required")
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		defer c.Close()
		fmt.Fprintln(a.stderr, "Waiting for step-up approval...")
		var g client.Grant
		err = a.withStepUp(ctx, c, func(ctx context.Context) error {
			var err error
			g, err = c.Away(ctx, client.AwayRequest{Budget: budget.v, For: dur.v, Pass: *passID})
			return err
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "Grant %s: %s while away, until %s.\n", g.ID, g.Amount, fmtTime(g.Until, time.Now()))
		return nil
	},
}

var cmdResume = &command{
	name:    "resume",
	args:    "",
	summary: "leave the Tripped state (step-up approval)",
	run: func(ctx context.Context, a *app, args []string) error {
		if pos, err := parseFlags(newFlagSet("resume"), args, true); err != nil {
			return err
		} else if len(pos) > 0 {
			return usagef("resume", "unexpected argument")
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		defer c.Close()
		fmt.Fprintln(a.stderr, "Waiting for step-up approval...")
		var st client.Status
		err = a.withStepUp(ctx, c, func(ctx context.Context) error {
			var err error
			st, err = c.Resume(ctx)
			return err
		})
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "Resumed; state is %s.\n", st.State)
		return nil
	},
}

var cmdLimits = &command{
	name:    "limits",
	args:    "[show] [--json]",
	summary: "show configured limits and current spend",
	help: `
Shows the effective limits (global, provider, model, away, pass defaults,
tripwire) and how much of each budget window is used. To change limits,
edit config.toml ('keyleash config path'), check it with 'keyleash config
check', and restart the daemon.`,
	run: runLimits,
}

func runLimits(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("limits")
	asJSON := fs.Bool("json", false, "print JSON")
	pos, err := parseFlags(fs, args, true)
	if err != nil {
		return err
	}
	if len(pos) > 0 && pos[0] == "set" {
		return usagef("limits", "limits are set in config.toml: edit it (keyleash config path), run 'keyleash config check', then restart the daemon")
	}
	if len(pos) > 1 || (len(pos) == 1 && pos[0] != "show") {
		return usagef("limits", "unknown subcommand")
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
	text, err := c.Config(cctx)
	if err != nil {
		return err
	}
	cfg, err := config.Parse(text)
	if err != nil {
		return fmt.Errorf("the daemon's config could not be parsed: %w", err)
	}
	if *asJSON {
		return a.printJSON(struct {
			Live     []client.LimitStatus `json:"live"`
			OnExceed string               `json:"on_exceed"`
		}{st.Limits, cfg.Limits.OnExceed})
	}
	printConfiguredLimits(a.stdout, cfg)
	if len(st.Limits) > 0 {
		fmt.Fprintln(a.stdout)
		printLimitTable(a.stdout, st.Limits)
	}
	return nil
}

// printConfiguredLimits summarises the limit-related config.
func printConfiguredLimits(w io.Writer, cfg *config.Config) {
	fmt.Fprintf(w, "profile:      %s\n", cfg.Profile)
	fmt.Fprintf(w, "global:       %s\n", fmtLimits(cfg.Limits.Global))
	names := sortedKeys(cfg.Limits.Provider)
	for _, n := range names {
		fmt.Fprintf(w, "provider %s: %s\n", n, fmtLimits(cfg.Limits.Provider[n]))
	}
	for _, n := range sortedKeys(cfg.Limits.Model) {
		fmt.Fprintf(w, "model %s: %s\n", n, fmtLimits(cfg.Limits.Model[n]))
	}
	away := "unlimited"
	if cfg.Limits.Away.Total != nil {
		away = cfg.Limits.Away.Total.String()
	}
	fmt.Fprintf(w, "away:         %s total, concurrency %d, new run passes %s\n", away, cfg.Limits.Away.Concurrency,
		map[bool]string{true: "allowed", false: "refused"}[cfg.Limits.Away.AllowNewRunPasses])
	pd := cfg.Limits.Pass
	day := "none"
	if pd.Day != nil {
		day = pd.Day.String()
	}
	fmt.Fprintf(w, "passes:       ttl %s (run %s), day %s, concurrency %d\n", pd.TTL.Duration, pd.RunTTL.Duration, day, pd.Concurrency)
	trip := "off"
	if cfg.Tripwire.Threshold != nil {
		trip = fmt.Sprintf("%s in %s", cfg.Tripwire.Threshold, cfg.Tripwire.Window.Duration)
	}
	fmt.Fprintf(w, "tripwire:     %s\n", trip)
	fmt.Fprintf(w, "on exceed:    %s; unknown models: %s\n", cfg.Limits.OnExceed, cfg.Models.Unknown)
}

// fmtLimits renders one scope's configured limits.
func fmtLimits(l config.Limits) string {
	var parts []string
	for _, w := range []string{"request", "minute", "hour", "session", "day", "month"} {
		if v, ok := l.Windows()[w]; ok {
			parts = append(parts, w+" "+v.String())
		}
	}
	if l.Concurrency > 0 {
		parts = append(parts, fmt.Sprintf("concurrency %d", l.Concurrency))
	}
	if len(parts) == 0 {
		return "unlimited"
	}
	return strings.Join(parts, ", ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
