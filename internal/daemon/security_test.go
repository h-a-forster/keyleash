package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/meter"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/proxy"
)

// Regression tests for the admin-channel security review: access to the
// admin channel (any process of the owner's user) is never proof of owner
// presence (spec §9, §12).

// pendingOf returns the pending approvals of kind.
func (e *env) pendingOf(kind string) []client.Approval {
	e.t.Helper()
	list, err := e.c.Approvals(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	var out []client.Approval
	for _, ap := range list {
		if ap.Kind == kind {
			out = append(out, ap)
		}
	}
	return out
}

// waitPendingN waits until n approvals of kind are pending.
func (e *env) waitPendingN(kind string, n int) []client.Approval {
	e.t.Helper()
	for i := 0; i < 500; i++ {
		if ps := e.pendingOf(kind); len(ps) >= n {
			return ps
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatalf("fewer than %d pending %s approvals: %+v", n, kind, e.pendingOf(kind))
	return nil
}

// Finding 1: a second caller of an admin step-up never rides on another
// caller's approval (it used to receive the rotated recovery code).
func TestRotateRecoveryStepUpsNeverCoalesce(t *testing.T) {
	e := newEnv(t, nil)
	e.approver = blockingApprover{}
	e.restart()
	e.unlock()
	type res struct {
		r   client.RotateRecoveryResponse
		err error
	}
	a, b := make(chan res, 1), make(chan res, 1)
	go func() { r, err := e.c.RotateRecovery(e.ctx()); a <- res{r, err} }()
	first := e.waitPendingN("admin_change", 1)
	go func() { r, err := e.c.RotateRecovery(e.ctx()); b <- res{r, err} }()
	both := e.waitPendingN("admin_change", 2)
	if both[0].ID == both[1].ID || both[0].Waiters != 1 || both[1].Waiters != 1 {
		t.Fatalf("admin step-ups coalesced: %+v", both)
	}
	if err := e.c.Decide(e.ctx(), first[0].ID, client.DecideRequest{Approved: true, Secret: ownerSecret()}); err != nil {
		t.Fatal(err)
	}
	ra := <-a
	if ra.err != nil || ra.r.Code == "" {
		t.Fatalf("approved caller: %+v", ra)
	}
	select {
	case rb := <-b:
		t.Fatalf("second caller finished on the first approval: %+v", rb)
	case <-time.After(100 * time.Millisecond):
	}
	second := both[0].ID
	if second == first[0].ID {
		second = both[1].ID
	}
	if err := e.c.Decide(e.ctx(), second, client.DecideRequest{Approved: false}); err != nil {
		t.Fatal(err)
	}
	if rb := <-b; !isAPI(rb.err, 403, client.CodeStepUpDenied) || rb.r.Code != "" {
		t.Fatalf("denied caller: %+v", rb)
	}
	e.assertNoSecrets(ra.r.Code)
}

// Finding 2: away grants never coalesce, and each prompt shows its own
// amount, duration and pass.
func TestAwayGrantsNeverCoalesce(t *testing.T) {
	e := newEnv(t, nil)
	e.approver = blockingApprover{}
	e.restart()
	e.unlock()
	type res struct {
		g   client.Grant
		err error
	}
	a, b := make(chan res, 1), make(chan res, 1)
	go func() {
		g, err := e.c.Away(e.ctx(), client.AwayRequest{Budget: money.Dollar, For: time.Hour})
		a <- res{g, err}
	}()
	e.waitPendingN("away_grant", 1)
	go func() {
		g, err := e.c.Away(e.ctx(), client.AwayRequest{Budget: 50 * money.Dollar, For: 8 * time.Hour})
		b <- res{g, err}
	}()
	ps := e.waitPendingN("away_grant", 2)
	var small, big client.Approval
	for _, p := range ps {
		switch {
		case strings.Contains(p.Prompt, "$1.00") && strings.Contains(p.Prompt, "1h0m0s"):
			small = p
		case strings.Contains(p.Prompt, "$50.00") && strings.Contains(p.Prompt, "8h0m0s"):
			big = p
		}
	}
	if small.ID == "" || big.ID == "" || !strings.Contains(big.Prompt, "any pass") {
		t.Fatalf("prompts do not show the exact grants: %+v", ps)
	}
	if err := e.c.Decide(e.ctx(), small.ID, client.DecideRequest{Approved: true, Secret: ownerSecret()}); err != nil {
		t.Fatal(err)
	}
	if ra := <-a; ra.err != nil || ra.g.Amount != money.Dollar {
		t.Fatalf("small grant: %+v", ra)
	}
	if err := e.c.Decide(e.ctx(), big.ID, client.DecideRequest{Approved: false}); err != nil {
		t.Fatal(err)
	}
	if rb := <-b; !isAPI(rb.err, 403, client.CodeStepUpDenied) {
		t.Fatalf("big grant must not ride on the small approval: %+v", rb)
	}
	if g := e.status().Grant; g == nil || g.Amount != money.Dollar {
		t.Fatalf("active grant = %+v", g)
	}
}

// Finding 3: wrong secrets are rate limited; approval.method = deny refuses
// every approval; only the vault-verified secret approves.
func TestDecideSecretRateLimitAndDenyMethod(t *testing.T) {
	e := newEnv(t, nil)
	e.approver = blockingApprover{}
	e.restart()
	e.unlock()
	done := make(chan error, 1)
	go func() {
		_, err := e.c.Away(e.ctx(), client.AwayRequest{Budget: money.Dollar, For: time.Hour})
		done <- err
	}()
	id := e.waitPending("away_grant")
	for i := 0; i < secretFreeTries; i++ {
		if err := e.c.Decide(e.ctx(), id, client.DecideRequest{Approved: true, Secret: []byte("guess")}); !isAPI(err, 401, client.CodeWrongSecret) {
			t.Fatalf("wrong secret %d: %v", i, err)
		}
	}
	if err := e.c.Decide(e.ctx(), id, client.DecideRequest{Approved: true, Secret: ownerSecret()}); !isAPI(err, 429, client.CodeRateLimited) {
		t.Fatalf("after %d wrong secrets: %v", secretFreeTries, err)
	}
	e.clk.Advance(secretBackoff + time.Second)
	if err := e.c.Decide(e.ctx(), id, client.DecideRequest{Approved: true, Secret: ownerSecret()}); err != nil {
		t.Fatalf("after the backoff: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	recs, err := e.c.AuditTail(e.ctx(), 200)
	if err != nil {
		t.Fatal(err)
	}
	fails := 0
	for _, r := range recs {
		if r.Type == "approval_secret" && r.Fields["ok"] == false {
			fails++
		}
	}
	if fails != secretFreeTries {
		t.Fatalf("audited wrong secrets = %d", fails)
	}

	d := newEnv(t, func(c *config.Config) { c.Approval.Method = "deny" })
	d.approver = blockingApprover{}
	d.restart()
	d.unlock()
	go func() {
		_, err := d.c.Away(d.ctx(), client.AwayRequest{Budget: money.Dollar, For: time.Hour})
		done <- err
	}()
	id = d.waitPending("away_grant")
	if err := d.c.Decide(d.ctx(), id, client.DecideRequest{Approved: true, Secret: ownerSecret()}); !isAPI(err, 403, client.CodeForbidden) {
		t.Fatalf("method deny: %v", err)
	}
	if err := d.c.Decide(d.ctx(), id, client.DecideRequest{Approved: false}); err != nil {
		t.Fatal(err)
	}
	<-done
}

// Finding 4: a process inside a run pass's tree may read status and revoke
// its own pass, nothing else; an unidentified caller may only read.
func TestConfinedCallers(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	var own, other client.PassCreateResponse
	if err := e.withOwner(func(ctx context.Context) error {
		var err error
		own, err = e.c.CreatePass(ctx, client.PassCreateRequest{Name: "run", Kind: "run", Providers: []string{"anthropic"}, BindPID: os.Getpid()})
		if err != nil {
			return err
		}
		other, err = e.c.CreatePass(ctx, client.PassCreateRequest{Name: "editor", Providers: []string{"anthropic"}})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The test process is now inside the run pass's tree.
	e.setAdminPID(os.Getpid())
	if _, err := e.c.Status(e.ctx()); err != nil {
		t.Fatalf("status: %v", err)
	}
	for name, call := range map[string]func() error{
		"create pass": func() error {
			_, err := e.c.CreatePass(e.ctx(), client.PassCreateRequest{Name: "x", Kind: "run", Providers: []string{"anthropic"}, BindPID: os.Getpid()})
			return err
		},
		"add key": func() error {
			_, err := e.c.AddKey(e.ctx(), "gemini", "x", []byte("AIzaFAKEFAKEFAKEFAKEFAKE"))
			return err
		},
		"list passes": func() error { _, err := e.c.Passes(e.ctx()); return err },
		"approvals":   func() error { _, err := e.c.Approvals(e.ctx()); return err },
		"away": func() error {
			_, err := e.c.Away(e.ctx(), client.AwayRequest{Budget: money.Dollar, For: time.Hour})
			return err
		},
		"revoke another": func() error { return e.c.RevokePass(e.ctx(), other.Pass.ID) },
	} {
		if err := call(); !isAPI(err, 403, client.CodeConfined) {
			t.Errorf("%s from a confined caller: %v", name, err)
		}
	}
	if err := e.c.RevokePass(e.ctx(), own.Pass.ID); err != nil {
		t.Fatalf("revoking its own pass: %v", err)
	}
	// The pass is gone but the process is still in its job: it stays
	// confined until it exits (finding A).
	if _, err := e.c.Passes(e.ctx()); !isAPI(err, 403, client.CodeConfined) {
		t.Fatalf("after revoking, still in the job: %v", err)
	}
	// Once its last member has exited the job is released.
	e.jobs.kill(os.Getpid())
	e.d.sweepRunPasses()
	if _, err := e.c.Passes(e.ctx()); err != nil {
		t.Fatalf("after the job was released: %v", err)
	}
	// A caller whose PID cannot be verified may read but not mutate.
	e.setAdminPID(-1)
	if _, err := e.c.Passes(e.ctx()); err != nil {
		t.Fatalf("unknown caller read: %v", err)
	}
	if err := e.c.RevokePass(e.ctx(), other.Pass.ID); !isAPI(err, 403, client.CodeConfined) {
		t.Fatalf("unknown caller revoke: %v", err)
	}
	// Locking only adds protection: any caller may (finding H).
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatalf("unknown caller lock: %v", err)
	}
}

// Finding 4: only a run pass bound to the caller's own verified PID, within
// the defaults, is issued without a step-up.
func TestRunPassWithoutStepUpOnlyWithinDefaults(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	e.appr.strictSetup.Store(true) // nothing is approved from here on
	e.setAdminPID(os.Getpid())
	self := os.Getpid()
	asked := len(e.appr.requests())
	denied := map[string]client.PassCreateRequest{
		"named pass":         {Name: "n", Providers: []string{"anthropic"}},
		"bound to another":   {Name: "r", Kind: "run", Providers: []string{"anthropic"}, BindPID: os.Getppid()},
		"over budget":        {Name: "r", Kind: "run", Providers: []string{"anthropic"}, BindPID: self, Limits: []client.PassLimit{{Window: "month", Amount: 50 * money.Dollar}}},
		"provider w/o key":   {Name: "r", Kind: "run", Providers: []string{"gemini"}, BindPID: self},
		"all providers":      {Name: "r", Kind: "run", Providers: []string{"*"}, BindPID: self},
		"long ttl":           {Name: "r", Kind: "run", Providers: []string{"anthropic"}, BindPID: self, TTL: 48 * time.Hour},
		"higher concurrency": {Name: "r", Kind: "run", Providers: []string{"anthropic"}, BindPID: self, Concurrency: 64},
	}
	for name, req := range denied {
		if _, err := e.c.CreatePass(e.ctx(), req); !isAPI(err, 403, client.CodeStepUpDenied) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(e.appr.requests()) - asked; n != len(denied) {
		t.Fatalf("approver asked %d times, want %d (one per refused pass)", n, len(denied))
	}
	r, err := e.c.CreatePass(e.ctx(), client.PassCreateRequest{Name: "run", Kind: "run", Providers: []string{"anthropic", "openai"}, BindPID: self})
	if err != nil {
		t.Fatalf("run pass within defaults: %v", err)
	}
	if n := len(e.appr.requests()) - asked; n != len(denied) {
		t.Fatal("a run pass within the defaults asked for approval")
	}
	limits := map[string]money.Micros{}
	for _, l := range r.Pass.Limits {
		limits[l.Window] = l.Amount
	}
	if limits["month"] != 10*money.Dollar || limits["session"] != 10*money.Dollar {
		t.Fatalf("default run budget = %+v", r.Pass.Limits)
	}
	p, _ := e.d.passes.Get(r.Pass.ID)
	if p.Entries["anthropic"] == "" || p.Entries["openai"] == "" {
		t.Fatalf("pass entries = %+v", p.Entries)
	}
	wantReason(t, e.anthropic(r.Token), 200, "")
}

// Finding 4: no pass may be created while away (run passes only with
// allow_new_run_passes), even with an approval at hand.
func TestNoPassCreationWhileAway(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	e.pres.set(time.Hour, false)
	e.d.stepPresence()
	if st := e.status(); st.State != client.StateAway {
		t.Fatalf("state = %s", st.State)
	}
	err := e.withOwner(func(ctx context.Context) error {
		_, err := e.c.CreatePass(ctx, client.PassCreateRequest{Name: "n", Providers: []string{"anthropic"}})
		return err
	})
	if !isAPI(err, 403, client.CodeForbidden) {
		t.Fatalf("named pass while away: %v", err)
	}
	err = e.withOwner(func(ctx context.Context) error {
		_, err := e.c.CreatePass(ctx, client.PassCreateRequest{Name: "r", Kind: "run", Providers: []string{"anthropic"}, BindPID: os.Getpid()})
		return err
	})
	if !isAPI(err, 403, client.CodeForbidden) {
		t.Fatalf("run pass while away without allow_new_run_passes: %v", err)
	}
}

// Finding 5 is covered by TestStateFileTamperTrips (state.json and ledger
// deleted together trip integrity).

// Finding 6: caller-controlled fields cannot make the log drop a record; a
// security record the log still rejects trips the daemon.
func TestAuditSanitisesAndTripsOnRejectedSecurityRecord(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	hostile := "sk-ant-api03-" + strings.Repeat("Zq9", 12)
	e.newPass(client.PassCreateRequest{Name: hostile, Providers: []string{"anthropic"}})
	recs, err := e.c.AuditTail(e.ctx(), 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range recs {
		if r.Type == "pass_issue" {
			name, _ := r.Fields["name"].(string)
			found = found || strings.HasPrefix(name, "[redacted:")
		}
	}
	if !found {
		t.Fatal("pass_issue with a secret-looking name was dropped or not redacted")
	}
	if st := e.status(); st.State != client.StateUnlocked {
		t.Fatalf("state = %s (%s)", st.State, st.TripReason)
	}
	e.assertNoSecrets(hostile)

	big := make([]string, 400)
	for i := range big {
		big[i] = strings.Repeat("x", 1000)
	}
	e.d.auditEvent("usage_note", map[string]any{"blob": big})
	time.Sleep(50 * time.Millisecond)
	if st := e.status(); st.State != client.StateUnlocked {
		t.Fatalf("a rejected non-security record tripped: %s", st.State)
	}
	e.d.auditEvent("request", map[string]any{"blob": big})
	for i := 0; i < 200 && e.d.State() != StateTripped; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if st := e.status(); st.State != client.StateTripped || st.TripReason != TripAudit {
		t.Fatalf("rejected request record: state %s (%s)", st.State, st.TripReason)
	}
}

func TestSanitizeAudit(t *testing.T) {
	in := map[string]any{"a": "sk-proj-" + strings.Repeat("Ab3", 10), "b": []string{"ok", strings.Repeat("y", 3000)},
		"c": map[string]any{"d": []any{"klp_" + strings.Repeat("Q7z", 10)}}, "n": 5}
	out := sanitizeAudit(in).(map[string]any)
	if s := out["a"].(string); !strings.HasPrefix(s, "[redacted:") {
		t.Fatalf("a = %q", s)
	}
	if b := out["b"].([]string); b[0] != "ok" || len(b[1]) > maxAuditString+20 {
		t.Fatalf("b = %v", len(b[1]))
	}
	if d := out["c"].(map[string]any)["d"].([]any); !strings.HasPrefix(d[0].(string), "[redacted:") {
		t.Fatalf("d = %v", d)
	}
	if out["n"] != 5 {
		t.Fatal("non-strings changed")
	}
}

// Finding 7: an unpriced model reserves and is charged at the provider's
// most expensive rates; an unbounded request reserves the per-request limit
// and needs approval, and is refused without a per-request limit.
func TestUnpricedWorstCase(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}})
	body := `{"model":"claude-mystery-9","max_tokens":256,"messages":[{"role":"user","content":"hi"}]}`
	p, _ := provider.Get("anthropic")
	ep, _ := p.Match(http.MethodPost, "/v1/messages")
	info, err := e.d.meter.Inspect(p, ep, "/v1/messages", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	worst, ok := e.d.meter.WorstCaseEstimate("anthropic", info)
	if !ok || worst <= 0 {
		t.Fatalf("worst case = %s %v", worst, ok)
	}
	e.appr.approve.Store(true)
	if r := e.post("anthropic", "/v1/messages", tok, body); r.status != 200 {
		t.Fatalf("unpriced request: %d %s", r.status, r.body)
	}
	rec := lastRequestRecord(t, e)
	if rec["reserved_micros"] != float64(worst) {
		t.Fatalf("reserved %v, want worst case %d", rec["reserved_micros"], worst)
	}
	var u meter.Usage
	u.InputTokens, u.OutputTokens = 12, 34
	want, _ := e.d.meter.WorstCaseCost("anthropic", u)
	if rec["cost_micros"] != float64(want) || rec["estimated"] != true {
		t.Fatalf("charged %v (estimated %v), want %d at maximum rates", rec["cost_micros"], rec["estimated"], want)
	}

	// Unbounded: a server-side tool whose uses are not capped.
	ub := `{"model":"claude-sonnet-4-5","max_tokens":256,"tools":[{"type":"web_search_20250305","name":"web_search"}],"messages":[{"role":"user","content":"hi"}]}`
	if info, _ := e.d.meter.Inspect(p, ep, "/v1/messages", []byte(ub)); info.InputTokensEstimate < meter.UnboundedInputTokens {
		t.Fatalf("fixture is not unbounded: %+v", info)
	}
	e.appr.approve.Store(false)
	calls := e.appr.calls.Load()
	wantReason(t, e.post("anthropic", "/v1/messages", tok, ub), 403, proxy.ReasonApprovalDenied)
	if e.appr.calls.Load() != calls+1 {
		t.Fatal("an unbounded request did not ask for approval")
	}
	e.appr.approve.Store(true)
	if r := e.post("anthropic", "/v1/messages", tok, ub); r.status != 200 {
		t.Fatalf("approved unbounded request: %d %s", r.status, r.body)
	}
	if rec := lastRequestRecord(t, e); rec["reserved_micros"] != float64(2*money.Dollar) {
		t.Fatalf("unbounded reservation = %v, want the $2 request limit", rec["reserved_micros"])
	}

	n := newEnv(t, func(c *config.Config) { c.Limits.Global.Request = nil })
	n.unlock()
	n.addKeys()
	ntok := n.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}})
	n.appr.approve.Store(true)
	wantReason(t, n.post("anthropic", "/v1/messages", ntok, ub), 403, proxy.ReasonBudgetExceeded)
}

func lastRequestRecord(t *testing.T, e *env) map[string]any {
	t.Helper()
	recs, err := e.c.AuditTail(e.ctx(), 50)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(recs) - 1; i >= 0; i-- {
		if recs[i].Type == "request" {
			raw, _ := json.Marshal(recs[i].Fields)
			var m map[string]any
			json.Unmarshal(raw, &m)
			return m
		}
	}
	t.Fatal("no request record")
	return nil
}

// Finding 8: only the very first key skips the step-up; a pass keeps the
// key it was issued with; the active key changes only by `keys use`.
func TestKeyAddStepUpAndPassKeyMapping(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.appr.strictSetup.Store(true)
	if _, err := e.c.AddKey(e.ctx(), "anthropic", "main", []byte(anthropicKey)); err != nil {
		t.Fatalf("first key: %v", err)
	}
	second := "sk-ant-api03-SECOND-ANTHROPIC-KEY-9876543210fedcba"
	if _, err := e.c.AddKey(e.ctx(), "anthropic", "other", []byte(second)); !isAPI(err, 403, client.CodeStepUpDenied) {
		t.Fatalf("second key without approval: %v", err)
	}
	e.appr.strictSetup.Store(false)
	old := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}})
	var k2 client.KeyInfo
	if err := e.withOwner(func(ctx context.Context) error {
		var err error
		k2, err = e.c.AddKey(ctx, "anthropic", "other", []byte(second))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if k2.Active {
		t.Fatal("a newly added key became active without `keys use`")
	}
	// Neither existing nor new passes are redirected to the new key.
	wantReason(t, e.anthropic(old), 200, "")
	fresh := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}})
	wantReason(t, e.anthropic(fresh), 200, "")
	// `keys use` is a step-up.
	e.appr.strictSetup.Store(true)
	if _, err := e.c.UseKey(e.ctx(), k2.ID); !isAPI(err, 403, client.CodeStepUpDenied) {
		t.Fatalf("keys use without approval: %v", err)
	}
	e.appr.approve.Store(true)
	if _, err := e.c.UseKey(e.ctx(), k2.ID); err != nil {
		t.Fatal(err)
	}
	e.appr.strictSetup.Store(false)
	// New passes use the chosen key (the fake upstream rejects it); the
	// earlier passes keep theirs.
	after := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}})
	if r := e.anthropic(after); r.status != 401 {
		t.Fatalf("pass after keys use: %d", r.status)
	}
	wantReason(t, e.anthropic(old), 200, "")
	wantReason(t, e.anthropic(fresh), 200, "")
	keys, _ := e.c.Keys(e.ctx())
	for _, k := range keys {
		if k.Active != (k.ID == k2.ID) {
			t.Fatalf("active flags: %+v", keys)
		}
	}
	// The mapping survives a restart (it lives in the vault).
	e.restart()
	e.unlock()
	wantReason(t, e.anthropic(old), 200, "")
	if r := e.anthropic(after); r.status != 401 {
		t.Fatalf("after restart: %d", r.status)
	}
	e.assertNoSecrets(second)
}

// Finding 9: a request still in flight at shutdown is charged before the
// ledger closes, so its spend survives the restart.
func TestShutdownSettlesInFlight(t *testing.T) {
	old := ShutdownGrace
	ShutdownGrace = 100 * time.Millisecond
	t.Cleanup(func() { ShutdownGrace = old })
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}})
	reserved := e.estimate("anthropic", "/v1/messages", anthropicReq)
	go func() {
		req, _ := http.NewRequest(http.MethodPost, "http://"+e.d.ProxyAddr()+"/anthropic/v1/messages", strings.NewReader(anthropicReq))
		req.Header.Set("X-Api-Key", tok)
		req.Header.Set("Anthropic-Version", "2023-06-01")
		req.Header.Set("X-Test-Hold", "1")
		if resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	select {
	case <-e.up.held:
	case <-time.After(10 * time.Second):
		t.Fatal("held request never reached upstream")
	}
	e.stop()
	close(e.up.relea)
	e.start()
	e.unlock() // fatals unless Unlocked: the ledger verifies
	if got, _ := limitSettled(e.status(), "global", "month"); got != reserved {
		t.Fatalf("month spend after restart = %s, want the reserved %s", got, reserved)
	}
}

// Finding 10: an over-limit approval admits exactly the request shown and
// raises no limit; a grant applies only to the requesting pass, within caps.
func TestOverLimitApprovalAdmitsOnlyThatRequest(t *testing.T) {
	var limit money.Micros
	e := newEnv(t, func(c *config.Config) { c.Limits.OnExceed = "approve" })
	limit = e.estimate("anthropic", "/v1/messages", anthropicReq) / 2
	e.cfg.Limits.Global.Request = &config.Amount{Micros: limit}
	e.approver = blockingApprover{}
	e.restart()
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}})
	tok2 := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}})
	send := func(tk string) chan result {
		ch := make(chan result, 1)
		go func() { ch <- e.anthropic(tk) }()
		return ch
	}
	a := send(tok)
	ap := e.waitPendingN("over_limit", 1)[0]
	if ap.Scope != "global" || ap.Window != "request" || ap.Limit != limit || ap.GrantMax != 5*limit || ap.GrantMaxFor != 24*time.Hour ||
		!strings.Contains(ap.Prompt, "this one request only") {
		t.Fatalf("over-limit approval = %+v", ap)
	}
	if err := e.c.Decide(e.ctx(), ap.ID, client.DecideRequest{Approved: true, Secret: ownerSecret()}); err != nil {
		t.Fatal(err)
	}
	if r := <-a; r.status != 200 {
		t.Fatalf("approved request: %d %s", r.status, r.body)
	}
	// The limit was not raised: the next request asks again; two at once
	// get two separate approvals.
	b, c := send(tok), send(tok)
	ps := e.waitPendingN("over_limit", 2)
	if ps[0].ID == ps[1].ID || ps[0].Waiters != 1 {
		t.Fatalf("over-limit approvals coalesced: %+v", ps)
	}
	// A grant above the cap is refused.
	tooBig := &client.ApprovalGrant{Amount: 5*limit + 1, For: time.Hour}
	if err := e.c.Decide(e.ctx(), ps[0].ID, client.DecideRequest{Approved: true, Grant: tooBig, Secret: ownerSecret()}); !isAPI(err, 400, client.CodeBadRequest) {
		t.Fatalf("grant above cap: %v", err)
	}
	g := &client.ApprovalGrant{Amount: 5 * limit, For: time.Hour}
	if err := e.c.Decide(e.ctx(), ps[0].ID, client.DecideRequest{Approved: true, Grant: g, Secret: ownerSecret()}); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Decide(e.ctx(), ps[1].ID, client.DecideRequest{Approved: false}); err != nil {
		t.Fatal(err)
	}
	got := []int{(<-b).status, (<-c).status}
	if !(got[0] == 200 && got[1] == 403 || got[0] == 403 && got[1] == 200) {
		t.Fatalf("statuses = %v", got)
	}
	// The grant covers later requests of this pass without approval ...
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatalf("within the grant: %d %s", r.status, r.body)
	}
	if n := len(e.pendingOf("over_limit")); n != 0 {
		t.Fatalf("pending = %d", n)
	}
	// ... but not another pass.
	d := send(tok2)
	other := e.waitPendingN("over_limit", 1)[0]
	if other.Pass == "" || e.c.Decide(e.ctx(), other.ID, client.DecideRequest{Approved: false}) != nil {
		t.Fatalf("other pass approval: %+v", other)
	}
	wantReason(t, <-d, 403, proxy.ReasonApprovalDenied)
}

// Finding 11: a tampered audit log trips audit_integrity after unlock; an
// edited config trips config_changed until resume accepts it.
func TestAuditTamperAndConfigChangeTrip(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}})
	wantReason(t, e.anthropic(tok), 200, "")
	e.stop()
	files, _ := filepath.Glob(filepath.Join(e.dir, AuditDir, "*.jsonl"))
	if len(files) == 0 {
		t.Fatal("no audit files")
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"provider":"anthropic"`, `"provider":"openai"`, 1)
	if tampered == string(raw) {
		t.Fatal("nothing to tamper with")
	}
	if err := os.WriteFile(files[0], []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	e.start()
	e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if st := e.status(); st.State != client.StateTripped || st.TripReason != TripAuditIntegrity {
		t.Fatalf("tampered audit: %s (%s)", st.State, st.TripReason)
	}
	wantReason(t, e.anthropic(tok), 423, proxy.ReasonTripped)
	e.appr.approve.Store(true)
	if st, err := e.c.Resume(e.ctx()); err != nil || st.State != client.StateUnlocked {
		t.Fatalf("resume: %v", err)
	}
	if rej, _ := filepath.Glob(filepath.Join(e.dir, AuditDir, "rejected-*")); len(rej) != 1 {
		t.Fatalf("rejected log not archived: %v", rej)
	}
	e.restart()
	e.unlock() // the new chain verifies

	// Config change.
	e.stop()
	e.cfg.Limits.Global.Day = &config.Amount{Micros: 500 * money.Dollar}
	e.start()
	e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	st := e.status()
	if st.State != client.StateTripped || st.TripReason != TripConfig || len(st.ConfigChanges) != 1 ||
		!strings.Contains(st.ConfigChanges[0], "limits.global.day") || !strings.Contains(st.ConfigChanges[0], "$500") {
		t.Fatalf("config change: %s (%s) %v", st.State, st.TripReason, st.ConfigChanges)
	}
	e.appr.approve.Store(false)
	if _, err := e.c.Resume(e.ctx()); !isAPI(err, 403, client.CodeStepUpDenied) {
		t.Fatalf("resume without approval: %v", err)
	}
	e.appr.approve.Store(true)
	if st, err := e.c.Resume(e.ctx()); err != nil || st.State != client.StateUnlocked {
		t.Fatalf("accepting the config: %v", err)
	}
	e.restart()
	e.unlock() // accepted: no trip
}
