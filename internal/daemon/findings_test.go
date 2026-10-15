package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/approval"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/proxy"
)

// Regression tests for security findings A–K (each replays the attack).

func createPassResp(t *testing.T, e *env, req client.PassCreateRequest) client.PassCreateResponse {
	t.Helper()
	var r client.PassCreateResponse
	if err := e.withOwner(func(ctx context.Context) error {
		var err error
		r, err = e.c.CreatePass(ctx, req)
		return err
	}); err != nil {
		t.Fatalf("create pass: %v", err)
	}
	return r
}

func auditHas(t *testing.T, e *env, typ string, match func(map[string]any) bool) bool {
	t.Helper()
	recs, err := e.c.AuditTail(e.ctx(), 500)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Type == typ && (match == nil || match(r.Fields)) {
			return true
		}
	}
	return false
}

// A: a process whose parent chain to the run pass's bound process is broken
// (here: a live process that is not a descendant) stays confined, and may
// use the run pass, while it is in the pass's job; a pass whose process
// cannot be confined is not issued; restarting the daemon ends run passes.
func TestFindingA_JobConfinement(t *testing.T) {
	requireProcessBinding(t)
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	r := createPassResp(t, e, client.PassCreateRequest{Name: "run", Kind: "run", Providers: []string{"anthropic"}, BindPID: os.Getpid()})
	if len(e.jobs.confined) != 1 || e.jobs.confined[0] != r.Pass.ID {
		t.Fatalf("run pass not confined in a job: %v", e.jobs.confined)
	}
	orphan := os.Getppid() // alive, and not a descendant of the bound process
	e.setAdminPID(orphan)
	if _, err := e.c.Passes(e.ctx()); err != nil {
		t.Fatalf("outsider confined before joining the job: %v", err)
	}
	e.peerPID.Store(int64(orphan))
	wantReason(t, e.anthropic(r.Token), 401, proxy.ReasonPassInvalid)

	// The orphan is in the job: confined, and its run pass works for it.
	e.jobs.add(r.Pass.ID, orphan)
	e.c.Close()
	if _, err := e.c.Passes(e.ctx()); !isAPI(err, 403, client.CodeConfined) {
		t.Fatalf("orphaned job member not confined: %v", err)
	}
	if res := e.anthropic(r.Token); res.status != 200 {
		t.Fatalf("job member refused its run pass: %d %s", res.status, res.body)
	}
	// The orphan may revoke its own pass (it is in the pass's job); the
	// pass ends, but the job lives on while the orphan does.
	if err := e.c.RevokePass(e.ctx(), r.Pass.ID); err != nil {
		t.Fatalf("job member revoking its own pass: %v", err)
	}
	e.d.sweepRunPasses()
	if _, err := e.c.Passes(e.ctx()); !isAPI(err, 403, client.CodeConfined) {
		t.Fatalf("orphan unconfined after its pass ended: %v", err)
	}
	e.jobs.kill(orphan)
	e.d.sweepRunPasses()
	if _, err := e.c.Passes(e.ctx()); err != nil {
		t.Fatalf("after the job was released: %v", err)
	}
	e.peerPID.Store(int64(os.Getpid()))

	// Confinement failure: no pass.
	e.setAdminPID(os.Getppid())
	e.jobs.mu.Lock()
	e.jobs.fail = errors.New("access denied")
	e.jobs.mu.Unlock()
	err := e.withOwner(func(ctx context.Context) error {
		_, err := e.c.CreatePass(ctx, client.PassCreateRequest{Name: "run2", Kind: "run", Providers: []string{"anthropic"}, BindPID: os.Getpid()})
		return err
	})
	if !isAPI(err, 409, client.CodeConflict) {
		t.Fatalf("unconfinable run pass: %v", err)
	}
	for _, p := range e.d.passes.List() {
		if p.Name == "run2" {
			t.Fatal("a run pass was issued although its process could not be confined")
		}
	}
	e.jobs.mu.Lock()
	e.jobs.fail = nil
	e.jobs.mu.Unlock()

	// A restarted daemon has no job for older run passes: they end.
	r3 := createPassResp(t, e, client.PassCreateRequest{Name: "run3", Kind: "run", Providers: []string{"anthropic"}, BindPID: os.Getpid()})
	e.restart()
	if p, ok := e.d.passes.Get(r3.Pass.ID); !ok || !p.Revoked {
		t.Fatal("run pass survived a daemon restart without a job")
	}
	e.unlock()
	if !auditHas(t, e, "pass_revoke", func(f map[string]any) bool { return f["reason"] == "daemon_restart" }) {
		t.Fatal("restart revocation not audited")
	}
}

// B: editing passes.json (un-revoking a pass) while keyleash is stopped
// trips pass_store at unlock; passes are refused; resume shows the change,
// revokes the changed pass and re-baselines.
func TestFindingB_PassStoreTamper(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	r := createPassResp(t, e, client.PassCreateRequest{Name: "victim", Providers: []string{"anthropic"}})
	keep := e.newPass(client.PassCreateRequest{Name: "keep", Providers: []string{"anthropic"}})
	if err := e.c.RevokePass(e.ctx(), r.Pass.ID); err != nil {
		t.Fatal(err)
	}
	e.stop()

	path := filepath.Join(e.dir, PassesFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	if err := json.Unmarshal(doc["body"], &body); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, pr := range body["passes"].([]any) {
		m := pr.(map[string]any)
		if m["id"] == r.Pass.ID {
			delete(m, "revoked")
			delete(m, "revoked_at")
			found = true
		}
	}
	if !found {
		t.Fatalf("pass not in body: %s", raw)
	}
	nb, _ := json.Marshal(body)
	doc["body"] = nb
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	e.start()
	st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != client.StateTripped || st.TripReason != TripPassStore {
		t.Fatalf("tampered passes.json: state %s %s", st.State, st.TripReason)
	}
	if !strings.Contains(strings.Join(st.PassStoreChanges, "\n"), "changed "+r.Pass.ID) {
		t.Fatalf("changes not reported: %v", st.PassStoreChanges)
	}
	wantReason(t, e.anthropic(r.Token), 423, proxy.ReasonTripped)

	e.appr.approve.Store(true)
	if _, err := e.c.Resume(e.ctx()); err != nil {
		t.Fatalf("resume: %v", err)
	}
	reqs := e.appr.requests()
	if last := reqs[len(reqs)-1]; !strings.Contains(last.Detail, "1 changed") {
		t.Fatalf("resume prompt does not show the pass store change: %q", last.Detail)
	}
	wantReason(t, e.anthropic(r.Token), 401, proxy.ReasonPassInvalid)
	if res := e.anthropic(keep); res.status != 200 {
		t.Fatalf("untouched pass refused after resume: %d", res.status)
	}
	// Re-baselined: the next unlock is clean.
	e.restart()
	e.unlock()
}

// C: at most one secret verification runs at a time (others get 429), it
// never blocks lock, and the lockout is per caller plus a global back-off.
func TestFindingC_SecretRateLimit(t *testing.T) {
	e := newEnv(t, nil)
	e.approver = blockingApprover{}
	e.restart()
	e.unlock()
	go func() { _, _ = e.c.Away(e.ctx(), client.AwayRequest{Budget: money.Dollar, For: time.Hour}) }()
	id := e.waitPending("away_grant")

	// A verification in flight (the slow KDF): a parallel attempt is
	// refused at once, and lock is not delayed.
	e.d.secretMu.Lock()
	e.d.secretInFlight = true
	e.d.secretMu.Unlock()
	if err := e.c.Decide(e.ctx(), id, client.DecideRequest{Approved: true, Secret: ownerSecret()}); !isAPI(err, 429, client.CodeRateLimited) {
		t.Fatalf("parallel secret attempt: %v", err)
	}
	e.d.secretMu.Lock()
	e.d.secretInFlight = false
	e.d.secretMu.Unlock()

	// Per caller: A is locked out after secretFreeTries, B is not; across
	// callers the global back-off applies (new processes cannot reset it).
	wrong := func(pid int) error {
		e.setAdminPID(pid)
		return e.c.Decide(e.ctx(), id, client.DecideRequest{Approved: true, Secret: []byte("guess")})
	}
	const a, b, c = 1_000_001, 1_000_002, 1_000_003
	for i := 0; i < secretFreeTries; i++ {
		if err := wrong(a); !isAPI(err, 401, client.CodeWrongSecret) {
			t.Fatalf("A wrong secret %d: %v", i, err)
		}
	}
	if err := wrong(a); !isAPI(err, 429, client.CodeRateLimited) {
		t.Fatalf("caller A after lockout: %v", err)
	}
	for i := secretFreeTries; i < secretGlobalFree-1; i++ {
		if err := wrong(b); !isAPI(err, 401, client.CodeWrongSecret) {
			t.Fatalf("caller B try %d: %v", i, err)
		}
	}
	if err := wrong(c); !isAPI(err, 401, client.CodeWrongSecret) {
		t.Fatalf("caller C first try: %v", err)
	}
	if err := wrong(c); !isAPI(err, 429, client.CodeRateLimited) {
		t.Fatalf("caller C after the global limit: %v", err)
	}
	e.clk.Advance(secretGlobalBackoff + time.Second)
	if err := wrong(c); !isAPI(err, 401, client.CodeWrongSecret) {
		t.Fatalf("caller C after the global back-off: %v", err)
	}
	if err := wrong(a); !isAPI(err, 429, client.CodeRateLimited) {
		t.Fatalf("caller A still locked out: %v", err)
	}
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
}

// D: duplicate and oversized lists are refused before any prompt; a step-up
// whose risk text would be truncated is refused; prompts name the
// requesting process and PID; a config-change resume summarises the keys.
func TestFindingD_ApprovalPrompts(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	e.appr.strictSetup.Store(true)
	before := len(e.appr.requests())
	for name, req := range map[string]client.PassCreateRequest{
		"dup provider": {Name: "x", Providers: []string{"anthropic", "Anthropic"}},
		"star+other":   {Name: "x", Providers: []string{"*", "openai"}},
		"dup model":    {Name: "x", Providers: []string{"anthropic"}, Models: []string{"claude-*", "claude-*"}},
		"unknown":      {Name: "x", Providers: []string{"anthropic", "nope"}},
		"too many":     {Name: "x", Providers: []string{"anthropic"}, Models: make([]string, 33)},
	} {
		if req.Models != nil && req.Models[0] == "" {
			for i := range req.Models {
				req.Models[i] = "m" + strings.Repeat("x", i%5) + string(rune('a'+i%26))
			}
		}
		if _, err := e.c.CreatePass(e.ctx(), req); !isAPI(err, 400, client.CodeBadRequest) {
			t.Errorf("%s: %v", name, err)
		}
	}
	var lim []client.PassLimit
	for i := 0; i < 30; i++ {
		lim = append(lim, client.PassLimit{Window: "day", Amount: money.Micros(i+1) * money.Dollar})
	}
	if _, err := e.c.CreatePass(e.ctx(), client.PassCreateRequest{Name: "x", Providers: []string{"anthropic"}, Limits: lim}); !isAPI(err, 400, client.CodeBadRequest) {
		t.Fatalf("truncated risk text: %v", err)
	}
	if n := len(e.appr.requests()); n != before {
		t.Fatalf("%d prompts shown for refused requests", n-before)
	}
	e.appr.approve.Store(true)
	if _, err := e.c.CreatePass(e.ctx(), client.PassCreateRequest{Name: "ok", Providers: []string{"anthropic"}}); err != nil {
		t.Fatal(err)
	}
	reqs := e.appr.requests()
	last := reqs[len(reqs)-1]
	if last.Requester != os.Getppid() || last.RequesterName == "" || last.RequesterName == "unknown process" {
		t.Fatalf("requester not named: %d %q", last.Requester, last.RequesterName)
	}
	if p := approval.PromptText(last); !strings.Contains(p, "pid ") || !strings.Contains(p, last.RequesterName) {
		t.Fatalf("prompt does not name the requester: %q", p)
	}

	det, note := resumeSummary(TripConfig, []string{"logging.level: info -> debug", "approval.method: hello -> console",
		"limits.global.day: $20 -> $2000", "presence.max_lease: 8h -> 72h"}, nil)
	if !strings.Contains(det, "4 config keys changed: approval.method, limits.global.day") {
		t.Fatalf("resume summary: %q / %q", det, note)
	}
}

// E is covered in internal/meter (TestUnpricedModelToolFeesChargeReservation).

// F: changing the pricing override file's bytes (same path, same
// config.toml) trips config_changed.
func TestFindingF_PricingOverrideHashed(t *testing.T) {
	over := filepath.Join(t.TempDir(), "pricing.json")
	write := func(price string) {
		if err := os.WriteFile(over, []byte(`{"version":1,"providers":{"anthropic":{"models":{"claude-sonnet-4-5":{"input":"`+price+`","output":"$15"}}}}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("$3")
	e := newEnv(t, func(c *config.Config) { c.Pricing.Override = over })
	e.unlock()
	e.restart()
	e.unlock() // unchanged: clean
	write("$0.000001")
	e.restart()
	st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if st.State != client.StateTripped || st.TripReason != TripConfig {
		t.Fatalf("override edit: %s %s", st.State, st.TripReason)
	}
	if !strings.Contains(strings.Join(st.ConfigChanges, "\n"), "pricing_override_file.sha256") {
		t.Fatalf("changes: %v", st.ConfigChanges)
	}
}

// G: a config.toml that switches approval.method to console cannot approve
// its own acceptance: the resume waits for the vault secret (the accepted
// method was passphrase) and the console is never read.
func TestFindingG_ResumeUsesAcceptedMethod(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Approval.Method = "passphrase" })
	e.noApprover = true
	console := &countingReader{r: strings.NewReader("y\ny\ny\n")}
	e.consoleIn, e.consoleOut = console, &strings.Builder{}
	e.restart()
	e.unlock()
	e.stop()
	e.cfg.Approval.Method = "console"
	e.start()
	st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if st.TripReason != TripConfig || st.ApprovalMethod != "passphrase" {
		t.Fatalf("after the edit: %s %s method %s", st.State, st.TripReason, st.ApprovalMethod)
	}
	done := make(chan error, 1)
	go func() { _, err := e.c.Resume(e.ctx()); done <- err }()
	id := e.waitPending("resume")
	list, _ := e.c.Approvals(e.ctx())
	for _, ap := range list {
		if ap.ID == id && ap.Method != "passphrase" {
			t.Fatalf("resume held by %q", ap.Method)
		}
	}
	select {
	case err := <-done:
		t.Fatalf("resume decided without the secret: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if console.n > 0 {
		t.Fatal("the console was read for a config-change resume")
	}
	if err := e.c.Decide(e.ctx(), id, client.DecideRequest{Approved: true, Secret: ownerSecret()}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if st := e.status(); st.State != client.StateUnlocked || st.ApprovalMethod != "console" {
		t.Fatalf("after accepting: %s %s", st.State, st.ApprovalMethod)
	}
	vs := e.d.vaultStateSnapshot()
	if vs == nil || vs.ApprovalMethod != "console" {
		t.Fatal("accepted method not recorded")
	}
}

type countingReader struct {
	r interface{ Read([]byte) (int, error) }
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// H: lock and panic work from a confined caller.
func TestFindingH_LockPanicFromConfined(t *testing.T) {
	requireProcessBinding(t)
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	createPassResp(t, e, client.PassCreateRequest{Name: "run", Kind: "run", Providers: []string{"anthropic"}, BindPID: os.Getpid()})
	e.setAdminPID(os.Getpid())
	if _, err := e.c.Away(e.ctx(), client.AwayRequest{Budget: money.Dollar, For: time.Hour}); !isAPI(err, 403, client.CodeConfined) {
		t.Fatalf("confined away: %v", err)
	}
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatalf("confined lock: %v", err)
	}
	e.setAdminPID(os.Getppid())
	e.unlock()
	e.setAdminPID(os.Getpid())
	if _, err := e.c.Panic(e.ctx(), false); err != nil {
		t.Fatalf("confined panic: %v", err)
	}
	if st := e.status(); st.State != client.StateLocked {
		t.Fatalf("state after panic: %s", st.State)
	}
}

// I: a pass is not issued when its audit record cannot be written.
func TestFindingI_PassIssueAuditedFirst(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	e.d.auditMu.Lock()
	e.d.audit.Close()
	e.d.auditMu.Unlock()
	err := e.withOwner(func(ctx context.Context) error {
		_, err := e.c.CreatePass(ctx, client.PassCreateRequest{Name: "unaudited", Providers: []string{"anthropic"}})
		return err
	})
	if err == nil {
		t.Fatal("pass issued without an audit record")
	}
	for _, p := range e.d.passes.List() {
		if p.Name == "unaudited" {
			t.Fatal("unaudited pass kept in the store")
		}
	}
}

// J: there is no separate rollback-arming endpoint; accepting a rollback is
// a flag on the unlock request, reported with the seq regression and
// audited.
func TestFindingJ_AcceptRollbackOnUnlock(t *testing.T) {
	e := newEnv(t, nil)
	rr := httptest.NewRecorder()
	e.d.adminHandler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/vault/accept-rollback", nil))
	if rr.Code != http.StatusNotFound && rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("arming endpoint still exists: %d", rr.Code)
	}

	e.unlock()
	e.stop()
	vpath := filepath.Join(e.dir, VaultFile)
	old, err := os.ReadFile(vpath)
	if err != nil {
		t.Fatal(err)
	}
	e.start()
	e.unlock()
	e.addKeys() // vault writes move the recorded seq forward
	e.stop()
	if err := os.WriteFile(vpath, old, 0o600); err != nil {
		t.Fatal(err)
	}
	e.start()
	_, err = e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if !isAPI(err, 409, client.CodeRollback) || !strings.Contains(err.Error(), "write") {
		t.Fatalf("rolled-back vault: %v", err)
	}
	st := e.status()
	if !st.Vault.RollbackDetected || st.Vault.RollbackFileSeq >= st.Vault.RollbackRecordedSeq {
		t.Fatalf("rollback seqs not reported: %+v", st.Vault)
	}
	// A failed or plain unlock does not stay armed.
	if _, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase); !isAPI(err, 409, client.CodeRollback) {
		t.Fatalf("second plain unlock: %v", err)
	}
	st, err = e.c.UnlockWith(e.ctx(), client.UnlockRequest{Method: client.MethodPassphrase, AcceptRollback: true}, testPassphrase)
	if err != nil {
		t.Fatalf("unlock --accept-rollback: %v", err)
	}
	if !st.Vault.RollbackAccepted || st.Vault.RollbackFileSeq == 0 || st.Vault.RollbackRecordedSeq <= st.Vault.RollbackFileSeq {
		t.Fatalf("accepted rollback not reported: %+v", st.Vault)
	}
	if !auditHas(t, e, "accept_rollback", func(f map[string]any) bool { return f["recorded_seq"] != nil && f["file_seq"] != nil }) {
		t.Fatal("accepted rollback not audited")
	}
}

// K: away grants are capped by limits.away.max_grant; the first-key
// exemption does not come back after every key is removed.
func TestFindingK_Residuals(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.appr.approve.Store(true)
	over := e.cfg.Limits.Away.MaxGrant.Micros + money.Cent
	if _, err := e.c.Away(e.ctx(), client.AwayRequest{Budget: over, For: time.Hour}); !isAPI(err, 400, client.CodeBadRequest) {
		t.Fatalf("grant above max_grant: %v", err)
	}
	e.appr.approve.Store(false)
	e.appr.strictSetup.Store(true)
	k, err := e.c.AddKey(e.ctx(), "anthropic", "main", []byte(anthropicKey))
	if err != nil {
		t.Fatalf("first key: %v", err)
	}
	e.appr.approve.Store(true)
	if err := e.c.RemoveKey(e.ctx(), k.ID); err != nil {
		t.Fatal(err)
	}
	e.appr.approve.Store(false)
	if _, err := e.c.AddKey(e.ctx(), "anthropic", "again", []byte(anthropicKey)); !isAPI(err, 403, client.CodeStepUpDenied) {
		t.Fatalf("key added without a step-up after removing every key: %v", err)
	}
	e.restart() // persisted in the vault
	e.unlock()
	if _, err := e.c.AddKey(e.ctx(), "anthropic", "again", []byte(anthropicKey)); !isAPI(err, 403, client.CodeStepUpDenied) {
		t.Fatalf("after restart: %v", err)
	}
}
