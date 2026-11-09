package daemon

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/approval"
	"github.com/h-a-forster/keyleash/internal/audit"
	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/proxy"
	"github.com/h-a-forster/keyleash/internal/vault"
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
	orphan := outsiderPID // not a descendant of the bound process
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
	e.setAdminPID(outsiderPID)
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
	if last.Requester != outsiderPID || last.RequesterName == "" || last.RequesterName == "unknown process" {
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
	e.setAdminPID(outsiderPID)
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
	// The warning belongs to that unlock, not to the rest of the process.
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if st, err = e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase); err != nil || st.Vault.RollbackAccepted {
		t.Fatalf("a later unlock: %v, accepted reported: %v", err, st.Vault.RollbackAccepted)
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

// Regression tests for the state-machine audit of 2026-11-09 (D1...).

// slowBody sends a request's headers with a Content-Length and no body: the
// proxy has authenticated it and waits for the body. send delivers the body
// and returns the response.
func slowBody(t *testing.T, e *env, tok string) (send func() *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", e.d.ProxyAddr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	hdr := "POST /anthropic/v1/messages HTTP/1.1\r\nHost: " + e.d.ProxyAddr() + "\r\nX-Api-Key: " + tok +
		"\r\nAnthropic-Version: 2023-06-01\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(anthropicReq)) + "\r\n\r\n"
	if _, err := conn.Write([]byte(hdr)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // Authenticate has run; the handler waits for the body
	return func() *http.Response {
		t.Helper()
		if _, err := conn.Write([]byte(anthropicReq)); err != nil {
			t.Fatal(err)
		}
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
}

// stream starts a streaming request that pauses after each of its first steps
// events (see X-Test-Steps) and returns once the headers are back.
func (e *env) stream(t *testing.T, tok string, steps int) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+e.d.ProxyAddr()+"/anthropic/v1/messages", strings.NewReader(anthropicStreamReq))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", tok)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	req.Header.Set("X-Test-Steps", strconv.Itoa(steps))
	resp, err := e.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// D1: a request authenticated while its pass was good is refused at admission
// once the pass is revoked, expired or its bound process is gone.
func TestDeadPassCannotSpendOnHeldRequest(t *testing.T) {
	cases := []struct {
		name   string
		req    client.PassCreateRequest
		kill   func(t *testing.T, e *env)
		reason string
	}{
		{"revoked", client.PassCreateRequest{}, func(t *testing.T, e *env) {
			ps, err := e.c.Passes(e.ctx())
			if err != nil || len(ps) != 1 {
				t.Fatalf("passes %v %v", ps, err)
			}
			if err := e.c.RevokePass(e.ctx(), ps[0].ID); err != nil {
				t.Fatal(err)
			}
		}, proxy.ReasonPassInvalid},
		{"expired", client.PassCreateRequest{TTL: time.Hour}, func(t *testing.T, e *env) {
			e.clk.Advance(2 * time.Hour)
		}, proxy.ReasonPassExpired},
		{"bound process gone", client.PassCreateRequest{BindPID: os.Getpid()}, func(t *testing.T, e *env) {
			e.treeGone.Store(true)
		}, proxy.ReasonPassInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.req.BindPID != 0 {
				requireProcessBinding(t)
			}
			e := newEnv(t, nil)
			e.unlock()
			e.addKeys()
			tok := e.newPass(tc.req)
			hits := e.up.hits.Load()
			send := slowBody(t, e, tok)
			tc.kill(t, e)
			resp := send()
			if resp.StatusCode != 401 || resp.Header.Get(proxy.ReasonHeader) != tc.reason {
				t.Fatalf("got %d %q, want 401 %q", resp.StatusCode, resp.Header.Get(proxy.ReasonHeader), tc.reason)
			}
			if e.up.hits.Load() != hits {
				t.Fatal("the request reached upstream")
			}
		})
	}
}

// D1: a request waiting on an approval ends when its pass is revoked.
func TestRevokeEndsRequestWaitingForApproval(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.OnExceed = "approve" })
	e.approver = blockingApprover{}
	e.restart()
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{Limits: []client.PassLimit{{Window: "day", Amount: 1}}})
	done := make(chan result, 1)
	go func() { done <- e.anthropic(tok) }()
	e.waitPending("over_limit")
	ps, err := e.c.Passes(e.ctx())
	if err != nil || len(ps) != 1 {
		t.Fatalf("passes %v %v", ps, err)
	}
	if err := e.c.RevokePass(e.ctx(), ps[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		wantReason(t, r, 401, proxy.ReasonPassInvalid)
	case <-time.After(e.cfg.Approval.Timeout.Duration / 2):
		t.Fatal("the request kept waiting after its pass was revoked")
	}
}

// D2: lock, panic and revoke end running requests: one waiting for upstream's
// answer gets the refusal, one mid-stream has its connection aborted so the
// client cannot take the truncated body for a complete one.
func TestStopEndsRunningRequests(t *testing.T) {
	stops := []struct {
		name   string
		status int
		reason string
		stop   func(t *testing.T, e *env)
	}{
		{"lock", 423, proxy.ReasonLocked, func(t *testing.T, e *env) {
			if _, err := e.c.Lock(e.ctx()); err != nil {
				t.Fatal(err)
			}
		}},
		{"panic", 423, proxy.ReasonLocked, func(t *testing.T, e *env) {
			if _, err := e.c.Panic(e.ctx(), false); err != nil {
				t.Fatal(err)
			}
		}},
		{"revoke", 401, proxy.ReasonPassInvalid, func(t *testing.T, e *env) {
			ps, err := e.c.Passes(e.ctx())
			if err != nil || len(ps) != 1 {
				t.Fatalf("passes %v %v", ps, err)
			}
			if err := e.c.RevokePass(e.ctx(), ps[0].ID); err != nil {
				t.Fatal(err)
			}
		}},
	}
	waitHeld := func(t *testing.T, e *env) {
		t.Helper()
		select {
		case <-e.up.held:
		case <-time.After(10 * time.Second):
			t.Fatal("upstream did not get the request")
		}
	}
	for _, tc := range stops {
		t.Run(tc.name+" before the response", func(t *testing.T) {
			e := newEnv(t, nil)
			e.unlock()
			e.addKeys()
			tok := e.newPass(client.PassCreateRequest{})
			done := make(chan result, 1)
			go func() { done <- e.anthropic(tok, "X-Test-Hold", "1") }()
			waitHeld(t, e)
			tc.stop(t, e)
			select {
			case r := <-done:
				wantReason(t, r, tc.status, tc.reason)
			case <-time.After(3 * time.Second):
				t.Fatal("the request kept running")
			}
		})
		t.Run(tc.name+" mid-stream", func(t *testing.T) {
			e := newEnv(t, nil)
			e.unlock()
			e.addKeys()
			tok := e.newPass(client.PassCreateRequest{})
			resp := e.stream(t, tok, 1)
			defer resp.Body.Close()
			waitHeld(t, e)
			if _, err := resp.Body.Read(make([]byte, 1)); err != nil { // the proxy is relaying
				t.Fatal(err)
			}
			errc := make(chan error, 1)
			go func() {
				_, err := io.ReadAll(resp.Body)
				errc <- err
			}()
			tc.stop(t, e)
			select {
			case err := <-errc:
				if err == nil {
					t.Fatal("the stream ended cleanly; a client would take the truncated body as complete")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("the stream kept running")
			}
		})
	}
}

// resumeGate holds resume prompts until the test opens gate; other prompts
// are approved.
type resumeGate struct {
	kind string // the prompts it holds ("" means resume)
	gate chan struct{}
	seen chan approval.Request
}

func (a *resumeGate) Method() string { return "test" }

func (a *resumeGate) Approve(ctx context.Context, req approval.Request) (bool, error) {
	if kind := cmp.Or(a.kind, "resume"); req.Kind != kind {
		return true, nil
	}
	a.seen <- req
	select {
	case <-a.gate:
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// D3: a resume prompt opened for a velocity trip and answered after lock and
// unlock does not clear the audit_integrity trip it never showed.
func TestStaleResumeApprovalChangesNothing(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Tripwire.Threshold = &config.Amount{Micros: 1} })
	ra := &resumeGate{gate: make(chan struct{}), seen: make(chan approval.Request, 1)}
	e.approver = ra
	e.restart()
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	e.tripBySpend(tok)
	errc := make(chan error, 1)
	go func() { _, err := e.c.Resume(e.ctx()); errc <- err }()
	<-ra.seen
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(e.dir, AuditDir, "audit-*.jsonl"))
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[0], []byte(strings.Replace(string(raw), "daemon_start", "daemon_stXrt", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if err != nil || st.TripReason != TripAuditIntegrity {
		t.Fatalf("second unlock: %v %s %s", err, st.State, st.TripReason)
	}
	close(ra.gate)
	if err := <-errc; err == nil {
		t.Fatal("the stale resume succeeded")
	}
	s := e.status()
	arch, _ := filepath.Glob(filepath.Join(e.dir, AuditDir, "rejected-*"))
	if s.State != client.StateTripped || s.TripReason != TripAuditIntegrity || len(arch) != 0 {
		t.Fatalf("state %s (%s), %d archived logs", s.State, s.TripReason, len(arch))
	}
}

// D16: a lock cannot run between a resume's approval and the end of its work,
// which installs derived keys read before the lock wiped them.
func TestLockWaitsForResumeToFinish(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.d.trip(TripAudit, "test")
	e.appr.approve.Store(true)
	locked := make(chan struct{})
	e.d.testResumeApproved = func() {
		go func() { e.d.lock("test"); close(locked) }()
		select {
		case <-locked:
			t.Error("lock ran in the middle of a resume")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if _, err := e.c.Resume(e.ctx()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Fatal("lock did not run after the resume")
	}
	var aerr error
	e.d.withAudit(func(l *audit.Log) { aerr = l.Anchor() })
	if s := e.status(); s.State != client.StateLocked || !errors.Is(aerr, audit.ErrNoAnchorKey) {
		t.Fatalf("state %s, anchor: %v", s.State, aerr)
	}
}

// D12: with kill_on_daemon_exit off, a run tree can outlive the daemon and is
// unconfined after a restart, so a self-bound run pass always needs a step-up.
func TestRunPassStepUpWhenTreesCanOutliveTheDaemon(t *testing.T) {
	for _, tc := range []struct {
		kill   bool
		stepUp bool
	}{{true, false}, {false, true}} {
		e := newEnv(t, func(c *config.Config) { c.Run.KillOnDaemonExit = tc.kill })
		e.unlock()
		e.addKeys()
		e.appr.strictSetup.Store(true)
		_, err := e.c.CreatePass(e.ctx(), client.PassCreateRequest{Name: "agent", Kind: pass.KindRun,
			Providers: []string{"anthropic"}, BindPID: outsiderPID})
		if tc.stepUp && !isAPI(err, 403, client.CodeStepUpDenied) {
			t.Fatalf("kill_on_daemon_exit=%v: %v, want a step-up", tc.kill, err)
		}
		if !tc.stepUp && err != nil {
			t.Fatalf("kill_on_daemon_exit=%v: %v", tc.kill, err)
		}
	}
}

// D6: a trip with nothing left to re-derive it from does not end with a lock
// and unlock or a restart: only a resume ends it, and then it stays ended.
func TestTripSurvivesLockAndRestartUntilResume(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.d.trip(TripAudit, "a security audit record (x) was rejected")
	calls := e.appr.calls.Load()
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
	unlockState := func(what string) client.Status {
		t.Helper()
		st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		return st
	}
	if st := unlockState("lock"); st.State != client.StateTripped || st.TripReason != TripAudit {
		t.Fatalf("after lock and unlock: %s (%s)", st.State, st.TripReason)
	}
	e.restart()
	if st := unlockState("restart"); st.State != client.StateTripped || st.TripReason != TripAudit {
		t.Fatalf("after restart and unlock: %s (%s)", st.State, st.TripReason)
	}
	if e.appr.calls.Load() != calls {
		t.Fatal("an approval was asked for without a resume")
	}
	e.appr.approve.Store(true)
	if st, err := e.c.Resume(e.ctx()); err != nil || st.State != client.StateUnlocked || st.TripReason != "" {
		t.Fatalf("resume: %v %s (%s)", err, st.State, st.TripReason)
	}
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if st := unlockState("after resume"); st.State != client.StateUnlocked || st.TripReason != "" {
		t.Fatalf("after resume, lock and unlock: %s (%s)", st.State, st.TripReason)
	}
	e.restart()
	e.unlock()
}

// D13: an approved tripwire trip stays approved across a restart inside the
// tripwire window.
func TestResumedTripwireStaysResumedAfterRestart(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Tripwire.Threshold = &config.Amount{Micros: 1} })
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	e.tripBySpend(tok)
	e.appr.approve.Store(true)
	if _, err := e.c.Resume(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(time.Second)
	e.restart()
	e.unlock()
	wantReason(t, e.anthropic(tok), 200, "")
}

// D11: a revocation that could not be saved is reported as a failure, and
// retrying it saves it, so the pass does not come back after a restart.
func TestRevokeReportsFailedSaveAndRetrySticks(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	ps, err := e.c.Passes(e.ctx())
	if err != nil || len(ps) != 1 {
		t.Fatalf("passes %v %v", ps, err)
	}
	store := filepath.Join(e.dir, PassesFile)
	if err := os.Remove(store); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(store, 0o700); err != nil { // the rename onto it fails
		t.Fatal(err)
	}
	if err := e.c.RevokePass(e.ctx(), ps[0].ID); err == nil {
		t.Fatal("a revocation that was not saved was reported as done")
	}
	wantReason(t, e.anthropic(tok), 401, proxy.ReasonPassInvalid) // effective in memory all the same
	if err := os.Remove(store); err != nil {
		t.Fatal(err)
	}
	if err := e.c.RevokePass(e.ctx(), ps[0].ID); err != nil {
		t.Fatal(err)
	}
	e.restart()
	e.unlock()
	wantReason(t, e.anthropic(tok), 401, proxy.ReasonPassInvalid)
}

// D14: the vault records the audit log's head, so a log deleted or cut back
// while the daemon is down trips the next unlock, like the ledger.
func TestAuditLogCutBackTrips(t *testing.T) {
	for name, cut := range map[string]func(t *testing.T, files []string){
		"all files removed": func(t *testing.T, files []string) {
			for _, f := range files {
				if err := os.Remove(f); err != nil {
					t.Fatal(err)
				}
			}
		},
		"tail cut": func(t *testing.T, files []string) {
			last := files[len(files)-1]
			raw, err := os.ReadFile(last)
			if err != nil {
				t.Fatal(err)
			}
			ls := strings.SplitAfter(strings.TrimSuffix(string(raw), "\n"), "\n")
			if err := os.WriteFile(last, []byte(strings.Join(ls[:len(ls)-3], "")), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.unlock()
			e.stop()
			files, _ := filepath.Glob(filepath.Join(e.dir, AuditDir, "audit-*.jsonl"))
			cut(t, files)
			e.start()
			st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
			if err != nil || st.State != client.StateTripped || st.TripReason != TripAuditIntegrity {
				t.Fatalf("%v: %s (%s)", err, st.State, st.TripReason)
			}
			e.appr.approve.Store(true)
			if _, err := e.c.Resume(e.ctx()); err != nil {
				t.Fatal(err)
			}
			e.restart()
			e.unlock() // the new chain's head is recorded
		})
	}
}

// D15: with screen_lock = "lock", unlocking under a locked screen ends Locked,
// not Away, and says so.
func TestUnlockUnderLockedScreenStaysLocked(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Presence.ScreenLock = "lock" })
	e.pres.set(0, true)
	e.d.stepPresence()
	if _, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase); !isAPI(err, 409, client.CodeConflict) {
		t.Fatalf("unlock: %v", err)
	}
	if s := e.status(); s.State != client.StateLocked || s.Vault.Unlocked {
		t.Fatalf("state %s, vault unlocked %v", s.State, s.Vault.Unlocked)
	}
	e.pres.set(0, false)
	e.d.stepPresence()
	e.unlock()
}

// D8: a reservation left by a daemon that died is charged at the next unlock
// (the unlock is the first moment a record can be authenticated).
func TestInFlightOfDeadDaemonChargedAtUnlock(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.stop()
	l, err := budget.Open(budget.Options{Dir: filepath.Join(e.dir, LedgerDir), Clock: e.clk})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Reserve(nil, 777, budget.Meta{RequestID: "req_dead", Model: "claude-sonnet-4-5"}); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	e.start()
	e.unlock() // fatals unless Unlocked: the charge verifies
	if settled, _ := e.d.ledger.Spent(budget.ScopeGlobal, budget.WindowDay); settled != 777 {
		t.Fatalf("settled %d, want 777", settled)
	}
	e.restart()
	e.unlock()
	if settled, _ := e.d.ledger.Spent(budget.ScopeGlobal, budget.WindowDay); settled != 777 {
		t.Fatalf("after a restart: settled %d, want 777", settled)
	}
}

// D9: a stream that keeps delivering past InFlightMaxAge keeps its reservation
// and concurrency slot and is charged what it cost.
func TestLongStreamKeepsItsReservation(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	resp := e.stream(t, tok, 2)
	defer resp.Body.Close()
	buf := make([]byte, 1<<16)
	waitChunk := func() {
		t.Helper()
		select {
		case <-e.up.held:
		case <-time.After(10 * time.Second):
			t.Fatal("no chunk from upstream")
		}
		if _, err := resp.Body.Read(buf); err != nil {
			t.Fatal(err)
		}
	}
	waitChunk()
	e.clk.Advance(InFlightMaxAge * 2 / 3)
	e.up.step <- struct{}{}
	waitChunk()
	e.clk.Advance(InFlightMaxAge * 2 / 3)
	e.d.housekeep()
	if s := e.status(); len(s.InFlight) != 1 {
		t.Fatalf("in flight %d: the running stream's reservation was settled", len(s.InFlight))
	}
	e.up.step <- struct{}{}
	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("rest of the stream (%d bytes): %v", len(rest), err)
	}
	want := e.expectedCost("anthropic", "/v1/messages", anthropicStreamReq, anthropicSSE)
	for range 200 {
		if settled, _ := e.d.ledger.Spent(budget.ScopeGlobal, budget.WindowDay); settled == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	settled, _ := e.d.ledger.Spent(budget.ScopeGlobal, budget.WindowDay)
	t.Fatalf("settled %d, want the metered %d", settled, want)
}

// D10: a request the lock already charged and that then never left records that
// charge in its audit record, not cost 0.
func TestAuditAgreesWithLockChargeOnUnsentRequest(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	res, err := e.d.ledger.Reserve(nil, 500, budget.Meta{RequestID: "req_unsent"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.d.ledger.ExpireInFlight(-1); err != nil {
		t.Fatal(err)
	}
	p, _ := provider.Get("anthropic")
	tk := &ticket{d: e.d, a: proxy.Admission{RequestID: "req_unsent", Provider: p}, res: res}
	tk.Finish(proxy.Outcome{Status: 423})
	if !auditHas(t, e, "request", func(f map[string]any) bool {
		return f["request_id"] == "req_unsent" && f["cost_micros"] == float64(500) && f["estimated"] == true
	}) {
		t.Fatal("the audit record does not show the 500 the ledger charged")
	}
}

func tamperFirstAmount(t *testing.T, dir string) {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(dir, LedgerDir, "ledger-*.jsonl"))
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	re := regexp.MustCompile(`"amount_micros":(\d+)`)
	loc := re.FindSubmatchIndex(raw)
	n, _ := strconv.Atoi(string(raw[loc[2]:loc[3]]))
	out := append(append(append([]byte{}, raw[:loc[2]]...), strconv.Itoa(n-1)...), raw[loc[3]:]...)
	if err := os.WriteFile(files[0], out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// acceptLedger unlocks into an integrity trip, resumes it, and checks the
// acceptance sticks: lock and unlock, restart and unlock, and a request.
func acceptLedger(t *testing.T, e *env, tok string) {
	t.Helper()
	st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if err != nil || st.State != client.StateTripped || st.TripReason != TripIntegrity {
		t.Fatalf("unlock: %v %s (%s)", err, st.State, st.TripReason)
	}
	e.appr.approve.Store(true)
	if st, err = e.c.Resume(e.ctx()); err != nil || st.State != client.StateUnlocked {
		t.Fatalf("resume: %v %s", err, st.State)
	}
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.unlock() // fatals unless Unlocked
	e.restart()
	e.unlock()
	wantReason(t, e.anthropic(tok), 200, "")
	e.restart()
	e.unlock()
}

// D4: accepting a failed ledger check sticks, keeps the spend, keeps the
// original where the owner can read it, and a new change is still caught.
func TestAcceptedLedgerStaysAccepted(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	for range 2 {
		wantReason(t, e.anthropic(tok), 200, "")
	}
	e.stop()
	tamperFirstAmount(t, e.dir)
	e.start()
	before, _ := e.d.ledger.Spent(budget.ScopeGlobal, budget.WindowDay)
	acceptLedger(t, e, tok)
	if after, _ := e.d.ledger.Spent(budget.ScopeGlobal, budget.WindowDay); after <= before {
		t.Fatalf("spend %d, had %d before accepting and one more request", after, before)
	}
	arch, _ := filepath.Glob(filepath.Join(e.dir, LedgerDir, "rejected-*", "ledger-*.jsonl"))
	if len(arch) != 1 {
		t.Fatalf("rejected copies: %v", arch)
	}
	e.stop()
	tamperFirstAmount(t, e.dir)
	e.start()
	if st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase); err != nil || st.TripReason != TripIntegrity {
		t.Fatalf("a new change after accepting: %v %s (%s)", err, st.State, st.TripReason)
	}
}

// D5: a clock stepped back over a month end does not break the chain, and the
// spend written meanwhile still counts after a restart.
func TestClockBackOverMonthEndKeepsChain(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	wantReason(t, e.anthropic(tok), 200, "")
	if err := e.d.ledger.Flush(); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(-15 * 24 * time.Hour) // 11 October to 26 September
	wantReason(t, e.anthropic(tok), 200, "")
	settled, _ := e.d.ledger.Spent(budget.ScopeGlobal, budget.WindowMonth)
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.unlock() // fatals unless Unlocked
	e.restart()
	e.unlock()
	if got, _ := e.d.ledger.Spent(budget.ScopeGlobal, budget.WindowMonth); got != settled {
		t.Fatalf("after a restart the month shows %d, it was %d", got, settled)
	}
}

// D7: a damaged line does not stop the daemon starting: it trips at unlock and
// the owner has the documented way out.
func TestCorruptLedgerLineTripsInsteadOfStoppingStart(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	wantReason(t, e.anthropic(tok), 200, "")
	e.stop()
	files, _ := filepath.Glob(filepath.Join(e.dir, LedgerDir, "ledger-*.jsonl"))
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files[0], append([]byte("garbage\n"), raw...), 0o600); err != nil {
		t.Fatal(err)
	}
	e.start()
	acceptLedger(t, e, tok)
}

// D18: an unreadable daemon-state entry is left alone until the owner accepts
// replacing it, and what replaces it keeps the first-key exemption closed and
// a config check in force.
func TestUnreadableDaemonStateIsNotOverwritten(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	e.stop()
	garbage := []byte(`{"version":99}`)
	v, err := vault.Open(filepath.Join(e.dir, VaultFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.UnlockPassphrase(testPassphrase); err != nil {
		t.Fatal(err)
	}
	id, ok := stateEntryID(v)
	if !ok {
		t.Fatal("no daemon-state entry")
	}
	if err := v.ReplaceEntrySecret(id, garbage); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	e.start()
	st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if err != nil || st.TripReason != TripIntegrity {
		t.Fatalf("unlock: %v %s (%s)", err, st.State, st.TripReason)
	}
	if err := e.withOwner(func(ctx context.Context) error {
		_, err := e.c.AddKey(ctx, "gemini", "main", []byte("AIza"+strings.Repeat("x", 35)))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := e.d.vault.WithSecret(id, func(b []byte) error { raw = append(raw, b...); return nil }); err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(garbage) {
		t.Fatalf("a key change overwrote the unreadable entry with %d bytes", len(raw))
	}
	e.appr.approve.Store(true)
	if st, err = e.c.Resume(e.ctx()); err != nil || st.State != client.StateUnlocked {
		t.Fatalf("resume: %v %s", err, st.State)
	}
	if vs := e.d.vaultStateSnapshot(); vs == nil || !vs.KeysEverAdded {
		t.Fatalf("after resume: %+v", vs)
	}
	e.stop()
	e.cfg.Limits.Pass.Concurrency++
	e.start()
	if st, err = e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase); err != nil || st.TripReason != TripConfig {
		t.Fatalf("a changed config after the replacement: %v %s (%s)", err, st.State, st.TripReason)
	}
}

// D19: the start of a re-key is on disk before the vault commits, so a crash
// between commit and outcome leaves evidence that it may have happened.
func TestRekeyStartIsRecordedBeforeCommit(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	err := e.d.rekey(e.ctx(), "rotate_recovery", func() error {
		files, _ := filepath.Glob(filepath.Join(e.dir, AuditDir, "audit-*.jsonl"))
		for _, f := range files {
			if raw, err := os.ReadFile(f); err == nil && strings.Contains(string(raw), `"rekey_start"`) {
				return nil
			}
		}
		return errors.New("no rekey_start record on disk at commit time")
	})
	if err != nil {
		t.Fatal(err)
	}
}

// D17: the recovered-from-.prev warning survives the first unlock's own writes.
func TestRecoveredFromPrevOutlivesUnlock(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.stop()
	if err := os.Rename(filepath.Join(e.dir, VaultFile), filepath.Join(e.dir, "vault.prev")); err != nil {
		t.Fatal(err)
	}
	e.start()
	st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Vault.RecoveredFromPrev || len(st.Warnings) == 0 {
		t.Fatalf("after unlock: recovered=%v warnings=%v", st.Vault.RecoveredFromPrev, st.Warnings)
	}
	if !auditHas(t, e, "unlock", func(f map[string]any) bool { return f["recovered_from_prev"] == true }) {
		t.Fatal("the unlock record does not say so")
	}
}

// D13: a state nothing expects serves nothing.
func TestUnknownStateServesNothing(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	e.d.mu.Lock()
	e.d.st.state = "unknown"
	e.d.mu.Unlock()
	defer func() {
		e.d.mu.Lock()
		e.d.st.state = StateUnlocked
		e.d.mu.Unlock()
	}()
	wantReason(t, e.anthropic(tok), 423, proxy.ReasonLocked)
	if _, err := e.d.requireServing(); err == nil {
		t.Fatal("requireServing let an unknown state through")
	}
	p, _ := provider.Get("anthropic")
	if _, err := e.d.reserve(proxy.Admission{Provider: p}, pass.Pass{ID: "x"}, 1, nil); err == nil {
		t.Fatal("reserve let an unknown state through")
	}
}

// D13: a lock during an away approval is reported as locked, not as tripped.
func TestAwayLockedDuringApprovalSaysLocked(t *testing.T) {
	e := newEnv(t, nil)
	ra := &resumeGate{kind: "away_grant", gate: make(chan struct{}), seen: make(chan approval.Request, 1)}
	e.approver = ra
	e.restart()
	e.unlock()
	errc := make(chan error, 1)
	go func() {
		_, err := e.c.Away(e.ctx(), client.AwayRequest{Budget: money.Dollar, For: time.Hour})
		errc <- err
	}()
	<-ra.seen
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
	close(ra.gate)
	if err := <-errc; !isAPI(err, 423, client.CodeLocked) {
		t.Fatalf("away after a lock: %v", err)
	}
}

// D13: removing a slot reports a vault.prev it could not scrub, like rotation.
func TestRemoveSlotReportsPrevNotScrubbed(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.appr.approve.Store(true)
	st := e.status()
	if len(st.Vault.Slots) < 2 {
		t.Fatalf("slots: %+v", st.Vault.Slots)
	}
	prev := filepath.Join(e.dir, "vault.prev")
	os.Remove(prev)
	if err := os.MkdirAll(filepath.Join(prev, "keep"), 0o700); err != nil { // cannot be replaced or removed
		t.Fatal(err)
	}
	defer os.RemoveAll(prev)
	resp, err := e.c.RemoveSlot(e.ctx(), st.Vault.Slots[1].ID)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Warning == "" {
		t.Fatal("no warning about vault.prev")
	}
}
