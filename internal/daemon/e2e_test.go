package daemon

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/audit"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/procinfo"
	"github.com/h-a-forster/keyleash/internal/proxy"
	"github.com/h-a-forster/keyleash/internal/vault"
)

func TestLockedRefusesWith423(t *testing.T) {
	e := newEnv(t, nil)
	r := e.anthropic("klp_0123456789_" + strings.Repeat("A", 43))
	wantReason(t, r, 423, proxy.ReasonLocked)
	if e.up.hits.Load() != 0 {
		t.Fatal("upstream reached while locked")
	}
	if s := e.status(); s.State != client.StateLocked || s.Vault.Unlocked {
		t.Fatalf("status = %+v", s)
	}
}

func TestUnlockWrongSecret(t *testing.T) {
	e := newEnv(t, nil)
	cases := []struct {
		name   string
		method string
		secret []byte
		status int
		code   string
	}{
		{"wrong passphrase", client.MethodPassphrase, []byte("not the passphrase"), 401, client.CodeWrongSecret},
		{"empty passphrase", client.MethodPassphrase, nil, 400, client.CodeBadRequest},
		{"malformed recovery", client.MethodRecovery, []byte("AAAA-BBBB"), 401, client.CodeWrongSecret},
		{"unknown method", "telepathy", []byte("x"), 400, client.CodeBadRequest},
		{"hello unavailable", client.MethodHello, nil, 400, client.CodeUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.c.Unlock(e.ctx(), tc.method, tc.secret)
			if !isAPI(err, tc.status, tc.code) {
				t.Fatalf("err = %v", err)
			}
			if len(tc.secret) > 0 && strings.Contains(err.Error(), string(tc.secret)) {
				t.Fatal("secret echoed in error")
			}
		})
	}
	if e.status().State != client.StateLocked {
		t.Fatal("unlocked by a wrong secret")
	}
	e.unlock()
	if _, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase); !isAPI(err, 409, client.CodeConflict) {
		t.Fatalf("double unlock: %v", err)
	}
	e.assertNoSecrets("not the passphrase")
}

func TestUnlockWithRecoveryCode(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := e.c.Unlock(e.ctx(), client.MethodRecovery, []byte(e.recovery)); err != nil {
		t.Fatal(err)
	}
	if e.status().State != client.StateUnlocked {
		t.Fatal("not unlocked")
	}
}

func TestRequestSettlesActualCost(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	token := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic", "openai"}})

	r := e.anthropic(token)
	if r.status != 200 || !strings.Contains(r.body, "Hello.") {
		t.Fatalf("anthropic: %d %s", r.status, r.body)
	}
	want1 := e.expectedCost("anthropic", "/v1/messages", anthropicReq, anthropicJSON)

	r = e.post("anthropic", "/v1/messages", token, anthropicStreamReq)
	if r.status != 200 || !strings.Contains(r.body, "message_stop") {
		t.Fatalf("anthropic stream: %d %s", r.status, r.body)
	}
	want2 := e.expectedCost("anthropic", "/v1/messages", anthropicStreamReq, anthropicSSE)

	r = e.post("openai", "/v1/chat/completions", token, openaiStreamReq)
	if r.status != 200 || !strings.Contains(r.body, "[DONE]") {
		t.Fatalf("openai stream: %d %s", r.status, r.body)
	}
	want3 := e.expectedCost("openai", "/v1/chat/completions", openaiStreamReq, openaiSSE)
	// The proxy asked the OpenAI stream for its usage chunk.
	e.up.mu.Lock()
	last := e.up.bodies[len(e.up.bodies)-1]
	e.up.mu.Unlock()
	if !strings.Contains(last, `"include_usage":true`) {
		t.Fatalf("include_usage not added: %s", last)
	}

	total := want1 + want2 + want3
	if total <= 0 {
		t.Fatal("fixtures priced at zero")
	}
	s := e.status()
	got, ok := limitSettled(s, "global", "day")
	if !ok || got != total {
		t.Fatalf("global day settled = %s, want %s (limits %+v)", got, total, s.Limits)
	}
	if len(s.InFlight) != 0 {
		t.Fatalf("in flight after completion: %+v", s.InFlight)
	}
	u, err := e.c.Usage(e.ctx(), "provider", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if u.Total != total || len(u.Rows) != 2 {
		t.Fatalf("usage = %+v, want total %s", u, total)
	}
	for _, row := range u.Rows {
		if row.Estimated != 0 {
			t.Fatalf("row %s marked estimated", row.Key)
		}
	}
	// The audit has the request records, with costs, and no secret.
	recs, err := e.c.AuditTail(e.ctx(), 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, rec := range recs {
		if rec.Type == "request" && rec.Fields["deny_reason"] == nil {
			n++
			if rec.Fields["client"] != "agent.exe" {
				t.Fatalf("attribution missing: %+v", rec.Fields)
			}
		}
	}
	if n != 3 {
		t.Fatalf("request records = %d", n)
	}
	e.assertNoSecrets(token)
}

func TestUnmeteredEndpointAndModelPolicy(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Models.Deny = []string{"*opus*"} })
	e.unlock()
	e.addKeys()
	token := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}, DenyModels: []string{"*haiku*"}})

	r := e.post("anthropic", "/v1/messages", token, `{"model":"claude-opus-5-5","max_tokens":10,"messages":[]}`)
	wantReason(t, r, 403, proxy.ReasonModelDenied)
	r = e.post("anthropic", "/v1/messages", token, `{"model":"claude-haiku-4-5","max_tokens":10,"messages":[]}`)
	wantReason(t, r, 403, proxy.ReasonModelDenied)
	// Provider scope.
	r = e.post("openai", "/v1/chat/completions", token, openaiStreamReq)
	wantReason(t, r, 403, ReasonProviderDenied)
	// Bad pass.
	r = e.anthropic("klp_0123456789_" + strings.Repeat("A", 43))
	wantReason(t, r, 401, proxy.ReasonPassInvalid)
	if e.up.hits.Load() != 0 {
		t.Fatal("denied request reached upstream")
	}
}

func TestUnknownModelPolicy(t *testing.T) {
	body := `{"model":"claude-unreleased-9","max_tokens":10,"messages":[{"role":"user","content":"x"}]}`
	t.Run("deny", func(t *testing.T) {
		e := newEnv(t, func(c *config.Config) { c.Models.Unknown = "deny" })
		e.unlock()
		e.addKeys()
		tok := e.newPass(client.PassCreateRequest{})
		wantReason(t, e.post("anthropic", "/v1/messages", tok, body), 403, proxy.ReasonModelDenied)
	})
	t.Run("approve denied", func(t *testing.T) {
		e := newEnv(t, nil) // recommended: approve
		e.unlock()
		e.addKeys()
		tok := e.newPass(client.PassCreateRequest{})
		wantReason(t, e.post("anthropic", "/v1/messages", tok, body), 403, proxy.ReasonApprovalDenied)
	})
	t.Run("approve approved charges fallback", func(t *testing.T) {
		e := newEnv(t, nil)
		e.appr.approve.Store(true)
		e.unlock()
		e.addKeys()
		tok := e.newPass(client.PassCreateRequest{})
		r := e.post("anthropic", "/v1/messages", tok, body)
		if r.status != 200 {
			t.Fatalf("%d %s", r.status, r.body)
		}
		// The fixture reports usage for claude-sonnet-4-5, which is priced,
		// so the actual cost is used; the reservation was the fallback.
		got, _ := limitSettled(e.status(), "global", "day")
		if got <= 0 || got > 2*money.Dollar {
			t.Fatalf("settled = %s", got)
		}
	})
}

func TestBudgetExceeded(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.Global.Request = &config.Amount{Micros: 1}
	})
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	r := e.anthropic(tok)
	wantReason(t, r, 403, proxy.ReasonBudgetExceeded)
	if !strings.Contains(r.body, "global request limit") && !strings.Contains(r.body, "per-request limit") {
		t.Fatalf("message does not name the limit: %s", r.body)
	}
	if e.up.hits.Load() != 0 {
		t.Fatal("upstream reached")
	}

	// A day limit that the first request uses up.
	e2 := newEnv(t, nil)
	e2.unlock()
	e2.addKeys()
	est := e2.estimate("anthropic", "/v1/messages", anthropicReq)
	tok2 := e2.newPass(client.PassCreateRequest{Limits: []client.PassLimit{{Window: "day", Amount: est + est/2}}})
	if r := e2.anthropic(tok2); r.status != 200 {
		t.Fatalf("first: %d %s", r.status, r.body)
	}
	// Settled spend is far below the estimate, so a second fits; keep going
	// until the pass's day limit refuses.
	var last result
	for range 200 {
		if last = e2.anthropic(tok2); last.status != 200 {
			break
		}
	}
	wantReason(t, last, 403, proxy.ReasonBudgetExceeded)
	if !strings.Contains(last.body, "remaining") {
		t.Fatalf("message lacks remaining amount: %s", last.body)
	}
}

func TestOnExceedApproveRaisesLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.Global.Request = &config.Amount{Micros: 1}
		c.Limits.OnExceed = "approve"
	})
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	wantReason(t, e.anthropic(tok), 403, proxy.ReasonApprovalDenied)
	e.appr.approve.Store(true)
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatalf("approved retry: %d %s", r.status, r.body)
	}
}

func TestConcurrencyLimit(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.Global.Concurrency = 1 })
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	done := make(chan result, 1)
	go func() { done <- e.anthropic(tok, "X-Test-Hold", "1") }()
	select {
	case <-e.up.held:
	case <-time.After(10 * time.Second):
		t.Fatal("held request never reached upstream")
	}
	wantReason(t, e.anthropic(tok), 429, proxy.ReasonConcurrency)
	close(e.up.relea)
	if r := <-done; r.status != 200 {
		t.Fatalf("held request: %d %s", r.status, r.body)
	}
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatalf("after release: %d %s", r.status, r.body)
	}
}

func TestAwayAppliesAwayLimits(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.Away.Total = &config.Amount{Micros: 1} })
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatalf("present: %d", r.status)
	}
	e.pres.set(time.Hour, false)
	e.d.stepPresence()
	if s := e.status(); s.State != client.StateAway || s.AwaySince.IsZero() {
		t.Fatalf("state = %s", s.State)
	}
	wantReason(t, e.anthropic(tok), 403, proxy.ReasonAwayLimit)

	// New run passes are refused while away.
	_, err := e.c.CreatePass(e.ctx(), client.PassCreateRequest{Name: "r", Kind: "run", Providers: []string{"*"}, BindPID: os.Getpid()})
	if !isAPI(err, 403, client.CodeForbidden) && !isAPI(err, 400, client.CodeBadRequest) {
		t.Fatalf("run pass while away: %v", err)
	}

	// Input resumes: back to Unlocked and normal limits.
	e.pres.set(0, false)
	e.d.stepPresence()
	if s := e.status(); s.State != client.StateUnlocked {
		t.Fatalf("state = %s", s.State)
	}
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatalf("present again: %d", r.status)
	}

	// Away too long locks.
	e.pres.set(time.Hour, false)
	e.d.stepPresence()
	e.clk.Advance(e.cfg.Presence.AwayMax.Duration + time.Second)
	e.d.housekeep()
	if s := e.status(); s.State != client.StateLocked {
		t.Fatalf("after away_max state = %s", s.State)
	}
}

func TestUnattendedGrant(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.Away.Total = &config.Amount{Micros: 1} })
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	// Step-up denied.
	if _, err := e.c.Away(e.ctx(), client.AwayRequest{Budget: money.Dollar, For: 8 * time.Hour}); !isAPI(err, 403, client.CodeStepUpDenied) {
		t.Fatalf("away without approval: %v", err)
	}
	e.appr.approve.Store(true)
	g, err := e.c.Away(e.ctx(), client.AwayRequest{Budget: money.Dollar, For: 8 * time.Hour})
	if err != nil || g.ID == "" {
		t.Fatalf("grant: %v", err)
	}
	e.pres.set(time.Hour, false)
	e.d.stepPresence()
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatalf("with grant: %d %s", r.status, r.body)
	}
	// away_max is extended to the grant's end.
	e.clk.Advance(e.cfg.Presence.AwayMax.Duration + time.Minute)
	e.d.housekeep()
	if s := e.status(); s.State != client.StateAway {
		t.Fatalf("grant should extend away_max, state = %s", s.State)
	}
	e.clk.Advance(8 * time.Hour)
	e.d.housekeep()
	if s := e.status(); s.State != client.StateLocked {
		t.Fatalf("after grant end state = %s", s.State)
	}
}

func TestPresenceResumedAndScreenLock(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Presence.ScreenLock = "lock" })
	e.unlock()
	e.clk.Advance(time.Hour) // wall clock jump between polls = sleep
	e.d.stepPresence()
	if s := e.status(); s.State != client.StateLocked || s.Vault.Unlocked {
		t.Fatalf("after resume state = %s unlocked=%v", s.State, s.Vault.Unlocked)
	}
	e.unlock()
	e.pres.set(0, true)
	e.d.stepPresence()
	if s := e.status(); s.State != client.StateLocked {
		t.Fatalf("screen lock (policy lock) state = %s", s.State)
	}
}

func TestLeaseExpiryLocks(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.clk.Advance(e.cfg.Presence.MaxLease.Duration)
	e.d.housekeep()
	if s := e.status(); s.State != client.StateLocked {
		t.Fatalf("state = %s", s.State)
	}
}

func TestTripwireAndResume(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Tripwire.Threshold = &config.Amount{Micros: 1} })
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	e.tripBySpend(tok)
	s := e.status()
	if s.State != client.StateTripped || s.TripReason != TripVelocity {
		t.Fatalf("state = %s (%s)", s.State, s.TripReason)
	}
	wantReason(t, e.anthropic(tok), 423, proxy.ReasonTripped)

	// Resume requires step-up.
	if _, err := e.c.Resume(e.ctx()); !isAPI(err, 403, client.CodeStepUpDenied) {
		t.Fatalf("resume without approval: %v", err)
	}
	if e.status().State != client.StateTripped {
		t.Fatal("left Tripped without approval")
	}
	e.appr.approve.Store(true)
	st, err := e.c.Resume(e.ctx())
	if err != nil || st.State != client.StateUnlocked {
		t.Fatalf("resume: %v %s", err, st.State)
	}
	if _, err := e.c.Resume(e.ctx()); !isAPI(err, 409, client.CodeConflict) {
		t.Fatalf("resume when not tripped: %v", err)
	}
}

func TestPanicRevokesAndLocks(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatal(r.status)
	}
	sum, err := e.c.Panic(e.ctx(), true)
	if err != nil || !sum.Locked || sum.PassesRevoked != 1 || sum.Note == "" {
		t.Fatalf("panic: %+v %v", sum, err)
	}
	wantReason(t, e.anthropic(tok), 423, proxy.ReasonLocked)
	e.unlock()
	wantReason(t, e.anthropic(tok), 401, proxy.ReasonPassInvalid)
	ps, _ := e.c.Passes(e.ctx())
	if len(ps) != 1 || !ps[0].Revoked {
		t.Fatalf("passes = %+v", ps)
	}
}

func TestRestartPreservesSpend(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatal(r.status)
	}
	want := e.expectedCost("anthropic", "/v1/messages", anthropicReq, anthropicJSON)
	e.restart()
	if e.status().State != client.StateLocked {
		t.Fatal("restart did not start locked")
	}
	e.unlock()
	s := e.status()
	got, _ := limitSettled(s, "global", "month")
	if got != want {
		t.Fatalf("month settled after restart = %s, want %s", got, want)
	}
	if sess, _ := limitSettled(s, "global", "session"); sess != 0 {
		t.Fatalf("session window should restart on unlock, got %s", sess)
	}
	// The pass survived too.
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatalf("after restart: %d", r.status)
	}
}

func TestLedgerTamperTripsAfterUnlock(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	for range 2 {
		if r := e.anthropic(tok); r.status != 200 {
			t.Fatal(r.status)
		}
	}
	e.stop()

	files, _ := filepath.Glob(filepath.Join(e.dir, LedgerDir, "ledger-*.jsonl"))
	if len(files) != 1 {
		t.Fatalf("ledger files: %v", files)
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		t.Fatal(err)
	}
	// Lower the first record's amount by one micro (hide spend).
	re := regexp.MustCompile(`"amount_micros":(\d+)`)
	loc := re.FindSubmatchIndex(raw)
	n, _ := strconv.Atoi(string(raw[loc[2]:loc[3]]))
	tampered := append(append(append([]byte{}, raw[:loc[2]]...), strconv.Itoa(n-1)...), raw[loc[3]:]...)
	if err := os.WriteFile(files[0], tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	e.start()
	if _, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase); err != nil {
		t.Fatal(err)
	}
	s := e.status()
	if s.State != client.StateTripped || s.TripReason != TripIntegrity {
		t.Fatalf("state = %s (%s), integrity %q", s.State, s.TripReason, s.Integrity)
	}
	wantReason(t, e.anthropic(tok), 423, proxy.ReasonTripped)
}

func TestStateFileTamperTrips(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatal(r.status)
	}
	e.stop()
	// state.json holds no security state any more: deleting it is harmless.
	if err := os.Remove(filepath.Join(e.dir, StateFile)); err != nil {
		t.Fatal(err)
	}
	e.start()
	e.unlock() // fatals unless Unlocked
	e.stop()
	// Deleting state.json and the whole ledger (to reset spend) is detected:
	// the checkpoint lives in the vault (spec Â§7.7).
	os.Remove(filepath.Join(e.dir, StateFile))
	if err := os.RemoveAll(filepath.Join(e.dir, LedgerDir)); err != nil {
		t.Fatal(err)
	}
	e.start()
	e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if s := e.status(); s.State != client.StateTripped || s.TripReason != TripIntegrity {
		t.Fatalf("state = %s (%s)", s.State, s.TripReason)
	}
	// The owner can accept the current state with step-up.
	e.appr.approve.Store(true)
	if st, err := e.c.Resume(e.ctx()); err != nil || st.State != client.StateUnlocked {
		t.Fatalf("resume: %v", err)
	}
	e.restart()
	e.unlock() // fatals unless Unlocked: the accepted state verifies now
}

func TestAuditVerifiesAfterSession(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	for range 3 {
		e.anthropic(tok)
	}
	e.clk.Advance(e.cfg.Audit.AnchorEvery.Duration)
	e.d.housekeep()
	v, err := e.c.AuditVerify(e.ctx())
	if err != nil || !v.OK || !v.KeyUsed || v.AnchorsVerified < 2 || v.Records < 10 {
		t.Fatalf("verify = %+v %v", v, err)
	}
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
	v, err = e.c.AuditVerify(e.ctx())
	if err != nil || !v.OK || v.KeyUsed {
		t.Fatalf("verify while locked = %+v %v", v, err)
	}
	e.stop()
	if _, err := audit.Verify(filepath.Join(e.dir, AuditDir), nil); err != nil {
		t.Fatalf("offline verify: %v", err)
	}
	// Tampering is detected.
	files, _ := filepath.Glob(filepath.Join(e.dir, AuditDir, "audit-*.jsonl"))
	raw, _ := os.ReadFile(files[0])
	raw = []byte(strings.Replace(string(raw), `"type":"unlock"`, `"type":"unlocx"`, 1))
	os.WriteFile(files[0], raw, 0o600)
	if _, err := audit.Verify(filepath.Join(e.dir, AuditDir), nil); err == nil {
		t.Fatal("tampered audit verified")
	}
}

func TestRekeyKeepsIntegrity(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	e.anthropic(tok)
	if _, err := e.c.RotateRecovery(e.ctx()); !isAPI(err, 403, client.CodeStepUpDenied) {
		t.Fatalf("rotate without approval: %v", err)
	}
	e.appr.approve.Store(true)
	rr, err := e.c.RotateRecovery(e.ctx())
	if err != nil || rr.Code == "" || rr.Code == e.recovery {
		t.Fatalf("rotate: %v", err)
	}
	e.anthropic(tok)
	e.restart()
	if _, err := e.c.Unlock(e.ctx(), client.MethodRecovery, []byte(e.recovery)); !isAPI(err, 401, client.CodeWrongSecret) {
		t.Fatalf("old recovery code still works: %v", err)
	}
	e.unlock()
	v, err := e.c.AuditVerify(e.ctx())
	if err != nil || !v.OK || v.AnchorsVerified == 0 {
		t.Fatalf("audit after rekey = %+v %v", v, err)
	}
	e.assertNoSecrets(rr.Code, tok)
}

func TestKeysAdminAndStepUp(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := e.c.AddKey(e.ctx(), "anthropic", "x", []byte(anthropicKey)); !isAPI(err, 423, client.CodeLocked) {
		t.Fatalf("add while locked: %v", err)
	}
	e.unlock()
	if _, err := e.c.AddKey(e.ctx(), "nope", "x", []byte("k")); !isAPI(err, 400, client.CodeBadRequest) {
		t.Fatalf("unknown provider: %v", err)
	}
	e.addKeys()
	keys, err := e.c.Keys(e.ctx())
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys = %+v %v (integrity root must be hidden)", keys, err)
	}
	for _, k := range keys {
		if k.Fingerprint == "" || !k.Authenticated {
			t.Fatalf("key = %+v", k)
		}
	}
	if err := e.c.RemoveKey(e.ctx(), keys[0].ID); !isAPI(err, 403, client.CodeStepUpDenied) {
		t.Fatalf("remove without step-up: %v", err)
	}
	e.appr.approve.Store(true)
	if err := e.c.RemoveKey(e.ctx(), keys[0].ID); err != nil {
		t.Fatal(err)
	}
	// The integrity root cannot be removed through the API.
	for _, en := range e.d.vault.Entries() {
		if isRootEntry(en) {
			if err := e.c.RemoveKey(e.ctx(), en.ID); !isAPI(err, 404, client.CodeNotFound) {
				t.Fatalf("root removal: %v", err)
			}
		}
	}
	tok := e.newPass(client.PassCreateRequest{Providers: []string{"anthropic"}})
	wantReason(t, e.anthropic(tok), 403, ReasonNoKey)
	e.assertNoSecrets()
}

func TestPassCreateValidation(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := e.c.CreatePass(e.ctx(), client.PassCreateRequest{Name: "x", Providers: []string{"*"}}); !isAPI(err, 423, client.CodeLocked) {
		t.Fatalf("create while locked: %v", err)
	}
	e.unlock()
	cases := []struct {
		name string
		req  client.PassCreateRequest
	}{
		{"no providers", client.PassCreateRequest{Name: "x"}},
		{"unknown provider", client.PassCreateRequest{Providers: []string{"nope"}}},
		{"bad kind", client.PassCreateRequest{Kind: "admin", Providers: []string{"*"}}},
		{"run unbound", client.PassCreateRequest{Kind: "run", Providers: []string{"*"}}},
		{"bad glob", client.PassCreateRequest{Providers: []string{"*"}, Models: []string{"[x"}}},
		{"bad window", client.PassCreateRequest{Providers: []string{"*"}, Limits: []client.PassLimit{{Window: "fortnight", Amount: 1}}}},
		{"negative ttl", client.PassCreateRequest{Providers: []string{"*"}, TTL: -time.Hour}},
		{"dead pid", client.PassCreateRequest{Providers: []string{"*"}, BindPID: 1 << 30}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := e.c.CreatePass(e.ctx(), tc.req); !isAPI(err, 400, client.CodeBadRequest) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	r, err := e.c.CreatePass(e.ctx(), client.PassCreateRequest{Name: "ok", Providers: []string{"*"}})
	if err != nil || !strings.HasPrefix(r.Token, "klp_") || r.Pass.Expires.IsZero() || r.Pass.Concurrency != e.cfg.Limits.Pass.Concurrency {
		t.Fatalf("create = %+v %v", r, err)
	}
	ps, _ := e.c.Passes(e.ctx())
	for _, p := range ps {
		if strings.Contains(p.Name+p.ID, r.Token) {
			t.Fatal("token in listing")
		}
	}
	if err := e.c.RevokePass(e.ctx(), r.Pass.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.c.RevokePass(e.ctx(), "nope"); !isAPI(err, 404, client.CodeNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
	wantReason(t, e.anthropic(r.Token), 401, proxy.ReasonPassInvalid)
}

func TestBoundPassFromOtherProcessDenied(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	r, err := e.c.CreatePass(e.ctx(), client.PassCreateRequest{Name: "bound", Providers: []string{"*"}, BindPID: os.Getpid()})
	if err != nil {
		t.Skipf("process binding unavailable on this platform: %v", err)
	}
	// The client is this process: allowed.
	e.peerPID.Store(int64(os.Getpid()))
	if res := e.anthropic(r.Token); res.status != 200 {
		t.Fatalf("own process: %d %s", res.status, res.body)
	}
	hits := e.up.hits.Load()
	// A different process (our parent is never our descendant): denied.
	e.peerPID.Store(int64(os.Getppid()))
	wantReason(t, e.anthropic(r.Token), 401, proxy.ReasonPassInvalid)
	// Attribution unknown: denied, never treated as unbound.
	e.peerPID.Store(0)
	wantReason(t, e.anthropic(r.Token), 401, proxy.ReasonPassInvalid)
	if e.up.hits.Load() != hits {
		t.Fatal("denied bound request reached upstream")
	}
}

func TestExternalApprovalViaAdmin(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Tripwire.Threshold = &config.Amount{Micros: 1} })
	// An approver that never answers: decisions come from the admin API.
	e.approver = blockingApprover{}
	e.restart()
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	e.tripBySpend(tok)
	done := make(chan error, 1)
	go func() { _, err := e.c.Resume(e.ctx()); done <- err }()
	var pending []client.Approval
	for i := 0; i < 200 && len(pending) == 0; i++ {
		pending, _ = e.c.Approvals(e.ctx())
		time.Sleep(10 * time.Millisecond)
	}
	if len(pending) != 1 || pending[0].Kind != "resume" {
		t.Fatalf("pending = %+v", pending)
	}
	// Access to the admin channel alone never approves (spec Â§9).
	if err := e.c.Decide(e.ctx(), pending[0].ID, client.DecideRequest{Approved: true}); !isAPI(err, 403, client.CodeForbidden) {
		t.Fatalf("approve without secret: %v", err)
	}
	if err := e.c.Decide(e.ctx(), pending[0].ID, client.DecideRequest{Approved: true, Secret: []byte("not the passphrase")}); !isAPI(err, 401, client.CodeWrongSecret) {
		t.Fatalf("approve with a wrong secret: %v", err)
	}
	if err := e.c.Decide(e.ctx(), pending[0].ID, client.DecideRequest{Approved: true, Secret: append([]byte(nil), testPassphrase...)}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := e.c.Decide(e.ctx(), pending[0].ID, client.DecideRequest{Approved: true, Secret: append([]byte(nil), testPassphrase...)}); !isAPI(err, 404, client.CodeNotFound) {
		t.Fatalf("second decision: %v", err)
	}
	e.assertNoSecrets()
}

func TestRecoveryCodeApprovesAndDenyNeedsNothing(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Tripwire.Threshold = &config.Amount{Micros: 1} })
	e.approver = blockingApprover{}
	e.restart()
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	e.tripBySpend(tok)
	first := make(chan error, 1)
	go func() { _, err := e.c.Resume(e.ctx()); first <- err }()
	id := e.waitPending("resume")
	if err := e.c.Decide(e.ctx(), id, client.DecideRequest{Approved: false}); err != nil {
		t.Fatal(err)
	}
	if err := <-first; !isAPI(err, 403, client.CodeStepUpDenied) {
		t.Fatalf("denied resume: %v", err)
	}
	second := make(chan error, 1)
	go func() { _, err := e.c.Resume(e.ctx()); second <- err }()
	id = e.waitPending("resume")
	if err := e.c.Decide(e.ctx(), id, client.DecideRequest{Approved: true, Method: client.MethodRecovery, Secret: []byte(e.recovery)}); err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if st := e.status(); st.State != client.StateUnlocked {
		t.Fatalf("state = %s", st.State)
	}
	e.assertNoSecrets()
}

func TestSecondInstanceRefused(t *testing.T) {
	e := newEnv(t, nil)
	_, err := Start(t.Context(), Options{DataDir: e.dir, Config: e.cfg, PresenceSource: e.pres,
		AdminListener: newMemListener(), manualPresence: true, manualHousekeeping: true})
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second instance: %v", err)
	}
}

func TestInvalidConfigRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, InitOptions{Method: "passphrase", Passphrase: testPassphrase}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ConfigFile), []byte("[models]\nunknown = \"free\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Start(t.Context(), Options{DataDir: dir, PresenceSource: &fakePresence{},
		AdminListener: newMemListener(), manualPresence: true, manualHousekeeping: true})
	if err == nil || !strings.Contains(err.Error(), "invalid config") {
		t.Fatalf("err = %v", err)
	}
	// No vault at all.
	_, err = Start(t.Context(), Options{DataDir: t.TempDir(), PresenceSource: &fakePresence{},
		AdminListener: newMemListener(), manualPresence: true, manualHousekeeping: true})
	if err == nil || !strings.Contains(err.Error(), "keyleash init") {
		t.Fatalf("err = %v", err)
	}
}

// Where process identity is unavailable (procinfo unsupported), a pass that
// asks to be bound to a process is refused, never issued unbound.
func TestBindPIDUnsupportedFailsClosed(t *testing.T) {
	if _, err := procinfo.Lookup(os.Getpid()); !errors.Is(err, procinfo.ErrUnsupported) {
		t.Skip("process binding is supported here; covered by the bound-pass tests")
	}
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	for _, req := range []client.PassCreateRequest{
		{Name: "bound", Providers: []string{"anthropic"}, BindPID: os.Getpid()},
		{Name: "run", Kind: "run", Providers: []string{"anthropic"}, BindPID: os.Getpid()},
	} {
		err := e.withOwner(func(ctx context.Context) error {
			_, err := e.c.CreatePass(ctx, req)
			return err
		})
		if !isAPI(err, 400, client.CodeBadRequest) {
			t.Fatalf("%s pass bound to a process: %v", req.Name, err)
		}
	}
	passes, err := e.c.Passes(e.ctx())
	if err != nil {
		t.Fatal(err)
	}
	if len(passes) != 0 {
		t.Fatalf("passes issued: %+v", passes)
	}
}

// A rotation whose caller is gone by the time the step-up is decided (the
// CLI was interrupted) is not committed: nobody would receive the new code,
// and the old one would be dead.
func TestRotateRecoveryNotCommittedWhenCallerGone(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.appr.approve.Store(true)
	ctx, cancel := context.WithCancel(e.ctx())
	defer cancel()
	e.d.testBeforeRekey = func(rctx context.Context) {
		cancel() // approved, then the caller is interrupted
		select {
		case <-rctx.Done():
		case <-time.After(10 * time.Second):
			t.Error("request context not cancelled after the caller went away")
		}
	}
	if r, err := e.c.RotateRecovery(ctx); err == nil || r.Code != "" {
		t.Fatalf("rotate for a gone caller: %+v %v", r, err)
	}
	// Unlock waits for the re-key to finish (unlockMu); the old code must
	// still work.
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if _, err := e.c.Unlock(e.ctx(), client.MethodRecovery, []byte(e.recovery)); err != nil {
		t.Fatalf("old recovery code after an aborted rotation: %v", err)
	}
	recs, err := e.c.AuditTail(e.ctx(), 200)
	if err != nil {
		t.Fatal(err)
	}
	aborted := false
	for _, rec := range recs {
		if rec.Type == "rekey" && rec.Fields["ok"] == true {
			t.Fatalf("rotation committed: %+v", rec.Fields)
		}
		aborted = aborted || (rec.Type == "rekey" && rec.Fields["reason"] == "caller_gone")
	}
	if !aborted {
		t.Fatal("aborted rotation not audited")
	}
}

// A re-key interrupted between its two renames leaves vault.prev under the
// old vault key; the next unlock replaces it and audits that (spec §5.4).
func TestUnlockScrubsStalePrev(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	vpath := filepath.Join(e.dir, VaultFile)
	e.addKeys() // at least one write, so vault.prev exists
	stale, err := os.ReadFile(vault.PrevPath(vpath))
	if err != nil {
		t.Fatal(err)
	}
	e.appr.approve.Store(true)
	if _, err := e.c.RotateRecovery(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.stop()
	// The crash: main renamed, .prev not yet.
	if err := os.WriteFile(vault.PrevPath(vpath), stale, 0o600); err != nil {
		t.Fatal(err)
	}
	e.start()
	e.unlock()
	prev, err := os.ReadFile(vault.PrevPath(vpath))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(prev, stale) {
		t.Fatal("stale vault.prev kept after unlock")
	}
	p := filepath.Join(t.TempDir(), "vault.json")
	if err := os.WriteFile(p, prev, 0o600); err != nil {
		t.Fatal(err)
	}
	old, err := vault.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := old.UnlockRecovery(e.recovery); !errors.Is(err, vault.ErrWrongSecret) {
		t.Fatalf("old recovery code on vault.prev after unlock: %v", err)
	}
	if !auditHas(t, e, "prev_scrub", func(f map[string]any) bool { return f["ok"] == true }) {
		t.Fatal("scrub not audited")
	}
	if s := e.status(); s.Vault.PrevNotScrubbed {
		t.Fatal("status reports vault.prev not scrubbed")
	}
}

// An old vault file restored without its anti-rollback sidecar, next to a
// newer vault.prev, is refused as a rollback (audited, shown in status)
// instead of unlocking and overwriting the newer vault.prev (spec §5.4).
func TestRestoredVaultWithoutSidecarIsRollback(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	vpath := filepath.Join(e.dir, VaultFile)
	backup, err := os.ReadFile(vpath)
	if err != nil {
		t.Fatal(err)
	}
	e.appr.approve.Store(true)
	if _, err := e.c.RotateRecovery(e.ctx()); err != nil {
		t.Fatal(err)
	}
	e.stop()
	prev, err := os.ReadFile(vault.PrevPath(vpath))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vpath, backup, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(vault.SeqPath(vpath)); err != nil {
		t.Fatal(err)
	}
	e.start()
	if _, err := e.c.Unlock(e.ctx(), client.MethodRecovery, []byte(e.recovery)); !isAPI(err, 409, client.CodeRollback) {
		t.Fatalf("unlock of a restored file = %v", err)
	}
	if s := e.status(); !s.Vault.RollbackDetected || s.Vault.RollbackRecordedSeq <= s.Vault.RollbackFileSeq {
		t.Fatalf("status = %+v", s.Vault)
	}
	if !auditHas(t, e, "unlock", func(f map[string]any) bool { return f["reason"] == "rollback" }) {
		t.Fatal("rollback not audited")
	}
	if now, _ := os.ReadFile(vault.PrevPath(vpath)); !bytes.Equal(now, prev) {
		t.Fatal("newer vault.prev overwritten")
	}
}
