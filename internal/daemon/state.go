package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/h-a-forster/keyleash/internal/approval"
	"github.com/h-a-forster/keyleash/internal/audit"
	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/presence"
	"github.com/h-a-forster/keyleash/internal/secmem"
	"github.com/h-a-forster/keyleash/internal/vault"
)

// State is the daemon state (docs/DAEMON.md "State machine").
type State string

// States.
const (
	StateLocked   State = client.StateLocked
	StateUnlocked State = client.StateUnlocked
	StateAway     State = client.StateAway
	StateTripped  State = client.StateTripped
)

// Trip reasons.
const (
	TripVelocity  = "velocity"
	TripIntegrity = "integrity"
	TripAudit     = "audit"
)

// stateData is everything guarded by Daemon.mu. Lock order: Daemon.mu
// before Daemon.auditMu; unlockMu before both.
type stateData struct {
	state      State
	tripReason string
	tripDetail string

	session    string
	leaseUntil time.Time
	awaySince  time.Time

	// Latest presence readings (edge-triggered events folded into flags).
	idle, screenLocked bool

	grant    *grantInfo
	overlays []overlay

	keys *integrityKeys
	// integrityOK is false after a failed ledger/state verification until
	// the owner approves a resume; the checkpoint is not saved meanwhile.
	integrityOK  bool
	integrityMsg string

	rollback        bool
	prevNotScrubbed bool

	lastAnchor, lastSave, lastExpire, lastSweep time.Time

	// concScopes are scopes with a concurrency cap set on the ledger.
	concScopes map[string]bool
	// modelsSeen records provider/model pairs that had no price.
	modelsSeen map[string]bool
}

// grantInfo is an unattended grant (docs/DAEMON.md).
type grantInfo struct {
	id     string
	amount money.Micros
	until  time.Time
	pass   string
}

// overlay raises one limit temporarily after an approved over_limit request.
type overlay struct {
	scope  string
	window budget.Window
	amount money.Micros
	until  time.Time
}

func newID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("keyleash: crypto/rand failed")
	}
	return prefix + hex.EncodeToString(b[:])
}

func (d *Daemon) sessionID() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.st.session
}

// errStatus is an admin error with an HTTP status and code.
type errStatus struct {
	status int
	code   string
	msg    string
}

func (e *errStatus) Error() string { return e.msg }

func statusErr(status int, code, format string, a ...any) error {
	return &errStatus{status: status, code: code, msg: fmt.Sprintf(format, a...)}
}

// ---- unlock ----------------------------------------------------------------

// unlock verifies a slot and performs the Locked → Unlocked transition.
// secret is not retained (the caller wipes it).
func (d *Daemon) unlock(ctx context.Context, method string, secret []byte) error {
	d.unlockMu.Lock()
	defer d.unlockMu.Unlock()
	if d.State() != StateLocked {
		return statusErr(409, client.CodeConflict, "already unlocked")
	}
	var err error
	switch method {
	case client.MethodPassphrase:
		if len(secret) == 0 {
			return statusErr(400, client.CodeBadRequest, "passphrase required")
		}
		err = d.vault.UnlockPassphrase(secret)
	case client.MethodRecovery:
		if len(secret) == 0 {
			return statusErr(400, client.CodeBadRequest, "recovery code required")
		}
		err = d.vault.UnlockRecovery(string(secret))
	case client.MethodHello:
		if ok, reason := d.helloAvailable(); !ok {
			return statusErr(400, client.CodeUnsupported, "Windows Hello is not available: %s", reason)
		}
		var hk vault.HelloKey
		if hk, err = openHelloKey(HelloVaultKey); err == nil {
			err = d.vault.UnlockHello(ctx, hk, "Unlock keyleash")
		}
	case client.MethodDPAPI:
		err = d.vault.UnlockDPAPI()
	default:
		return statusErr(400, client.CodeBadRequest, "unknown unlock method")
	}
	if err != nil {
		d.auditEvent("unlock", map[string]any{"ok": false, "method": method, "reason": unlockFailReason(err)})
		switch {
		case errors.Is(err, vault.ErrWrongSecret), errors.Is(err, vault.ErrBadRecoveryCode):
			return statusErr(401, client.CodeWrongSecret, "wrong secret")
		case errors.Is(err, vault.ErrRollback):
			d.mu.Lock()
			d.st.rollback = true
			d.mu.Unlock()
			return statusErr(409, client.CodeRollback, "%v; if you restored an older vault on purpose, run `keyleash unlock --accept-rollback`", vault.ErrRollback)
		case errors.Is(err, vault.ErrTampered):
			return statusErr(409, client.CodeConflict, "vault integrity check failed")
		case errors.Is(err, errors.ErrUnsupported):
			return statusErr(400, client.CodeUnsupported, "unlock method not supported on this system")
		case ctx.Err() != nil:
			return ctx.Err()
		}
		d.log.Warn("unlock failed", "method", method, "err", err)
		return statusErr(401, client.CodeWrongSecret, "unlock failed")
	}
	return d.afterUnlock(method)
}

func unlockFailReason(err error) string {
	switch {
	case errors.Is(err, vault.ErrWrongSecret), errors.Is(err, vault.ErrBadRecoveryCode):
		return "wrong_secret"
	case errors.Is(err, vault.ErrRollback):
		return "rollback"
	case errors.Is(err, vault.ErrTampered):
		return "tampered"
	default:
		return "error"
	}
}

// afterUnlock runs with unlockMu held and the vault unlocked: integrity keys,
// ledger verification against the stored checkpoint, new session.
func (d *Daemon) afterUnlock(method string) error {
	keys, created, err := d.loadIntegrityKeys()
	if err != nil {
		d.vault.Lock()
		d.log.Error("cannot load integrity keys", "err", err)
		return statusErr(500, client.CodeInternal, "cannot load integrity keys")
	}
	d.withAudit(func(l *audit.Log) { l.SetAnchorKey(keys.anchor.Bytes()) })
	d.ledger.SetMACKey(keys.ledger.Bytes())

	var problems []string
	st, exists, serr := loadStateFile(filepath.Join(d.dataDir, StateFile), keys.state.Bytes(), d.vault.ID())
	if serr != nil {
		problems = append(problems, "state.json: "+serr.Error())
	}
	nonEmpty, lerr := ledgerHasRecords(filepath.Join(d.dataDir, LedgerDir))
	if lerr != nil {
		problems = append(problems, "ledger: cannot list files")
	}
	if nonEmpty && !exists && serr == nil {
		problems = append(problems, "state.json is missing but the ledger has records")
	}
	if nonEmpty && created {
		problems = append(problems, "the integrity key was missing from the vault")
	}
	var cp *budget.Checkpoint
	if exists && serr == nil {
		cp = st.Checkpoint
	}
	in, verr := d.ledger.VerifyIntegrity(keys.ledger.Bytes(), budget.VerifyOptions{Checkpoint: cp})
	if verr != nil {
		problems = append(problems, "ledger verification error")
	} else if !in.OK() {
		problems = append(problems, in.Problems...)
		if len(in.Problems) == 0 {
			problems = append(problems, "ledger integrity check failed")
		}
	}

	now := d.clk.Now()
	sid := newID("s_")
	d.mu.Lock()
	d.st.keys = keys
	d.st.session = sid
	d.st.leaseUntil = now.Add(d.cfg.Presence.MaxLease.Duration)
	d.st.rollback = false
	d.st.integrityOK = len(problems) == 0
	d.st.integrityMsg = "ok"
	if !d.st.integrityOK {
		d.st.integrityMsg = "failed"
	}
	for _, m := range st.ModelsSeen {
		d.st.modelsSeen[m] = true
	}
	d.st.lastAnchor, d.st.lastSave, d.st.lastExpire = now, now, now
	for _, sc := range d.sessionScopesLocked() {
		d.ledger.ResetSession(sc)
	}
	d.ledger.ResetSession(budgetSessionScope(sid))
	d.st.state = StateUnlocked
	switch {
	case !d.st.integrityOK:
		d.st.state, d.st.tripReason, d.st.tripDetail = StateTripped, TripIntegrity, "ledger or state verification failed"
	case d.ledger.Tripped():
		d.st.state, d.st.tripReason, d.st.tripDetail = StateTripped, TripVelocity, "tripwire still active"
	case d.isAuditBroken():
		d.st.state, d.st.tripReason, d.st.tripDetail = StateTripped, TripAudit, "audit log cannot be written"
	case d.st.screenLocked && d.cfg.Presence.ScreenLock == "lock":
		// Should not happen (the unlock came from this session) but fail
		// towards the tighter state.
		d.enterAwayLocked(now, "screen_lock")
	case d.st.idle || d.st.screenLocked:
		d.enterAwayLocked(now, "idle")
	}
	state := d.st.state
	d.mu.Unlock()

	d.auditEvent("unlock", map[string]any{
		"ok": true, "method": method, "session": sid, "state": string(state),
		"recovered_from_prev": d.vault.RecoveredFromPrev(), "integrity_ok": len(problems) == 0,
	})
	if len(problems) > 0 {
		if len(problems) > 8 {
			problems = problems[:8]
		}
		d.log.Error("integrity verification failed after unlock; daemon tripped", "problems", problems)
		d.auditEvent("trip", map[string]any{"reason": TripIntegrity, "problems": problems})
	}
	d.anchor()
	d.saveState()
	return nil
}

// sessionScopesLocked lists the scopes whose session windows restart on
// unlock: every scope with a configured session-window limit.
func (d *Daemon) sessionScopesLocked() []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range d.buildLimitsLocked() {
		if l.Window == budget.WindowSession && l.Scope != budget.ScopeAway && !seen[l.Scope] {
			seen[l.Scope] = true
			out = append(out, l.Scope)
		}
	}
	return out
}

func budgetSessionScope(id string) string { return budget.ScopeSessionPrefix + id }

// ---- lock / panic / trip / resume ------------------------------------------

// lock performs any → Locked: no new reservations, in-flight ones are
// settled at their reserved amount (so every record is written while the MAC
// key is still set), the checkpoint is saved, the audit anchored, and then the
// vault and every derived key are wiped.
func (d *Daemon) lock(reason string) {
	d.unlockMu.Lock()
	defer d.unlockMu.Unlock()
	d.lockHeld(reason)
}

func (d *Daemon) lockHeld(reason string) {
	d.mu.Lock()
	if d.st.state == StateLocked {
		d.mu.Unlock()
		d.vault.Lock()
		return
	}
	prev, sid := d.st.state, d.st.session
	d.st.state = StateLocked
	d.st.session = ""
	d.st.awaySince = time.Time{}
	d.st.leaseUntil = time.Time{}
	d.st.grant = nil
	d.st.overlays = nil
	d.applyLimitsLocked()
	d.mu.Unlock()

	// Admit holds d.mu (read) across its state check and Reserve, so no
	// reservation can start after this point.
	if n, err := d.ledger.ExpireInFlight(-1); err != nil {
		d.log.Warn("settling in-flight reservations on lock", "err", err)
	} else if n > 0 {
		d.log.Info("in-flight requests charged at their reserved amount on lock", "count", n)
	}
	d.saveState()
	d.auditEvent("lock", map[string]any{"reason": reason, "from": string(prev), "session": sid})
	d.anchor()

	d.withAudit(func(l *audit.Log) { l.ClearAnchorKey() })
	d.ledger.SetMACKey(nil)
	d.vault.Lock()
	d.mu.Lock()
	d.st.keys.destroy()
	d.st.keys = nil
	d.mu.Unlock()
	d.log.Info("locked", "reason", reason)
}

// panicLock revokes every pass and locks.
func (d *Daemon) panicLock(revokeUpstream bool) (int, error) {
	n, rerr := d.passes.RevokeAll()
	d.auditEvent("panic", map[string]any{"passes_revoked": n, "revoke_upstream": revokeUpstream})
	d.lock("panic")
	d.mu.Lock()
	d.applyLimitsLocked()
	d.mu.Unlock()
	return n, rerr
}

// trip moves Unlocked/Away to Tripped. It must not be called with d.mu held.
func (d *Daemon) trip(reason, detail string) {
	d.mu.Lock()
	changed := false
	if d.st.state == StateUnlocked || d.st.state == StateAway {
		d.st.state = StateTripped
		d.st.tripReason, d.st.tripDetail = reason, detail
		changed = true
	}
	d.mu.Unlock()
	if changed {
		d.log.Warn("tripped", "reason", reason, "detail", detail)
		d.auditEvent("trip", map[string]any{"reason": reason, "detail": detail})
	}
}

// resume leaves Tripped after a step-up approval.
func (d *Daemon) resume(ctx context.Context) error {
	d.mu.RLock()
	state, reason, detail := d.st.state, d.st.tripReason, d.st.tripDetail
	d.mu.RUnlock()
	if state != StateTripped {
		return statusErr(409, client.CodeConflict, "not tripped")
	}
	dec, err := d.stepUp(ctx, approval.Request{
		Kind: "resume", Title: "Resume keyleash", Detail: "Tripped: " + reason + " (" + detail + ")",
		CoalesceKey: "resume",
	})
	if err != nil {
		return err
	}
	if d.isAuditBroken() {
		if err := d.reopenAudit(); err != nil {
			return statusErr(503, client.CodeInternal, "the audit log still cannot be written; fix the disk and retry")
		}
	}
	d.ledger.ResetTrip()
	now := d.clk.Now()
	d.mu.Lock()
	if d.st.state != StateTripped {
		d.mu.Unlock()
		return nil
	}
	accepted := !d.st.integrityOK
	d.st.integrityOK = true
	if accepted {
		d.st.integrityMsg = "accepted by owner after failure"
	}
	d.st.state, d.st.tripReason, d.st.tripDetail = StateUnlocked, "", ""
	if d.st.idle || d.st.screenLocked {
		d.enterAwayLocked(now, "idle")
	}
	d.mu.Unlock()
	d.auditEvent("resume", map[string]any{"approved_by": dec.Method, "reason": reason, "integrity_accepted": accepted})
	d.saveState()
	return nil
}

// stepUp asks the approval queue and maps the outcome to admin errors.
func (d *Daemon) stepUp(ctx context.Context, req approval.Request) (approval.Decision, error) {
	dec, err := d.queue.Request(ctx, req)
	d.auditEvent("approval", map[string]any{
		"kind": req.Kind, "approved": dec.Approved && err == nil, "method": dec.Method,
		"pass": req.PassID, "model": req.Model, "amount_micros": int64(req.Amount),
	})
	switch {
	case errors.Is(err, approval.ErrTimeout):
		return dec, statusErr(403, client.CodeStepUpTimeout, "step-up approval timed out")
	case err != nil && ctx.Err() != nil:
		return dec, ctx.Err()
	case err != nil || !dec.Approved:
		return dec, statusErr(403, client.CodeStepUpDenied, "step-up approval denied")
	}
	return dec, nil
}

// ---- presence --------------------------------------------------------------

// enterAwayLocked: Unlocked → Away. Caller holds d.mu.
func (d *Daemon) enterAwayLocked(now time.Time, cause string) {
	if d.st.state != StateUnlocked {
		return
	}
	d.st.state = StateAway
	d.st.awaySince = now
	d.ledger.ResetSession(budget.ScopeAway)
	d.auditEvent("away", map[string]any{"cause": cause, "session": d.st.session})
}

func (d *Daemon) leaveAwayLocked() {
	if d.st.state != StateAway {
		return
	}
	d.st.state = StateUnlocked
	d.st.awaySince = time.Time{}
	d.auditEvent("present", map[string]any{"session": d.st.session})
}

// onPresence applies one presence event (called on the monitor goroutine).
func (d *Daemon) onPresence(ev presence.Event) {
	now := d.clk.Now()
	lockReason := ""
	d.mu.Lock()
	switch ev.Kind {
	case presence.Idle:
		d.st.idle = true
		d.enterAwayLocked(now, "idle")
	case presence.Active:
		d.st.idle = false
		if !d.st.screenLocked {
			d.leaveAwayLocked()
		}
	case presence.ScreenLocked:
		d.st.screenLocked = true
		if d.st.state != StateLocked {
			if d.cfg.Presence.ScreenLock == "lock" {
				lockReason = "screen_lock"
			} else {
				d.enterAwayLocked(now, "screen_lock")
			}
		}
	case presence.ScreenUnlocked:
		d.st.screenLocked = false
		if !d.st.idle {
			d.leaveAwayLocked()
		}
	case presence.Resumed:
		if d.st.state != StateLocked {
			lockReason = "resumed"
		}
	}
	d.mu.Unlock()
	if lockReason != "" {
		d.lock(lockReason)
	}
}

// stepPresence polls the presence source once (tests; production runs the
// monitor on its own goroutine).
func (d *Daemon) stepPresence() { d.monitor.Step(d.onPresence) }

// ---- housekeeping ----------------------------------------------------------

// housekeep runs once a second: lease and away expiry, grant and overlay
// expiry, audit flush and anchors, checkpoint saves, stale reservations and
// run passes whose process has exited.
func (d *Daemon) housekeep() {
	now := d.clk.Now()
	lockReason := ""
	var anchorDue, saveDue, expireDue, sweepDue bool
	d.mu.Lock()
	st := d.st.state
	if st != StateLocked {
		if !d.st.leaseUntil.IsZero() && !now.Before(d.st.leaseUntil) {
			lockReason = "lease_expired"
		}
		if st == StateAway && lockReason == "" {
			limit := d.st.awaySince.Add(d.cfg.Presence.AwayMax.Duration)
			if g := d.st.grant; g != nil && g.until.After(limit) {
				limit = g.until
			}
			if !now.Before(limit) {
				lockReason = "away_max"
			}
		}
	}
	changed := false
	if g := d.st.grant; g != nil && !now.Before(g.until) {
		d.st.grant = nil
		changed = true
		d.auditEvent("limit_change", map[string]any{"change": "grant_expired", "grant": g.id})
	}
	kept := d.st.overlays[:0]
	for _, o := range d.st.overlays {
		if now.Before(o.until) {
			kept = append(kept, o)
		} else {
			changed = true
		}
	}
	d.st.overlays = kept
	if changed {
		d.applyLimitsLocked()
	}
	if d.st.keys != nil {
		anchorDue = d.cfg.Audit.AnchorEvery.Duration > 0 && now.Sub(d.st.lastAnchor) >= d.cfg.Audit.AnchorEvery.Duration
		saveDue = now.Sub(d.st.lastSave) >= StateSaveEvery
		expireDue = now.Sub(d.st.lastExpire) >= expireEvery
		if expireDue {
			d.st.lastExpire = now
		}
	}
	if now.Sub(d.st.lastSweep) >= passSweepEvery {
		sweepDue = true
		d.st.lastSweep = now
	}
	d.mu.Unlock()

	if lockReason != "" {
		d.lock(lockReason)
		return
	}
	if expireDue {
		if n, err := d.ledger.ExpireInFlight(InFlightMaxAge); err != nil {
			d.log.Warn("expiring stale reservations", "err", err)
		} else if n > 0 {
			d.log.Warn("stale in-flight reservations charged at their reserved amount", "count", n)
		}
	}
	if sweepDue {
		d.sweepRunPasses()
	}
	if anchorDue {
		d.anchor()
	}
	if saveDue {
		d.saveState()
	}
	d.withAudit(func(l *audit.Log) {
		if err := l.Flush(); err != nil {
			d.markAuditBroken(err)
		}
	})
}

// ---- audit helpers ---------------------------------------------------------

func (d *Daemon) withAudit(fn func(l *audit.Log)) {
	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	fn(d.audit)
}

func (d *Daemon) isAuditBroken() bool {
	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	return d.auditBroken
}

// auditEvent appends one record. A record the log rejects as malformed or
// secret-looking is a programming error (logged, not fatal). Any other
// failure is a write failure: the audit record is the point, so the daemon
// stops serving (Tripped) until the log can be reopened. Never call trip
// synchronously from here: callers may hold d.mu.
func (d *Daemon) auditEvent(typ string, fields map[string]any) {
	d.auditMu.Lock()
	err := d.audit.Append(typ, fields)
	d.auditMu.Unlock()
	if err == nil {
		return
	}
	if errors.Is(err, audit.ErrClosed) {
		return // shutting down
	}
	if errors.Is(err, audit.ErrSecret) || errors.Is(err, audit.ErrTooLarge) {
		d.log.Error("audit record rejected", "type", typ, "err", err)
		return
	}
	d.markAuditBroken(err)
}

func (d *Daemon) markAuditBroken(err error) {
	d.auditMu.Lock()
	already := d.auditBroken
	d.auditBroken = true
	d.auditMu.Unlock()
	if !already {
		d.log.Error("audit log write failed; tripping", "err", err)
		go d.trip(TripAudit, "audit log write failed")
	}
}

// reopenAudit replaces a broken audit log with a freshly opened one.
func (d *Daemon) reopenAudit() error {
	// Copy the anchor key first: the lock order is d.mu before auditMu.
	var key []byte
	d.mu.RLock()
	if d.st.keys != nil {
		key = append([]byte(nil), d.st.keys.anchor.Bytes()...)
	}
	d.mu.RUnlock()
	defer secmem.Wipe(key)

	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	d.audit.Close()
	l, err := audit.Open(filepath.Join(d.dataDir, AuditDir), d.clk)
	if err != nil {
		return err
	}
	if key != nil {
		l.SetAnchorKey(key)
	}
	d.audit = l
	d.auditBroken = false
	return nil
}

// anchor writes an anchor record (no-op while locked).
func (d *Daemon) anchor() {
	d.auditMu.Lock()
	err := d.audit.Anchor()
	d.auditMu.Unlock()
	if err != nil && !errors.Is(err, audit.ErrNoAnchorKey) {
		d.markAuditBroken(err)
		return
	}
	d.mu.Lock()
	d.st.lastAnchor = d.clk.Now()
	d.mu.Unlock()
}

// saveState stores the ledger checkpoint in state.json (MAC'd). It is a
// no-op while locked or while an integrity failure is unresolved.
func (d *Daemon) saveState() {
	if err := d.ledger.Flush(); err != nil {
		d.log.Warn("ledger flush before checkpoint", "err", err)
	}
	now := d.clk.Now()
	d.mu.Lock()
	d.st.lastSave = now
	d.mu.Unlock()

	// A read lock keeps the keys alive (they are destroyed under the write
	// lock) without blocking request admission.
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.st.keys == nil || !d.st.integrityOK {
		return
	}
	models := make([]string, 0, len(d.st.modelsSeen))
	for m := range d.st.modelsSeen {
		models = append(models, m)
	}
	cp := d.ledger.Checkpoint()
	body := stateBody{Version: 1, VaultID: d.vault.ID(), Saved: now.UTC(), Checkpoint: &cp, ModelsSeen: models}
	if err := saveStateFile(filepath.Join(d.dataDir, StateFile), d.st.keys.state.Bytes(), body); err != nil {
		d.log.Error("saving state.json failed", "err", err)
	}
}

// ---- vault re-key ----------------------------------------------------------

// rekey runs a re-keying vault operation (RemoveSlot, RotateRecovery). The
// daemon's integrity keys come from a vault entry (see integrity.go), which
// a re-key re-seals, so they stay valid; the change is recorded and the chain
// anchored before and after.
func (d *Daemon) rekey(op string, fn func() error) error {
	d.unlockMu.Lock()
	defer d.unlockMu.Unlock()
	if !d.vault.IsUnlocked() {
		return statusErr(423, client.CodeLocked, "vault is locked")
	}
	d.anchor()
	err := fn()
	if errors.Is(err, vault.ErrPrevNotScrubbed) {
		d.mu.Lock()
		d.st.prevNotScrubbed = true
		d.mu.Unlock()
	}
	ok := err == nil || errors.Is(err, vault.ErrPrevNotScrubbed)
	d.auditEvent("rekey", map[string]any{"op": op, "ok": ok, "prev_scrubbed": err == nil})
	if ok {
		d.auditEvent("slot_change", map[string]any{"op": op})
	}
	d.anchor()
	return err
}

// destroy wipes all derived keys. Safe on nil.
func (k *integrityKeys) destroy() {
	if k == nil {
		return
	}
	k.anchor.Destroy()
	k.ledger.Destroy()
	k.state.Destroy()
}
