package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/approval"
	"github.com/h-a-forster/keyleash/internal/audit"
	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/pass"
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
	// TripAuditIntegrity: audit.Verify failed after unlock (chain or anchor).
	TripAuditIntegrity = "audit_integrity"
	// TripConfig: config.toml changed since the last accepted config.
	TripConfig = "config_changed"
	// TripPassStore: passes.json does not match the baseline in the vault
	// (forged, edited or rolled back) or could not be checked.
	TripPassStore = "pass_store"
)

// ownerTrip reports trip reasons whose resume must be approved with the
// approval method of the last accepted config (spec §14).
func ownerTrip(reason string) bool {
	switch reason {
	case TripIntegrity, TripAuditIntegrity, TripPassStore, TripConfig:
		return true
	}
	return false
}

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

	grant *grantInfo
	// passGrants are allowances carried by over-limit approvals, each
	// scoped to the requesting pass and one exceeded limit.
	passGrants []passGrant

	// configChanges lists config keys changed since the last accepted
	// config; configPending is that config, accepted by resume.
	configChanges []string
	configPending *pendingConfig
	// auditBad is set when audit.Verify failed after unlock; resume
	// archives the rejected log and starts a new chain.
	auditBad bool
	// passDiff is set while passes.json does not match the vault's
	// baseline; resume revokes the added and changed passes and
	// re-baselines. The store's MAC key is not set meanwhile.
	passDiff *pass.Diff
	// acceptedMethod is approval.method of the last accepted config.
	acceptedMethod string
	// rollbackFileSeq/RecordedSeq describe the last rollback detected or
	// accepted at unlock; rollbackAccepted marks an accepted one.
	rollbackFileSeq, rollbackRecordedSeq uint64
	rollbackAccepted                     bool

	keys *integrityKeys
	// integrityOK is false after a failed ledger/state verification until
	// the owner approves a resume; the checkpoint is not saved meanwhile.
	integrityOK  bool
	integrityMsg string

	rollback        bool
	prevNotScrubbed bool

	lastAnchor, lastSave, lastExpire, lastSweep, lastCheckpoint time.Time

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

// passGrant lets one pass exceed one limit by up to amount until until: its
// reservations skip that limit and count against scope grant:<id> instead
// (spec §9). It comes only from an approval decided with a vault secret.
type passGrant struct {
	id     string
	pass   string
	scope  string
	window budget.Window
	amount money.Micros
	until  time.Time
}

// pendingConfig is a changed config awaiting the owner's acceptance.
type pendingConfig struct{ hash, toml string }

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
//
// With acceptRollback (an explicit owner request, `keyleash unlock
// --accept-rollback`), a vault file older than the anti-rollback record is
// accepted by this one unlock (not with DPAPI, which proves no presence);
// the sequence regression is reported and audited.
func (d *Daemon) unlock(ctx context.Context, method string, secret []byte, acceptRollback bool) error {
	d.unlockMu.Lock()
	defer d.unlockMu.Unlock()
	if d.State() != StateLocked {
		return statusErr(409, client.CodeConflict, "already unlocked")
	}
	if acceptRollback {
		if method == client.MethodDPAPI {
			return statusErr(400, client.CodeBadRequest, "a rollback can only be accepted with the passphrase, recovery code or Windows Hello")
		}
		d.vault.SetAcceptRollback(true)
		defer d.vault.SetAcceptRollback(false)
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
			var re *vault.RollbackError
			d.mu.Lock()
			d.st.rollback = true
			d.st.rollbackAccepted = false
			if errors.As(err, &re) {
				d.st.rollbackFileSeq, d.st.rollbackRecordedSeq = re.FileSeq, re.RecordedSeq
			}
			d.mu.Unlock()
			if re != nil {
				return statusErr(409, client.CodeRollback, "%v: the vault file is at write %d but write %d was recorded; if you restored an older vault on purpose, run `keyleash unlock --accept-rollback`", vault.ErrRollback, re.FileSeq, re.RecordedSeq)
			}
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
	if acc := d.vault.AcceptedRollback(); acceptRollback && acc != nil {
		d.mu.Lock()
		d.st.rollbackFileSeq, d.st.rollbackRecordedSeq, d.st.rollbackAccepted = acc.FileSeq, acc.RecordedSeq, true
		d.mu.Unlock()
		d.log.Warn("accepted a rolled-back vault file", "file_seq", acc.FileSeq, "recorded_seq", acc.RecordedSeq)
		d.auditEvent("accept_rollback", map[string]any{"method": method, "file_seq": acc.FileSeq, "recorded_seq": acc.RecordedSeq})
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
// ledger verification against the checkpoint stored in the vault, audit
// chain and anchor verification, the config check, and a new session.
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
	vs, vsExists, vserr := d.loadVaultState()
	if vserr != nil {
		problems = append(problems, "the daemon state in the vault cannot be read")
		vs = &vaultState{Version: 1, ActiveKeys: map[string]string{}}
		d.vsMu.Lock()
		d.vs = vs.clone()
		d.vsMu.Unlock()
	} else if !vsExists {
		// A vault from before the daemon-state entry: start the entry.
		d.vsMu.Lock()
		d.vs = vs.clone()
		d.vsMu.Unlock()
	}
	// state.json holds only non-security bookkeeping now; a checkpoint in
	// it is used once, to migrate a vault without the daemon-state entry.
	st, stExists, serr := loadStateFile(filepath.Join(d.dataDir, StateFile), keys.state.Bytes(), d.vault.ID())
	if serr != nil {
		d.log.Warn("state.json ignored", "err", serr)
		st, stExists = stateBody{}, false
	}
	nonEmpty, lerr := ledgerHasRecords(filepath.Join(d.dataDir, LedgerDir))
	if lerr != nil {
		problems = append(problems, "ledger: cannot list files")
	}
	if nonEmpty && created {
		problems = append(problems, "the integrity key was missing from the vault")
	}
	var cp *budget.Checkpoint
	switch {
	case vsExists && vserr == nil:
		cp = vs.Checkpoint
		if cp == nil && nonEmpty {
			problems = append(problems, "the ledger has records but the vault holds no checkpoint")
		}
	case !vsExists && stExists && st.Checkpoint != nil:
		cp = st.Checkpoint
	case !vsExists && nonEmpty:
		problems = append(problems, "the ledger checkpoint is missing but the ledger has records")
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

	// The audit chain and its anchors (spec §11), with the anchor key.
	var auditProblem string
	d.withAudit(func(l *audit.Log) {
		if ferr := l.Flush(); ferr != nil {
			auditProblem = "audit log cannot be flushed"
			return
		}
		rep, aerr := audit.Verify(filepath.Join(d.dataDir, AuditDir), keys.anchor.Bytes())
		switch {
		case rep.FirstBad != nil:
			auditProblem = rep.FirstBad.String()
		case aerr != nil:
			auditProblem = "audit verification could not complete"
		}
	})

	// passes.json against the baseline in the vault (spec §6). The MAC key
	// stays unset while they disagree, so nothing re-baselines the
	// tampered content before the owner resumes.
	d.passes.SetMACKey(nil)
	var passDiff *pass.Diff
	if vserr != nil {
		passDiff = d.unverifiedPassDiff()
	} else {
		d.passes.SetMACKey(keys.passes.Bytes())
		diff, perr := d.passes.VerifyAgainst(vs.PassStore)
		switch {
		case perr != nil:
			d.passes.SetMACKey(nil)
			passDiff = d.unverifiedPassDiff()
		case !diff.OK:
			d.passes.SetMACKey(nil)
			passDiff = &diff
		default:
			// Record the baseline (and fold in revocations made while
			// locked) with an authenticated write.
			if err := d.passes.Commit(); err != nil {
				d.log.Error("re-baselining passes.json failed", "err", err)
			}
		}
	}

	// The approval method of the last accepted config: resumes from
	// owner trips are approved with it (spec §14).
	accMethod := ""
	if vserr == nil {
		accMethod = vs.ApprovalMethod
		if accMethod == "" && vs.ConfigTOML != "" {
			accMethod = config.ApprovalMethodOf(vs.ConfigTOML)
		}
		if accMethod == "" && vs.ConfigHash == "" {
			accMethod = d.cfg.Approval.Method // first acceptance below
		}
	}

	// A vault from before keys_ever_added: derive it from the entries.
	if vserr == nil && !vs.KeysEverAdded && d.vaultHasAPIKey() {
		if err := d.updateVaultState(func(s *vaultState) { s.KeysEverAdded = true }); err != nil {
			d.log.Error("recording keys_ever_added failed", "err", err)
		}
	}

	// The effective config against the last accepted one (spec §14),
	// including the pricing override file's path and content hash.
	var changes []string
	var pending *pendingConfig
	curTOML, cerr := d.acceptedConfigText()
	curHash := hashText(curTOML)
	var herr error
	if cerr != nil || herr != nil {
		problems = append(problems, "cannot encode the effective config")
	} else if vs.ConfigHash != "" && vs.ConfigHash != curHash {
		pending = &pendingConfig{hash: curHash, toml: curTOML}
		var derr error
		if changes, derr = config.Diff(vs.ConfigTOML, curTOML); derr != nil || len(changes) == 0 {
			changes = []string{"config.toml changed (details unavailable)"}
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
	d.st.auditBad = auditProblem != ""
	d.st.configChanges, d.st.configPending = changes, pending
	d.st.passDiff = passDiff
	d.st.acceptedMethod = accMethod
	if !d.st.rollbackAccepted {
		d.st.rollbackFileSeq, d.st.rollbackRecordedSeq = 0, 0
	}
	for _, m := range st.ModelsSeen {
		d.st.modelsSeen[m] = true
	}
	d.st.lastAnchor, d.st.lastSave, d.st.lastExpire, d.st.lastCheckpoint = now, now, now, now
	for _, sc := range d.sessionScopesLocked() {
		d.ledger.ResetSession(sc)
	}
	d.ledger.ResetSession(budgetSessionScope(sid))
	d.st.state = StateUnlocked
	switch {
	case !d.st.integrityOK:
		d.st.state, d.st.tripReason, d.st.tripDetail = StateTripped, TripIntegrity, "ledger or state verification failed"
	case d.st.auditBad:
		d.st.state, d.st.tripReason, d.st.tripDetail = StateTripped, TripAuditIntegrity, "audit log verification failed"
	case passDiff != nil:
		d.st.state, d.st.tripReason, d.st.tripDetail = StateTripped, TripPassStore, "passes.json does not match the record in the vault"
	case pending != nil:
		d.st.state, d.st.tripReason, d.st.tripDetail = StateTripped, TripConfig, "config.toml changed since it was last accepted"
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

	// While a changed config is unaccepted, approvals use the accepted
	// config's method, never the one the changed file names.
	if pending != nil {
		d.queue.SetApprover(d.approverFor(accMethod, false))
	} else {
		d.queue.SetApprover(d.configured)
	}

	d.auditEvent("unlock", map[string]any{
		"ok": true, "method": method, "session": sid, "state": string(state),
		"recovered_from_prev": d.vault.RecoveredFromPrev(), "integrity_ok": len(problems) == 0,
		"audit_ok": auditProblem == "", "config_changed": pending != nil, "pass_store_ok": passDiff == nil,
	})
	if passDiff != nil {
		ch := passStoreChanges(passDiff)
		d.log.Error("passes.json does not match the vault; daemon tripped until `keyleash resume`", "changes", ch)
		d.auditEvent("pass_store", map[string]any{"changes": ch, "mac_ok": passDiff.MACOK,
			"counter": passDiff.Counter, "baseline": passDiff.Baseline})
		if len(problems) == 0 && auditProblem == "" {
			d.auditEvent("trip", map[string]any{"reason": TripPassStore})
		}
	}
	if len(problems) > 0 {
		if len(problems) > 8 {
			problems = problems[:8]
		}
		d.log.Error("integrity verification failed after unlock; daemon tripped", "problems", problems)
		d.auditEvent("trip", map[string]any{"reason": TripIntegrity, "problems": problems})
	}
	if auditProblem != "" {
		d.log.Error("audit log verification failed after unlock; daemon tripped", "problem", auditProblem)
		d.auditEvent("trip", map[string]any{"reason": TripAuditIntegrity, "problem": auditProblem})
	}
	if pending != nil {
		d.log.Warn("config.toml changed since it was last accepted; daemon tripped until `keyleash resume`", "changes", changes)
		d.auditEvent("config_change", map[string]any{"changes": changes, "accepted": false})
		if len(problems) == 0 && auditProblem == "" && passDiff == nil {
			d.auditEvent("trip", map[string]any{"reason": TripConfig})
		}
	}
	// First unlock (or a migrated vault): record the config as accepted.
	if cerr == nil && herr == nil && vserr == nil && (vs.ConfigHash == "" || !vsExists) {
		m := d.cfg.Approval.Method
		if err := d.updateVaultState(func(s *vaultState) {
			s.ConfigHash, s.ConfigTOML, s.ApprovalMethod = curHash, curTOML, m
		}); err != nil {
			d.log.Error("recording the config in the vault failed", "err", err)
		}
	} else if cerr == nil && vserr == nil && vs.ApprovalMethod == "" && accMethod != "" {
		// Migration: record the accepted config's method.
		if err := d.updateVaultState(func(s *vaultState) { s.ApprovalMethod = accMethod }); err != nil {
			d.log.Error("recording the approval method in the vault failed", "err", err)
		}
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
	d.st.passGrants = nil
	d.st.configChanges, d.st.configPending, d.st.auditBad = nil, nil, false
	d.st.passDiff = nil
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
	d.passes.SetMACKey(nil)
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

// resume leaves Tripped after a step-up approval. It also accepts what the
// trip reported: a failed ledger verification (the current ledger becomes
// the checkpoint), a failed audit verification (the rejected log is moved to
// audit/rejected-<time>/ and a new chain starts) and a changed config (it
// becomes the accepted config).
func (d *Daemon) resume(ctx context.Context) error {
	d.mu.RLock()
	state, reason := d.st.state, d.st.tripReason
	changes := append([]string(nil), d.st.configChanges...)
	passDiff, accMethod := d.st.passDiff, d.st.acceptedMethod
	owner := ownerTrip(reason) || passDiff != nil || d.st.configPending != nil || !d.st.integrityOK || d.st.auditBad
	d.mu.RUnlock()
	if state != StateTripped {
		return statusErr(409, client.CodeConflict, "not tripped")
	}
	det, note := resumeSummary(reason, changes, passDiff)
	req := approval.Request{Kind: "resume", Title: "Resume keyleash", Detail: det, Note: note}
	var dec approval.Decision
	var err error
	if owner {
		// Approved with the accepted config's method (never the console,
		// and never a method a changed config.toml names).
		dec, err = d.stepUpWith(ctx, d.approverFor(accMethod, true), req)
	} else {
		dec, err = d.stepUp(ctx, req)
	}
	if err != nil {
		return err
	}
	if d.isAuditBroken() {
		if err := d.reopenAudit(); err != nil {
			return statusErr(503, client.CodeInternal, "the audit log still cannot be written; fix the disk and retry")
		}
	}
	d.mu.RLock()
	auditBad, pending := d.st.auditBad, d.st.configPending
	d.mu.RUnlock()
	archived := ""
	if auditBad {
		var aerr error
		if archived, aerr = d.archiveAudit(); aerr != nil {
			d.log.Error("archiving the rejected audit log failed", "err", aerr)
			return statusErr(503, client.CodeInternal, "the rejected audit log could not be archived; check the data directory and retry")
		}
	}
	var passRevoked []string
	if passDiff != nil {
		var perr error
		if passRevoked, perr = d.rebaselinePasses(passDiff); perr != nil {
			d.log.Error("re-baselining passes.json failed", "err", perr)
			return statusErr(503, client.CodeInternal, "passes.json could not be re-baselined; check the data directory and retry")
		}
	}
	if pending != nil {
		m := d.cfg.Approval.Method
		if err := d.updateVaultState(func(s *vaultState) {
			s.ConfigHash, s.ConfigTOML, s.ApprovalMethod = pending.hash, pending.toml, m
		}); err != nil {
			d.log.Error("recording the accepted config failed", "err", err)
			return statusErr(503, client.CodeInternal, "the accepted config could not be recorded in the vault")
		}
		d.queue.SetApprover(d.configured)
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
	d.st.auditBad = false
	d.st.configChanges, d.st.configPending = nil, nil
	d.st.passDiff = nil
	if pending != nil {
		d.st.acceptedMethod = d.cfg.Approval.Method
	}
	d.st.state, d.st.tripReason, d.st.tripDetail = StateUnlocked, "", ""
	if d.st.idle || d.st.screenLocked {
		d.enterAwayLocked(now, "idle")
	}
	d.mu.Unlock()
	f := map[string]any{"approved_by": dec.Method, "reason": reason, "integrity_accepted": accepted}
	if archived != "" {
		f["audit_archived"] = archived
	}
	if pending != nil {
		f["config_accepted"] = changes
		d.auditEvent("config_change", map[string]any{"changes": changes, "accepted": true})
	}
	if passDiff != nil {
		f["pass_store_accepted"] = passStoreChanges(passDiff)
		f["passes_revoked"] = passRevoked
	}
	d.auditEvent("resume", f)
	d.saveState()
	return nil
}

// archiveAudit moves the current audit files to audit/rejected-<time>/ and
// starts a fresh chain (after the owner accepted a failed verification).
func (d *Daemon) archiveAudit() (string, error) {
	var key []byte
	d.mu.RLock()
	if d.st.keys != nil {
		key = append([]byte(nil), d.st.keys.anchor.Bytes()...)
	}
	d.mu.RUnlock()
	defer secmem.Wipe(key)

	dir := filepath.Join(d.dataDir, AuditDir)
	name := "rejected-" + d.clk.Now().UTC().Format("20060102T150405Z")
	d.auditMu.Lock()
	defer d.auditMu.Unlock()
	d.audit.Close()
	reopen := func() error {
		l, err := audit.Open(dir, d.clk)
		if err != nil {
			d.auditBroken = true
			return err
		}
		if key != nil {
			l.SetAnchorKey(key)
		}
		d.audit = l
		return nil
	}
	if err := os.MkdirAll(filepath.Join(dir, name), 0o700); err != nil {
		return "", errors.Join(err, reopen())
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", errors.Join(err, reopen())
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		if err := os.Rename(filepath.Join(dir, e.Name()), filepath.Join(dir, name, e.Name())); err != nil {
			return "", errors.Join(err, reopen())
		}
	}
	return filepath.Join(AuditDir, name), reopen()
}

// stepUp asks the approval queue for an admin step-up and maps the outcome
// to admin errors. Admin step-ups never coalesce (spec §9): only the caller
// whose request triggered the prompt proceeds. The verified caller PID is
// attached so the CLI can recognise its own request.
func (d *Daemon) stepUp(ctx context.Context, req approval.Request) (approval.Decision, error) {
	return d.stepUpWith(ctx, nil, req)
}

// stepUpWith is stepUp with a specific approver (nil: the queue's). The
// prompt names the requesting process; a request whose risk text would not
// fit the prompt is refused rather than truncated (spec §9).
func (d *Daemon) stepUpWith(ctx context.Context, a approval.Approver, req approval.Request) (approval.Decision, error) {
	req.CoalesceKey = ""
	req.Requester = callerFrom(ctx).pid
	req.RequesterName = "unknown process"
	if req.Requester > 0 {
		req.RequesterName = "pid " + strconv.Itoa(req.Requester)
		if p, err := d.lookupProcess(req.Requester); err == nil && p.Image != "" {
			req.RequesterName = filepath.Base(p.Image)
		}
	}
	if err := approval.Fits(req); err != nil {
		return approval.Decision{}, statusErr(400, client.CodeBadRequest, "the approval prompt would be too long to show in full; request less at once")
	}
	dec, err := d.queue.RequestWith(ctx, a, req)
	d.auditEvent("approval", map[string]any{
		"kind": req.Kind, "approved": dec.Approved && err == nil, "method": dec.Method,
		"pass": req.PassID, "model": req.Model, "amount_micros": int64(req.Amount),
		"requester_pid": req.Requester, "requester": req.RequesterName, "detail": req.Detail,
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

// housekeep runs once a second: lease and away expiry, grant and pass-grant
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
	kept := d.st.passGrants[:0]
	for _, g := range d.st.passGrants {
		if now.Before(g.until) {
			kept = append(kept, g)
		} else {
			changed = true
			d.auditEvent("limit_change", map[string]any{"change": "pass_grant_expired", "grant": g.id, "pass": g.pass})
		}
	}
	d.st.passGrants = kept
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

// securityAuditTypes are record types whose loss is not acceptable: if the
// log rejects one even after sanitising, the daemon trips (spec §11).
var securityAuditTypes = map[string]bool{
	"request": true, "pass_issue": true, "approval": true, "unlock": true, "lock": true,
	"trip": true, "key_add": true, "key_remove": true, "slot_change": true,
}

// maxAuditString bounds one string field; longer values are cut.
const maxAuditString = 1024

// sanitizeAudit replaces every string that looks like a secret with
// audit.Redact's "[redacted:<hash prefix>]" and truncates overlong strings,
// so a caller-controlled value (client image, model, pass name, label,
// detail) cannot make Append drop a record.
func sanitizeAudit(v any) any {
	switch x := v.(type) {
	case string:
		s := audit.Redact(x)
		if len(s) > maxAuditString {
			s = strings.ToValidUTF8(s[:maxAuditString], "") + "...[truncated]"
		}
		return s
	case []string:
		out := make([]string, len(x))
		for i, s := range x {
			out[i] = sanitizeAudit(s).(string)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = sanitizeAudit(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = sanitizeAudit(e)
		}
		return out
	}
	return v
}

// auditEvent appends one record after sanitising its string fields. If the
// log still rejects it (secret-looking or too large), a security-relevant
// record type trips the daemon; other types are logged. Any other failure is
// a write failure: the audit record is the point, so the daemon stops
// serving (Tripped) until the log can be reopened. Never call trip
// synchronously from here: callers may hold d.mu.
func (d *Daemon) auditEvent(typ string, fields map[string]any) {
	_ = d.auditEventErr(typ, fields)
}

// auditEventErr is auditEvent that also reports whether the record was
// written, for operations that must not take effect unaudited.
func (d *Daemon) auditEventErr(typ string, fields map[string]any) error {
	if fields != nil {
		fields = sanitizeAudit(fields).(map[string]any)
	}
	d.auditMu.Lock()
	broken := d.auditBroken
	err := d.audit.Append(typ, fields)
	d.auditMu.Unlock()
	if err == nil && broken {
		err = errors.New("audit log marked broken")
	}
	if err == nil {
		return nil
	}
	if errors.Is(err, audit.ErrClosed) {
		return err // shutting down
	}
	if errors.Is(err, audit.ErrSecret) || errors.Is(err, audit.ErrTooLarge) {
		d.log.Error("audit record rejected", "type", typ, "err", err)
		if securityAuditTypes[typ] {
			go d.trip(TripAudit, "a security audit record ("+typ+") was rejected")
		}
		return err
	}
	d.markAuditBroken(err)
	return err
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

// saveState writes the ledger checkpoint into the daemon-state vault entry
// (spec §7.7) and the non-security bookkeeping into state.json (MAC'd). It
// is a no-op while locked or while an integrity failure is unresolved.
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
	if err := d.updateVaultState(func(s *vaultState) { s.Checkpoint = &cp }); err != nil {
		d.log.Error("saving the ledger checkpoint to the vault failed", "err", err)
	}
	body := stateBody{Version: 1, VaultID: d.vault.ID(), Saved: now.UTC(), ModelsSeen: models}
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
	k.passes.Destroy()
}
