package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/approval"
	"github.com/h-a-forster/keyleash/internal/audit"
	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/glob"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/procinfo"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/secmem"
	"github.com/h-a-forster/keyleash/internal/vault"
)

// Bounds on admin inputs.
const (
	maxGrantDuration = 7 * 24 * time.Hour
	maxPassTTL       = 365 * 24 * time.Hour
	maxAuditTail     = 1000
)

// adminHandler returns the admin API (docs/DAEMON.md table).
func (d *Daemon) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", d.hStatus)
	mux.HandleFunc("POST /v1/unlock", d.hUnlock)
	mux.HandleFunc("POST /v1/lock", d.hLock)
	mux.HandleFunc("POST /v1/panic", d.hPanic)
	mux.HandleFunc("POST /v1/shutdown", d.hShutdown)
	mux.HandleFunc("POST /v1/away", d.hAway)
	mux.HandleFunc("POST /v1/resume", d.hResume)
	mux.HandleFunc("GET /v1/passes", d.hPassList)
	mux.HandleFunc("POST /v1/passes", d.hPassCreate)
	mux.HandleFunc("DELETE /v1/passes", d.hPassRevoke)
	mux.HandleFunc("GET /v1/keys", d.hKeys)
	mux.HandleFunc("POST /v1/keys", d.hKeyAdd)
	mux.HandleFunc("DELETE /v1/keys/{id}", d.hKeyRemove)
	mux.HandleFunc("POST /v1/keys/{id}/use", d.hKeyUse)
	mux.HandleFunc("GET /v1/usage", d.hUsage)
	mux.HandleFunc("GET /v1/approvals", d.hApprovals)
	mux.HandleFunc("POST /v1/approvals/{id}", d.hDecide)
	mux.HandleFunc("GET /v1/audit/tail", d.hAuditTail)
	mux.HandleFunc("GET /v1/audit/verify", d.hAuditVerify)
	mux.HandleFunc("GET /v1/config", d.hConfig)
	mux.HandleFunc("POST /v1/vault/recovery", d.hRotateRecovery)
	mux.HandleFunc("DELETE /v1/vault/slots/{id}", d.hRemoveSlot)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *Daemon) writeErr(w http.ResponseWriter, err error) {
	var es *errStatus
	if !errors.As(err, &es) {
		if errors.Is(err, context.Canceled) {
			return
		}
		d.log.Error("admin request failed", "err", err)
		es = &errStatus{status: 500, code: client.CodeInternal, msg: "internal error"}
	}
	var b client.ErrorBody
	b.Error.Code, b.Error.Message = es.code, es.msg
	writeJSON(w, es.status, b)
}

// readBody reads a bounded JSON body into v. The raw bytes are wiped before
// returning, so secrets live only in v (which the caller wipes).
func readBody(r *http.Request, v any) error {
	raw, err := io.ReadAll(io.LimitReader(r.Body, adminBodyLimit+1))
	defer secmem.Wipe(raw)
	if err != nil {
		return statusErr(400, client.CodeBadRequest, "cannot read request body")
	}
	if len(raw) > adminBodyLimit {
		return statusErr(413, client.CodeBadRequest, "request body too large")
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = append(raw[:0], "{}"...)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return statusErr(400, client.CodeBadRequest, "malformed JSON body")
	}
	return nil
}

// requireServing fails unless the daemon is Unlocked or Away.
func (d *Daemon) requireServing() (State, error) {
	st := d.State()
	switch st {
	case StateLocked:
		return st, statusErr(423, client.CodeLocked, "keyleash is locked")
	case StateTripped:
		return st, statusErr(409, client.CodeConflict, "keyleash is tripped; run `keyleash resume`")
	}
	return st, nil
}

// ---- status / unlock / lock / panic ----------------------------------------

func (d *Daemon) status() client.Status {
	d.mu.RLock()
	s := client.Status{
		State: string(d.st.state), TripReason: d.st.tripReason, Session: d.st.session,
		LeaseUntil: d.st.leaseUntil, AwaySince: d.st.awaySince, Integrity: d.st.integrityMsg,
		ProxyAddr: d.proxyLn.Addr().String(),
	}
	if d.st.state == StateAway {
		until := d.st.awaySince.Add(d.cfg.Presence.AwayMax.Duration)
		if g := d.st.grant; g != nil && g.until.After(until) {
			until = g.until
		}
		s.AwayUntil = until
	}
	if g := d.st.grant; g != nil {
		s.Grant = &client.Grant{ID: g.id, Amount: g.amount, Until: g.until, Pass: g.pass}
	}
	s.Vault.RollbackDetected = d.st.rollback
	s.Vault.RollbackFileSeq, s.Vault.RollbackRecordedSeq = d.st.rollbackFileSeq, d.st.rollbackRecordedSeq
	s.Vault.RollbackAccepted = d.st.rollbackAccepted
	s.Vault.PrevNotScrubbed = d.st.prevNotScrubbed
	s.ConfigChanges = append([]string(nil), d.st.configChanges...)
	s.PassStoreChanges = passStoreChanges(d.st.passDiff)
	d.mu.RUnlock()

	for _, l := range d.ledger.Status() {
		s.Limits = append(s.Limits, client.LimitStatus{Scope: l.Scope, Window: string(l.Window), Limit: l.Amount,
			Settled: l.Settled, Reserved: l.Reserved, Remaining: l.Remaining})
	}
	for _, f := range d.ledger.InFlight() {
		s.InFlight = append(s.InFlight, client.InFlight{ID: f.ID, Pass: f.Meta.PassID, Provider: f.Meta.Provider,
			Model: f.Meta.Model, Client: f.Meta.Client, Amount: f.Amount, Age: f.Age})
	}
	if s.Limits == nil {
		s.Limits = []client.LimitStatus{}
	}
	if s.InFlight == nil {
		s.InFlight = []client.InFlight{}
	}
	if d.osSource != nil && d.osSource.Degraded() {
		s.PresenceDegraded, s.PresenceDegradedReason = true, d.osSource.DegradedReason()
	}
	s.Vault.ID, s.Vault.Seq, s.Vault.Unlocked = d.vault.ID(), d.vault.Seq(), d.vault.IsUnlocked()
	s.Vault.RecoveredFromPrev = d.vault.RecoveredFromPrev()
	s.Vault.Slots = []client.Slot{}
	for _, sl := range d.vault.Slots() {
		s.Vault.Slots = append(s.Vault.Slots, client.Slot{ID: sl.ID, Type: sl.Type, Label: sl.Label,
			Created: sl.Created, Convenience: sl.Convenience})
	}
	s.PendingApprovals = len(d.queue.Pending())
	s.ApprovalMethod = d.queue.Method()
	s.AuditHealthy = !d.isAuditBroken()
	if s.Vault.RecoveredFromPrev {
		s.Warnings = append(s.Warnings, "the vault was recovered from vault.prev after the main file was missing or corrupt")
	}
	if s.Vault.PrevNotScrubbed {
		s.Warnings = append(s.Warnings, "vault.prev still holds the old vault key after a re-key; delete it")
	}
	if s.Vault.RollbackDetected {
		s.Warnings = append(s.Warnings, "the vault file is older than the last recorded state (possible rollback)")
	}
	if s.Vault.RollbackAccepted {
		s.Warnings = append(s.Warnings, fmt.Sprintf("a rolled-back vault file (write %d, recorded write %d) was accepted at unlock; review slots and keys",
			s.Vault.RollbackFileSeq, s.Vault.RollbackRecordedSeq))
	}
	if len(s.PassStoreChanges) > 0 {
		s.Warnings = append(s.Warnings, "passes.json does not match the record in the vault; review the changes and run `keyleash resume` (added and changed passes are revoked)")
	}
	if s.PresenceDegraded {
		s.Warnings = append(s.Warnings, "presence detection is degraded: "+s.PresenceDegradedReason)
	}
	if len(s.ConfigChanges) > 0 {
		s.Warnings = append(s.Warnings, "config.toml changed since it was last accepted; review the changes and run `keyleash resume` to accept them")
	}
	return s
}

func (d *Daemon) hStatus(w http.ResponseWriter, _ *http.Request) {
	d.syncTrips()
	writeJSON(w, 200, d.status())
}

func (d *Daemon) hUnlock(w http.ResponseWriter, r *http.Request) {
	var req client.UnlockRequest
	err := readBody(r, &req)
	defer secmem.Wipe(req.Secret)
	if err != nil {
		d.writeErr(w, err)
		return
	}
	if err := d.unlock(r.Context(), req.Method, req.Secret, req.AcceptRollback); err != nil {
		d.writeErr(w, err)
		return
	}
	writeJSON(w, 200, d.status())
}

func (d *Daemon) hLock(w http.ResponseWriter, r *http.Request) {
	d.lock("admin")
	writeJSON(w, 200, d.status())
}

func (d *Daemon) hPanic(w http.ResponseWriter, r *http.Request) {
	var req client.PanicRequest
	if err := readBody(r, &req); err != nil {
		// A panic must never fail on a bad body: lock anyway.
		req = client.PanicRequest{}
	}
	n, err := d.panicLock(req.RevokeUpstream)
	sum := client.PanicSummary{Locked: true, PassesRevoked: n}
	if req.RevokeUpstream {
		sum.Note = "upstream key revocation is not implemented yet (spec §15); rotate the keys at the provider"
	}
	if err != nil {
		sum.Note = strings.TrimSpace(sum.Note + " passes are revoked in memory but saving passes.json failed")
	}
	sum.Status = d.status()
	writeJSON(w, 200, sum)
}

// hShutdown asks the daemon to stop (keyleash stop). Stopping locks the
// vault and ends every pass's use until the daemon runs again, so it needs
// no step-up (spec §9 reserves those for calls that weaken protection or
// spend more), but unlike lock and panic it is not open to every caller:
// the guard refuses confined and unidentified callers (spec §12). That is
// defence in depth, not a boundary: the daemon runs as the owner's user
// with no restrictive process DACL, so a confined process can simply kill
// it (which also locks the vault and spends nothing); the refusal only
// keeps such a stop from passing as an orderly, owner-requested one. The
// request is audited with the caller; the shutdown itself (docs/DAEMON.md
// "Shutdown") runs after the response is sent.
func (d *Daemon) hShutdown(w http.ResponseWriter, r *http.Request) {
	pid := callerFrom(r.Context()).pid
	name := "pid " + strconv.Itoa(pid)
	if p, err := d.lookupProcess(pid); err == nil && p.Image != "" {
		name = filepath.Base(p.Image)
	}
	d.auditEvent("shutdown", map[string]any{"requester_pid": pid, "requester": name})
	d.log.Info("shutdown requested over the admin channel", "requester_pid", pid)
	writeJSON(w, http.StatusAccepted, client.ShutdownResponse{Stopping: true})
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	d.requestStop()
}

// ---- away / resume ---------------------------------------------------------

func (d *Daemon) hAway(w http.ResponseWriter, r *http.Request) {
	var req client.AwayRequest
	if err := readBody(r, &req); err != nil {
		d.writeErr(w, err)
		return
	}
	if req.Budget <= 0 || req.For <= 0 || req.For > maxGrantDuration {
		d.writeErr(w, statusErr(400, client.CodeBadRequest, "budget must be positive and duration between 0 and 168h"))
		return
	}
	if mg := d.cfg.Limits.Away.MaxGrant; mg == nil || req.Budget > mg.Micros {
		capAmt := money.Micros(0)
		if mg != nil {
			capAmt = mg.Micros
		}
		d.writeErr(w, statusErr(400, client.CodeBadRequest, "budget exceeds limits.away.max_grant (%s)", capAmt))
		return
	}
	if req.Pass != "" {
		if p, ok := d.passes.Get(req.Pass); !ok || p.Revoked || p.Expired(d.clk.Now()) {
			d.writeErr(w, statusErr(404, client.CodeNotFound, "no such active pass"))
			return
		}
	}
	if _, err := d.requireServing(); err != nil {
		d.writeErr(w, err)
		return
	}
	detail := "Allow " + req.Budget.String() + " while away for " + req.For.String()
	if req.Pass != "" {
		detail += " (pass " + req.Pass + ")"
	} else {
		detail += " (any pass)"
	}
	if _, err := d.stepUp(r.Context(), approval.Request{Kind: "away_grant", Title: "Unattended grant",
		Detail: detail, Note: "approving grants exactly this; it is never combined with another request",
		PassID: req.Pass, Amount: req.Budget}); err != nil {
		d.writeErr(w, err)
		return
	}
	now := d.clk.Now()
	g := &grantInfo{id: newID("g_"), amount: req.Budget, until: now.Add(req.For), pass: req.Pass}
	d.mu.Lock()
	if d.st.state != StateUnlocked && d.st.state != StateAway {
		d.mu.Unlock()
		d.writeErr(w, statusErr(409, client.CodeConflict, "keyleash locked or tripped during approval"))
		return
	}
	d.st.grant = g
	if g.until.After(d.st.leaseUntil) {
		d.st.leaseUntil = g.until
	}
	d.applyLimitsLocked()
	d.ledger.ResetSession(budget.ScopeGrantPrefix + g.id)
	d.mu.Unlock()
	d.auditEvent("limit_change", map[string]any{"change": "grant", "grant": g.id, "amount_micros": int64(g.amount),
		"until": g.until.UTC().Format(time.RFC3339), "pass": g.pass})
	writeJSON(w, 200, client.Grant{ID: g.id, Amount: g.amount, Until: g.until, Pass: g.pass})
}

func (d *Daemon) hResume(w http.ResponseWriter, r *http.Request) {
	if err := d.resume(r.Context()); err != nil {
		d.writeErr(w, err)
		return
	}
	writeJSON(w, 200, d.status())
}

// ---- passes ----------------------------------------------------------------

func passInfo(p pass.Pass, now time.Time) client.PassInfo {
	pi := client.PassInfo{ID: p.ID, Name: p.Name, Kind: p.Kind, Created: p.Created, Expires: p.Expires,
		Providers: p.Providers, Models: p.ModelAllow, DenyModels: p.ModelDeny, Concurrency: p.MaxConcurrency,
		Revoked: p.Revoked, RevokedAt: p.RevokedAt, LastUsed: p.LastUsed, Expired: p.Expired(now)}
	for _, l := range p.Limits {
		pi.Limits = append(pi.Limits, client.PassLimit{Window: l.Window, Amount: l.Amount})
	}
	if p.Bind != nil {
		pi.BindPID, pi.BindImage = p.Bind.PID, filepath.Base(p.Bind.Image)
	}
	return pi
}

func (d *Daemon) hPassList(w http.ResponseWriter, _ *http.Request) {
	now := d.clk.Now()
	out := []client.PassInfo{}
	for _, p := range d.passes.List() {
		out = append(out, passInfo(p, now))
	}
	writeJSON(w, 200, out)
}

func (d *Daemon) hPassCreate(w http.ResponseWriter, r *http.Request) {
	var req client.PassCreateRequest
	if err := readBody(r, &req); err != nil {
		d.writeErr(w, err)
		return
	}
	st, err := d.requireServing()
	if err != nil {
		d.writeErr(w, err)
		return
	}
	kind := req.Kind
	if kind == "" {
		kind = pass.KindNamed
	}
	if st == StateAway && !(kind == pass.KindRun && d.cfg.Limits.Away.AllowNewRunPasses) {
		d.writeErr(w, statusErr(403, client.CodeForbidden, "keyleash is in away mode: new passes are refused"))
		return
	}
	caller := callerFrom(r.Context())
	if caller.confined || !caller.known() {
		d.writeErr(w, statusErr(403, client.CodeConfined, "passes cannot be created from inside a keyleash run pass or by an unidentified process"))
		return
	}
	p, err := d.passFromRequest(req)
	if err != nil {
		d.writeErr(w, err)
		return
	}
	// A run pass bound to the calling process within the configured
	// defaults needs no step-up (spec §6); anything else does.
	if why := d.passNeedsStepUp(&p, req, caller.pid); why != "" {
		risk, extra := describePass(p, d.clk.Now())
		if _, err := d.stepUp(r.Context(), approval.Request{Kind: "pass_create", Title: "Create a pass: " + why,
			Detail: risk, Note: extra}); err != nil {
			d.writeErr(w, err)
			return
		}
		if st2, err := d.requireServing(); err != nil {
			d.writeErr(w, err)
			return
		} else if st2 == StateAway && !(p.Kind == pass.KindRun && d.cfg.Limits.Away.AllowNewRunPasses) {
			d.writeErr(w, statusErr(403, client.CodeForbidden, "keyleash is in away mode: new passes are refused"))
			return
		}
	}
	// Fix the key each provider uses now, so adding a key or changing the
	// active key later never redirects this pass (spec §6).
	p.Entries = map[string]string{}
	provs := p.Providers
	if slices.Contains(provs, pass.AllProviders) {
		provs = provider.Names()
	}
	for _, name := range provs {
		if id, ok, _ := d.entryFor(pass.Pass{}, strings.ToLower(name)); ok {
			p.Entries[strings.ToLower(name)] = id
		}
	}
	token, issued, err := d.passes.Issue(p)
	if err != nil {
		if errors.Is(err, pass.ErrInvalid) {
			d.writeErr(w, statusErr(400, client.CodeBadRequest, "invalid pass scope"))
			return
		}
		d.writeErr(w, err)
		return
	}
	// Issue → confine → audit → activate: the pass is returned (and its
	// limits applied) only once its process tree is confined and the audit
	// record is written; otherwise the issue is rolled back.
	rollback := func(why string, status int, code, msg string) {
		if rerr := d.passes.Remove(issued.ID); rerr != nil {
			d.log.Error("rolling back an issued pass failed", "pass", issued.ID, "err", rerr)
		}
		d.log.Error("pass issue rolled back", "pass", issued.ID, "why", why)
		d.writeErr(w, statusErr(status, code, "%s", msg))
	}
	if issued.Kind == pass.KindRun && d.jobs != nil {
		if err := d.jobs.Confine(issued.ID, issued.Bind.PID, issued.Bind.StartTime); err != nil {
			d.log.Warn("confining a run pass failed", "pass", issued.ID, "err", err)
			rollback("confine", 409, client.CodeConflict, "the process could not be confined (spec §12); no pass was issued")
			return
		}
	}
	if err := d.auditEventErr("pass_issue", map[string]any{"pass": issued.ID, "name": issued.Name, "kind": issued.Kind,
		"providers": issued.Providers, "bound": issued.Bind != nil, "expires": issued.Expires.UTC().Format(time.RFC3339),
		"requester_pid": caller.pid, "entries": issued.Entries}); err != nil {
		rollback("audit", 503, client.CodeInternal, "the audit record could not be written; no pass was issued")
		return
	}
	d.applyLimits()
	writeJSON(w, 200, client.PassCreateResponse{Pass: passInfo(issued, d.clk.Now()), Token: token})
}

// passFromRequest validates a create request and fills config defaults.
func (d *Daemon) passFromRequest(req client.PassCreateRequest) (pass.Pass, error) {
	bad := func(msg string) (pass.Pass, error) {
		return pass.Pass{}, statusErr(400, client.CodeBadRequest, "%s", msg)
	}
	p := pass.Pass{Name: strings.TrimSpace(req.Name), Kind: req.Kind}
	if p.Name == "" {
		p.Name = "pass"
	}
	if len(p.Name) > 64 {
		return bad("name too long")
	}
	if p.Kind == "" {
		p.Kind = pass.KindNamed
	}
	ttl := req.TTL
	switch p.Kind {
	case pass.KindNamed:
		if ttl == 0 {
			ttl = d.cfg.Limits.Pass.TTL.Duration
		}
	case pass.KindRun:
		if ttl == 0 {
			ttl = d.cfg.Limits.Pass.RunTTL.Duration
		}
		if req.BindPID <= 0 {
			return bad("run passes must be bound to a process")
		}
	default:
		return bad("kind must be \"named\" or \"run\"")
	}
	if ttl <= 0 || ttl > maxPassTTL {
		return bad("ttl out of range")
	}
	if len(req.Providers) == 0 {
		return bad("at least one provider is required (or \"*\")")
	}
	if len(req.Providers) > pass.MaxListLen || len(req.Models) > pass.MaxListLen ||
		len(req.DenyModels) > pass.MaxListLen || len(req.Limits) > pass.MaxListLen {
		return bad("too many providers, model patterns or limits (at most " + strconv.Itoa(pass.MaxListLen) + " each)")
	}
	seenProv := map[string]bool{}
	for _, name := range req.Providers {
		key := strings.ToLower(name)
		if seenProv[key] {
			return bad("duplicate provider " + strconv.Quote(name))
		}
		seenProv[key] = true
		if name == pass.AllProviders {
			continue
		}
		if _, ok := provider.Get(name); !ok {
			return bad("unknown provider " + strconv.Quote(name))
		}
	}
	if seenProv[pass.AllProviders] && len(req.Providers) > 1 {
		return bad("\"*\" cannot be combined with other providers")
	}
	for _, list := range [][]string{req.Models, req.DenyModels} {
		seen := map[string]bool{}
		for _, g := range list {
			if !glob.Valid(g) {
				return bad("bad model pattern " + strconv.Quote(g))
			}
			if seen[g] {
				return bad("duplicate model pattern " + strconv.Quote(g))
			}
			seen[g] = true
		}
	}
	for _, l := range req.Limits {
		if !budget.Window(l.Window).Valid() || l.Amount < 0 {
			return bad("bad limit")
		}
		p.Limits = append(p.Limits, pass.LimitSpec{Window: l.Window, Amount: l.Amount})
	}
	if len(p.Limits) == 0 && p.Kind == pass.KindRun && d.cfg.Limits.Pass.MaxRunBudget != nil {
		// A run pass's default budget: max_run_budget per session and month.
		b := d.cfg.Limits.Pass.MaxRunBudget.Micros
		p.Limits = []pass.LimitSpec{{Window: string(budget.WindowSession), Amount: b}, {Window: string(budget.WindowMonth), Amount: b}}
	}
	if len(p.Limits) == 0 && d.cfg.Limits.Pass.Day != nil {
		p.Limits = []pass.LimitSpec{{Window: string(budget.WindowDay), Amount: d.cfg.Limits.Pass.Day.Micros}}
	}
	p.MaxConcurrency = req.Concurrency
	if p.MaxConcurrency < 0 {
		return bad("concurrency cannot be negative")
	}
	if p.MaxConcurrency == 0 {
		p.MaxConcurrency = d.cfg.Limits.Pass.Concurrency
	}
	p.Providers = slices.Clone(req.Providers)
	p.ModelAllow = slices.Clone(req.Models)
	p.ModelDeny = slices.Clone(req.DenyModels)
	p.Expires = d.clk.Now().Add(ttl)
	if req.BindPID > 0 {
		proc, err := d.lookupProcess(req.BindPID)
		if err != nil || proc.StartTime == 0 {
			return bad("cannot bind to that process (not found, or process identity unavailable on this system)")
		}
		p.Bind = &pass.Binding{PID: proc.PID, StartTime: proc.StartTime, Image: proc.Image}
	}
	return p, nil
}

// passNeedsStepUp returns "" when p may be issued without a step-up: a run
// pass bound to the calling process (callerPID), using only providers that
// have a key ("*" only when every provider has one), with a TTL within
// limits.pass.run_ttl, every spend limit within limits.pass.max_run_budget
// (and a month limit, added at that amount if missing), and concurrency
// within limits.pass.concurrency. Otherwise it says why a step-up is needed.
func (d *Daemon) passNeedsStepUp(p *pass.Pass, req client.PassCreateRequest, callerPID int) string {
	pd := d.cfg.Limits.Pass
	switch {
	case p.Kind != pass.KindRun:
		return "it is a named pass"
	case p.Bind == nil || p.Bind.PID != callerPID:
		return "it is bound to a process other than the caller"
	case pd.MaxRunBudget == nil:
		return "limits.pass.max_run_budget is not set"
	case p.Expires.Sub(d.clk.Now()) > pd.RunTTL.Duration:
		return "its lifetime exceeds limits.pass.run_ttl"
	case p.MaxConcurrency <= 0 || (pd.Concurrency > 0 && p.MaxConcurrency > pd.Concurrency):
		return "its concurrency exceeds limits.pass.concurrency"
	}
	withKey := map[string]bool{}
	for _, e := range d.vault.Entries() {
		if e.Kind == vault.KindAPIKey && !isInternalEntry(e) {
			withKey[e.Provider] = true
		}
	}
	for _, name := range p.Providers {
		if name == pass.AllProviders {
			for _, n := range provider.Names() {
				if !withKey[n] {
					return "it allows every provider but " + n + " has no key"
				}
			}
			continue
		}
		if !withKey[strings.ToLower(name)] {
			return "provider " + name + " has no key"
		}
	}
	hasMonth := false
	for _, l := range p.Limits {
		if l.Amount > pd.MaxRunBudget.Micros {
			return "a spend limit exceeds limits.pass.max_run_budget (" + pd.MaxRunBudget.Micros.String() + ")"
		}
		hasMonth = hasMonth || l.Window == string(budget.WindowMonth)
	}
	if !hasMonth {
		p.Limits = append(p.Limits, pass.LimitSpec{Window: string(budget.WindowMonth), Amount: pd.MaxRunBudget.Micros})
	}
	return ""
}

// describePass is the approval prompt text for a pass creation: the risk
// text (what the pass may spend, where, for how long, bound to what), which
// must be shown in full, and extras (model patterns, name) that may be cut.
func describePass(p pass.Pass, now time.Time) (risk, extra string) {
	var b strings.Builder
	b.WriteString(p.Kind + " pass, " + strings.Join(p.Providers, ","))
	if len(p.Limits) == 0 {
		b.WriteString("; NO spend limit")
	} else {
		b.WriteString(";")
		for _, l := range p.Limits {
			b.WriteString(" " + l.Amount.String() + "/" + l.Window)
		}
	}
	if p.Bind != nil {
		b.WriteString("; bound pid " + strconv.Itoa(p.Bind.PID))
	} else {
		b.WriteString("; unbound")
	}
	b.WriteString("; ttl " + p.Expires.Sub(now).Round(time.Minute).String())
	b.WriteString("; conc " + strconv.Itoa(p.MaxConcurrency))
	if len(p.ModelAllow) == 0 {
		b.WriteString("; all models")
	} else {
		b.WriteString("; " + strconv.Itoa(len(p.ModelAllow)) + " model patterns")
	}
	var x []string
	if p.Bind != nil {
		x = append(x, "image "+filepath.Base(p.Bind.Image))
	}
	if len(p.ModelAllow) > 0 {
		x = append(x, "models "+strings.Join(p.ModelAllow, ","))
	}
	if len(p.ModelDeny) > 0 {
		x = append(x, "deny "+strings.Join(p.ModelDeny, ","))
	}
	x = append(x, "name "+strconv.Quote(p.Name))
	return b.String(), strings.Join(x, "; ")
}

func (d *Daemon) hPassRevoke(w http.ResponseWriter, r *http.Request) {
	var req client.PassRevokeRequest
	if err := readBody(r, &req); err != nil {
		d.writeErr(w, err)
		return
	}
	// A confined caller may revoke only the run pass whose tree it is in.
	if c := callerFrom(r.Context()); c.confined {
		p, ok := d.passes.Get(req.ID)
		own := ok && c.known() && d.inRunTree(p, c.pid)
		if !own {
			d.writeErr(w, statusErr(403, client.CodeConfined, "this process runs under a keyleash run pass; it may only revoke its own pass"))
			return
		}
	}
	if err := d.passes.Revoke(req.ID); err != nil {
		if errors.Is(err, pass.ErrNotFound) {
			d.writeErr(w, statusErr(404, client.CodeNotFound, "no such pass"))
			return
		}
		d.log.Error("pass revoke persistence failed (revoked in memory)", "err", err)
	}
	d.applyLimits()
	d.auditEvent("pass_revoke", map[string]any{"pass": req.ID, "reason": "admin"})
	writeJSON(w, 200, struct{}{})
}

// sweepRunPasses revokes bound passes whose process has exited (PID gone or
// reused) and refreshes limits so expired passes drop out.
func (d *Daemon) sweepRunPasses() {
	for _, p := range d.passes.List() {
		if p.Revoked || p.Bind == nil {
			continue
		}
		proc, err := d.lookupProcess(p.Bind.PID)
		dead := errors.Is(err, procinfo.ErrNotFound) || (err == nil && proc.StartTime != p.Bind.StartTime)
		if !dead {
			continue
		}
		if err := d.passes.Revoke(p.ID); err != nil && !errors.Is(err, pass.ErrNotFound) {
			d.log.Warn("revoking pass of exited process", "pass", p.ID, "err", err)
		}
		d.auditEvent("pass_revoke", map[string]any{"pass": p.ID, "reason": "process_exited"})
	}
	if d.jobs != nil {
		// Jobs of ended passes are kept while any member lives (they stay
		// confined), then released.
		now := d.clk.Now()
		d.jobs.Sweep(func(id string) bool {
			p, ok := d.passes.Get(id)
			return ok && !p.Revoked && !p.Expired(now)
		})
	}
	d.applyLimits()
}

// ---- keys ------------------------------------------------------------------

func (d *Daemon) hKeys(w http.ResponseWriter, _ *http.Request) {
	auth := d.vault.IsUnlocked()
	out := []client.KeyInfo{}
	ents := d.vault.Entries()
	for _, e := range ents {
		if isInternalEntry(e) {
			continue
		}
		ki := client.KeyInfo{ID: e.ID, Provider: e.Provider, Kind: e.Kind, Label: e.Label,
			Created: e.Created, Rotated: e.Rotated, Fingerprint: e.Fingerprint, Authenticated: auth}
		if e.Kind == vault.KindAPIKey && auth {
			id, ok, _ := d.entryFor(pass.Pass{}, e.Provider)
			ki.Active = ok && id == e.ID
		}
		out = append(out, ki)
	}
	writeJSON(w, 200, out)
}

// hKeyAdd stores a provider key. Adding a key needs a step-up (spec §9),
// except the very first api_key in the vault (initial setup): a key is
// where traffic and its bill go, so an agent must not be able to add its
// own. New passes keep using the provider's active key until the owner runs
// `keyleash keys use`.
func (d *Daemon) hKeyAdd(w http.ResponseWriter, r *http.Request) {
	var req client.AddKeyRequest
	err := readBody(r, &req)
	defer secmem.Wipe(req.Secret)
	if err != nil {
		d.writeErr(w, err)
		return
	}
	if _, ok := provider.Get(req.Provider); !ok {
		d.writeErr(w, statusErr(400, client.CodeBadRequest, "unknown provider"))
		return
	}
	if req.Kind == "" {
		req.Kind = vault.KindAPIKey
	}
	if req.Label == "" {
		req.Label = "default"
	}
	if len(req.Secret) == 0 {
		d.writeErr(w, statusErr(400, client.CodeBadRequest, "secret required"))
		return
	}
	if !d.vault.IsUnlocked() {
		d.writeErr(w, statusErr(423, client.CodeLocked, "keyleash is locked"))
		return
	}
	// Only the very first api_key the vault ever holds is exempt: removing
	// every key does not reopen the exemption (spec §9).
	vs := d.vaultStateSnapshot()
	first := req.Kind == vault.KindAPIKey && vs != nil && !vs.KeysEverAdded && !d.vaultHasAPIKey()
	if !first {
		if _, err := d.stepUp(r.Context(), approval.Request{Kind: "key_add", Title: "Add a provider key",
			Detail: "Add a " + req.Provider + " " + req.Kind + " labelled " + strconv.Quote(req.Label),
			Note:   "existing passes keep their key; new passes use the active key until `keyleash keys use`"}); err != nil {
			d.writeErr(w, err)
			return
		}
	}
	e, err := d.vault.AddEntry(req.Provider, req.Kind, req.Label, req.Secret)
	if err != nil {
		if errors.Is(err, vault.ErrInvalid) {
			d.writeErr(w, statusErr(400, client.CodeBadRequest, "invalid key entry (label or kind)"))
			return
		}
		if errors.Is(err, vault.ErrLocked) {
			d.writeErr(w, statusErr(423, client.CodeLocked, "keyleash is locked"))
			return
		}
		d.writeErr(w, err)
		return
	}
	if e.Kind == vault.KindAPIKey {
		if err := d.updateVaultState(func(s *vaultState) { s.KeysEverAdded = true }); err != nil {
			d.log.Error("recording keys_ever_added failed", "err", err)
		}
	}
	d.auditEvent("key_add", map[string]any{"entry": e.ID, "provider": e.Provider, "kind": e.Kind,
		"fingerprint": e.Fingerprint, "step_up": !first, "requester_pid": callerFrom(r.Context()).pid})
	active := false
	if e.Kind == vault.KindAPIKey {
		id, ok, _ := d.entryFor(pass.Pass{}, e.Provider)
		active = ok && id == e.ID
	}
	writeJSON(w, 200, client.KeyInfo{ID: e.ID, Provider: e.Provider, Kind: e.Kind, Label: e.Label,
		Created: e.Created, Rotated: e.Rotated, Fingerprint: e.Fingerprint, Authenticated: true, Active: active})
}

// findEntry returns a non-internal entry by id.
func (d *Daemon) findEntry(id string) (vault.EntryInfo, bool) {
	for _, e := range d.vault.Entries() {
		if e.ID == id && !isInternalEntry(e) {
			return e, true
		}
	}
	return vault.EntryInfo{}, false
}

func (d *Daemon) hKeyRemove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target, ok := d.findEntry(id)
	if !ok {
		d.writeErr(w, statusErr(404, client.CodeNotFound, "no such key"))
		return
	}
	if !d.vault.IsUnlocked() {
		d.writeErr(w, statusErr(423, client.CodeLocked, "keyleash is locked"))
		return
	}
	if _, err := d.stepUp(r.Context(), approval.Request{Kind: "key_remove", Title: "Remove a provider key",
		Detail: "Remove " + target.Provider + " key " + target.Label + " (" + target.Fingerprint + "); passes issued with it stop working"}); err != nil {
		d.writeErr(w, err)
		return
	}
	if err := d.vault.RemoveEntry(id); err != nil {
		if errors.Is(err, vault.ErrNotFound) {
			d.writeErr(w, statusErr(404, client.CodeNotFound, "no such key"))
			return
		}
		d.writeErr(w, err)
		return
	}
	if d.activeKey(target.Provider) == id {
		if err := d.updateVaultState(func(s *vaultState) { delete(s.ActiveKeys, target.Provider) }); err != nil {
			d.log.Warn("clearing the active key mapping", "err", err)
		}
	}
	d.auditEvent("key_remove", map[string]any{"entry": id, "provider": target.Provider, "fingerprint": target.Fingerprint})
	writeJSON(w, 200, struct{}{})
}

// hKeyUse makes an api_key entry its provider's active key: the key new
// passes are mapped to (step-up; existing passes keep theirs).
func (d *Daemon) hKeyUse(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	target, ok := d.findEntry(id)
	if !ok || target.Kind != vault.KindAPIKey {
		d.writeErr(w, statusErr(404, client.CodeNotFound, "no such api key"))
		return
	}
	if !d.vault.IsUnlocked() {
		d.writeErr(w, statusErr(423, client.CodeLocked, "keyleash is locked"))
		return
	}
	if _, err := d.stepUp(r.Context(), approval.Request{Kind: "key_use", Title: "Change the active provider key",
		Detail: "Use " + target.Provider + " key " + target.Label + " (" + target.Fingerprint + ") for new passes"}); err != nil {
		d.writeErr(w, err)
		return
	}
	if _, still := d.findEntry(id); !still {
		d.writeErr(w, statusErr(404, client.CodeNotFound, "no such api key"))
		return
	}
	if err := d.updateVaultState(func(s *vaultState) {
		if s.ActiveKeys == nil {
			s.ActiveKeys = map[string]string{}
		}
		s.ActiveKeys[target.Provider] = id
	}); err != nil {
		d.writeErr(w, err)
		return
	}
	d.auditEvent("key_use", map[string]any{"entry": id, "provider": target.Provider, "fingerprint": target.Fingerprint})
	writeJSON(w, 200, client.KeyInfo{ID: target.ID, Provider: target.Provider, Kind: target.Kind, Label: target.Label,
		Created: target.Created, Rotated: target.Rotated, Fingerprint: target.Fingerprint, Authenticated: true, Active: true})
}

// ---- usage / approvals / audit / config ------------------------------------

func (d *Daemon) hUsage(w http.ResponseWriter, r *http.Request) {
	by := r.URL.Query().Get("by")
	if by == "" {
		by = "model"
	}
	switch by {
	case "pass", "model", "provider", "process":
	default:
		d.writeErr(w, statusErr(400, client.CodeBadRequest, "by must be pass, model, provider or process"))
		return
	}
	now := d.clk.Now()
	since := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.Local)
	if s := r.URL.Query().Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			d.writeErr(w, statusErr(400, client.CodeBadRequest, "since must be RFC 3339"))
			return
		}
		since = t
	}
	if err := d.ledger.Flush(); err != nil {
		d.log.Warn("ledger flush for usage", "err", err)
	}
	u, err := readUsage(filepath.Join(d.dataDir, LedgerDir), by, since)
	if err != nil {
		d.writeErr(w, err)
		return
	}
	writeJSON(w, 200, u)
}

func (d *Daemon) hApprovals(w http.ResponseWriter, _ *http.Request) {
	out := []client.Approval{}
	for _, p := range d.queue.Pending() {
		out = append(out, d.approvalInfo(p))
	}
	writeJSON(w, 200, out)
}

// approvalInfo is the admin view of a pending approval, including who asked
// and, for an over-limit request, the largest grant approving it may carry.
func (d *Daemon) approvalInfo(p approval.PendingInfo) client.Approval {
	a := client.Approval{ID: p.ID, Kind: p.Request.Kind, Prompt: p.Prompt, Pass: p.Request.PassID,
		Model: p.Request.Model, Amount: p.Request.Amount, Created: p.Created, Deadline: p.Deadline, Waiters: p.Waiters,
		Requester: p.Request.Requester, Scope: p.Request.Scope, Window: p.Request.Window, Limit: p.Request.Limit,
		Method: p.Method}
	if a.Requester > 0 {
		if proc, err := d.lookupProcess(a.Requester); err == nil {
			a.RequesterImage = filepath.Base(proc.Image)
		}
	}
	if p.Request.Kind == "over_limit" {
		a.GrantMax = grantCap(p.Request.Limit, d.cfg.Approval.GrantMaxMultiple)
		if a.GrantMax > 0 {
			a.GrantMaxFor = d.cfg.Approval.GrantMaxDuration.Duration
		}
	}
	return a
}

// Owner-secret rate limit for approvals (spec §9). Each caller (PID and
// executable image) gets secretFreeTries wrong secrets, then waits
// secretBackoff, doubling up to secretBackoffMax. Across all callers, after
// secretGlobalFree wrong secrets every attempt waits secretGlobalBackoff,
// doubling up to secretGlobalMax, so new processes cannot reset the limit.
// At most one verification runs at a time; concurrent attempts get 429.
const (
	secretFreeTries     = 5
	secretBackoff       = 30 * time.Second
	secretBackoffMax    = 15 * time.Minute
	secretGlobalFree    = 10
	secretGlobalBackoff = 2 * time.Second
	secretGlobalMax     = time.Minute
	secretMaxCallers    = 1024
)

// secretFailures counts consecutive wrong secrets and the time before which
// the next attempt is refused.
type secretFailures struct {
	fails int
	until time.Time
}

// fail records a wrong secret and returns the new count.
func (f *secretFailures) fail(now time.Time, free int, base, ceil time.Duration) int {
	f.fails++
	if f.fails >= free {
		back := base
		for i := free; i < f.fails && back < ceil; i++ {
			back *= 2
		}
		f.until = now.Add(min(back, ceil))
	}
	return f.fails
}

// hDecide decides a pending approval. Denying needs nothing. Approving is a
// step-up and therefore needs proof of owner presence (spec §9): the vault
// passphrase or recovery code, verified by the vault itself. Access to the
// admin channel alone never approves anything.
func (d *Daemon) hDecide(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req client.DecideRequest
	err := readBody(r, &req)
	defer secmem.Wipe(req.Secret)
	if err != nil {
		d.writeErr(w, err)
		return
	}
	pend, ok := d.queue.Get(id)
	if !ok {
		d.writeErr(w, statusErr(404, client.CodeNotFound, "no such pending approval"))
		return
	}
	if !req.Approved {
		if req.Grant != nil {
			d.writeErr(w, statusErr(400, client.CodeBadRequest, "a denial carries no grant"))
			return
		}
		d.decide(w, id, false, nil, "external")
		return
	}
	// The approver that holds this request decides what may approve it: a
	// resume after a config change waits for the secret even when the
	// changed config says "deny".
	if pend.Method == "deny" || (d.cfg.Approval.Method == "deny" && pend.Method != "passphrase") {
		d.writeErr(w, statusErr(403, client.CodeForbidden, "approval.method is deny: nothing can be approved"))
		return
	}
	if len(req.Secret) == 0 {
		d.writeErr(w, statusErr(403, client.CodeForbidden,
			"approving needs your keyleash passphrase or recovery code (`keyleash approvals approve <id>` asks for it)"))
		return
	}
	var g *approval.Grant
	if req.Grant != nil {
		info := d.approvalInfo(pend)
		switch {
		case pend.Request.Kind != "over_limit" || info.GrantMax <= 0:
			d.writeErr(w, statusErr(400, client.CodeBadRequest, "only an over-limit approval can carry a grant"))
			return
		case req.Grant.Amount <= 0 || req.Grant.For <= 0:
			d.writeErr(w, statusErr(400, client.CodeBadRequest, "bad grant"))
			return
		case req.Grant.Amount > info.GrantMax || req.Grant.For > info.GrantMaxFor:
			d.writeErr(w, statusErr(400, client.CodeBadRequest, "grant too large: at most %s for %s", info.GrantMax, info.GrantMaxFor))
			return
		}
		g = &approval.Grant{Amount: req.Grant.Amount, For: req.Grant.For}
	}
	method, err := d.verifyOwnerSecret(r.Context(), id, req.Method, req.Secret)
	if err != nil {
		d.writeErr(w, err)
		return
	}
	d.decide(w, id, true, g, method)
}

func (d *Daemon) decide(w http.ResponseWriter, id string, approved bool, g *approval.Grant, method string) {
	if err := d.queue.DecideAs(id, approved, g, method); err != nil {
		if errors.Is(err, approval.ErrNotFound) {
			d.writeErr(w, statusErr(404, client.CodeNotFound, "no such pending approval"))
			return
		}
		d.writeErr(w, err)
		return
	}
	writeJSON(w, 200, struct{}{})
}

// secretCallerKey identifies the caller for the per-caller secret limit:
// its PID and executable image ("?" when unknown).
func (d *Daemon) secretCallerKey(ctx context.Context) string {
	c := callerFrom(ctx)
	img := "?"
	if c.known() {
		if p, err := d.lookupProcess(c.pid); err == nil && p.Image != "" {
			img = strings.ToLower(p.Image)
		}
	}
	return strconv.Itoa(c.pid) + ":" + img
}

// verifyOwnerSecret checks a passphrase or recovery code against the
// unlocked vault (the vault derives the key from the secret and compares
// what it unwraps with its own key; nothing is compared in the daemon). It
// returns the method that matched. Wrong secrets are audited and rate
// limited per caller and globally; the attempt is reserved before the slow
// key derivation, which runs without holding the unlock lock, so lock and
// panic are never delayed by it.
func (d *Daemon) verifyOwnerSecret(ctx context.Context, approvalID, method string, secret []byte) (string, error) {
	switch method {
	case "", client.MethodRecovery, client.MethodPassphrase:
	default:
		return "", statusErr(400, client.CodeBadRequest, "method must be passphrase or recovery")
	}
	key := d.secretCallerKey(ctx)
	now := d.clk.Now()
	d.secretMu.Lock()
	cf := d.secretCallers[key]
	var wait time.Duration
	if cf != nil {
		wait = cf.until.Sub(now)
	}
	if g := d.secretGlobal.until.Sub(now); g > wait {
		wait = g
	}
	switch {
	case wait > 0:
		d.secretMu.Unlock()
		return "", statusErr(429, client.CodeRateLimited, "too many wrong secrets; retry in %s", wait.Round(time.Second))
	case d.secretInFlight:
		d.secretMu.Unlock()
		return "", statusErr(429, client.CodeRateLimited, "another secret is being verified; retry shortly")
	}
	d.secretInFlight = true
	d.secretMu.Unlock()
	defer func() {
		d.secretMu.Lock()
		d.secretInFlight = false
		d.secretMu.Unlock()
	}()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if !d.vault.IsUnlocked() || d.State() == StateLocked {
		return "", statusErr(423, client.CodeLocked, "keyleash is locked")
	}

	var err error
	used := method
	switch method {
	case client.MethodRecovery:
		err = d.vault.VerifyRecovery(string(secret))
	case client.MethodPassphrase:
		err = d.vault.VerifyPassphrase(secret)
	default:
		used = client.MethodRecovery
		if err = d.vault.VerifyRecovery(string(secret)); errors.Is(err, vault.ErrBadRecoveryCode) {
			used = client.MethodPassphrase
			err = d.vault.VerifyPassphrase(secret)
		}
	}
	if err == nil {
		d.secretMu.Lock()
		delete(d.secretCallers, key)
		d.secretGlobal = secretFailures{}
		d.secretMu.Unlock()
		d.auditEvent("approval_secret", map[string]any{"approval": approvalID, "ok": true, "method": used})
		return used, nil
	}
	if errors.Is(err, vault.ErrLocked) {
		return "", statusErr(423, client.CodeLocked, "keyleash is locked")
	}
	if errors.Is(err, vault.ErrWrongSecret) || errors.Is(err, vault.ErrBadRecoveryCode) {
		now = d.clk.Now()
		d.secretMu.Lock()
		cf = d.secretCallers[key]
		if cf == nil {
			if len(d.secretCallers) >= secretMaxCallers {
				// Bounded: drop entries whose wait is over; if none, the
				// global limit (already counting) still applies.
				for k, v := range d.secretCallers {
					if !v.until.After(now) {
						delete(d.secretCallers, k)
					}
				}
			}
			cf = &secretFailures{}
			if len(d.secretCallers) < secretMaxCallers {
				d.secretCallers[key] = cf
			}
		}
		fails := cf.fail(now, secretFreeTries, secretBackoff, secretBackoffMax)
		global := d.secretGlobal.fail(now, secretGlobalFree, secretGlobalBackoff, secretGlobalMax)
		d.secretMu.Unlock()
		d.auditEvent("approval_secret", map[string]any{"approval": approvalID, "ok": false, "method": used, "failures": fails, "failures_all": global})
		return "", statusErr(401, client.CodeWrongSecret, "wrong secret")
	}
	d.log.Warn("verifying the owner secret failed", "err", err)
	d.auditEvent("approval_secret", map[string]any{"approval": approvalID, "ok": false, "method": used, "reason": unlockFailReason(err)})
	return "", statusErr(409, client.CodeConflict, "the vault could not verify the secret")
}

func (d *Daemon) hAuditTail(w http.ResponseWriter, r *http.Request) {
	n := 50
	if s := r.URL.Query().Get("n"); s != "" {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 {
			d.writeErr(w, statusErr(400, client.CodeBadRequest, "n must be a positive integer"))
			return
		}
		n = min(v, maxAuditTail)
	}
	var recs []audit.Record
	var err error
	d.withAudit(func(l *audit.Log) {
		if ferr := l.Flush(); ferr != nil {
			d.log.Warn("audit flush", "err", ferr)
		}
		recs, err = l.Tail(n)
	})
	if err != nil {
		d.writeErr(w, err)
		return
	}
	out := []client.AuditRecord{}
	for _, rec := range recs {
		out = append(out, client.AuditRecord{Seq: rec.Seq, TS: rec.TS, Type: rec.Type, Fields: rec.Fields, Hash: rec.Hash})
	}
	writeJSON(w, 200, out)
}

func (d *Daemon) hAuditVerify(w http.ResponseWriter, _ *http.Request) {
	d.withAudit(func(l *audit.Log) { _ = l.Flush() })
	var key []byte
	d.mu.RLock()
	if d.st.keys != nil {
		key = append([]byte(nil), d.st.keys.anchor.Bytes()...)
	}
	d.mu.RUnlock()
	defer secmem.Wipe(key)
	rep, err := audit.Verify(filepath.Join(d.dataDir, AuditDir), key)
	out := client.AuditVerify{OK: err == nil, Records: rep.Records, Files: rep.Files, Anchors: rep.Anchors,
		AnchorsVerified: rep.AnchorsVerified, KeyUsed: key != nil}
	if rep.FirstBad != nil {
		out.Problem = rep.FirstBad.String()
	} else if err != nil {
		out.Problem = "verification could not complete"
		d.log.Warn("audit verify", "err", err)
	}
	writeJSON(w, 200, out)
}

func (d *Daemon) hConfig(w http.ResponseWriter, _ *http.Request) {
	s, err := d.cfg.Encode()
	if err != nil {
		d.writeErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]string{"toml": s})
}

// ---- vault administration --------------------------------------------------

func (d *Daemon) hRotateRecovery(w http.ResponseWriter, r *http.Request) {
	// Reading the (empty) body to EOF also lets net/http notice a caller
	// that disconnects, which cancels r.Context(); rekey checks it.
	if err := readBody(r, &struct{}{}); err != nil {
		d.writeErr(w, err)
		return
	}
	if !d.vault.IsUnlocked() {
		d.writeErr(w, statusErr(423, client.CodeLocked, "keyleash is locked"))
		return
	}
	if _, err := d.stepUp(r.Context(), approval.Request{Kind: "admin_change", Title: "Rotate the recovery code",
		Detail: "Replace the recovery code and re-key the vault"}); err != nil {
		d.writeErr(w, err)
		return
	}
	var code string
	err := d.rekey(r.Context(), "rotate_recovery", func() error {
		var rerr error
		code, rerr = d.vault.RotateRecovery()
		return rerr
	})
	resp := client.RotateRecoveryResponse{Code: code}
	if errors.Is(err, vault.ErrPrevNotScrubbed) {
		resp.Warning = "vault.prev still holds the old vault key; delete it"
	} else if err != nil {
		d.writeErr(w, err)
		return
	}
	writeJSON(w, 200, resp)
}

func (d *Daemon) hRemoveSlot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !d.vault.IsUnlocked() {
		d.writeErr(w, statusErr(423, client.CodeLocked, "keyleash is locked"))
		return
	}
	found := false
	for _, s := range d.vault.Slots() {
		found = found || s.ID == id
	}
	if !found {
		d.writeErr(w, statusErr(404, client.CodeNotFound, "no such slot"))
		return
	}
	if _, err := d.stepUp(r.Context(), approval.Request{Kind: "admin_change", Title: "Remove a vault slot",
		Detail: "Remove slot " + id + " and re-key the vault"}); err != nil {
		d.writeErr(w, err)
		return
	}
	err := d.rekey(r.Context(), "remove_slot", func() error { return d.vault.RemoveSlot(id) })
	switch {
	case err == nil, errors.Is(err, vault.ErrPrevNotScrubbed):
		writeJSON(w, 200, struct{}{})
	case errors.Is(err, vault.ErrLastSlot):
		d.writeErr(w, statusErr(409, client.CodeConflict, "cannot remove the last non-convenience slot"))
	case errors.Is(err, vault.ErrNotFound):
		d.writeErr(w, statusErr(404, client.CodeNotFound, "no such slot"))
	default:
		d.writeErr(w, err)
	}
}
