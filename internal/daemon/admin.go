package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	mux.HandleFunc("POST /v1/away", d.hAway)
	mux.HandleFunc("POST /v1/resume", d.hResume)
	mux.HandleFunc("GET /v1/passes", d.hPassList)
	mux.HandleFunc("POST /v1/passes", d.hPassCreate)
	mux.HandleFunc("DELETE /v1/passes", d.hPassRevoke)
	mux.HandleFunc("GET /v1/keys", d.hKeys)
	mux.HandleFunc("POST /v1/keys", d.hKeyAdd)
	mux.HandleFunc("DELETE /v1/keys/{id}", d.hKeyRemove)
	mux.HandleFunc("GET /v1/usage", d.hUsage)
	mux.HandleFunc("GET /v1/approvals", d.hApprovals)
	mux.HandleFunc("POST /v1/approvals/{id}", d.hDecide)
	mux.HandleFunc("GET /v1/audit/tail", d.hAuditTail)
	mux.HandleFunc("GET /v1/audit/verify", d.hAuditVerify)
	mux.HandleFunc("GET /v1/config", d.hConfig)
	mux.HandleFunc("POST /v1/vault/accept-rollback", d.hAcceptRollback)
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
	s.Vault.PrevNotScrubbed = d.st.prevNotScrubbed
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
	if s.PresenceDegraded {
		s.Warnings = append(s.Warnings, "presence detection is degraded: "+s.PresenceDegradedReason)
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
	if err := d.unlock(r.Context(), req.Method, req.Secret); err != nil {
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
	}
	if _, err := d.stepUp(r.Context(), approval.Request{Kind: "away_grant", Title: "Unattended grant",
		Detail: detail, PassID: req.Pass, Amount: req.Budget, CoalesceKey: "away_grant"}); err != nil {
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
	p, err := d.passFromRequest(req)
	if err != nil {
		d.writeErr(w, err)
		return
	}
	st, err := d.requireServing()
	if err != nil {
		d.writeErr(w, err)
		return
	}
	if st == StateAway && p.Kind == pass.KindRun && !d.cfg.Limits.Away.AllowNewRunPasses {
		d.writeErr(w, statusErr(403, client.CodeForbidden, "keyleash is in away mode: new run passes are refused"))
		return
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
	d.applyLimits()
	d.auditEvent("pass_issue", map[string]any{"pass": issued.ID, "name": issued.Name, "kind": issued.Kind,
		"providers": issued.Providers, "bound": issued.Bind != nil, "expires": issued.Expires.UTC().Format(time.RFC3339)})
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
	for _, name := range req.Providers {
		if name == pass.AllProviders {
			continue
		}
		if _, ok := provider.Get(name); !ok {
			return bad("unknown provider " + strconv.Quote(name))
		}
	}
	for _, g := range append(slices.Clone(req.Models), req.DenyModels...) {
		if !glob.Valid(g) {
			return bad("bad model pattern " + strconv.Quote(g))
		}
	}
	for _, l := range req.Limits {
		if !budget.Window(l.Window).Valid() || l.Amount < 0 {
			return bad("bad limit")
		}
		p.Limits = append(p.Limits, pass.LimitSpec{Window: l.Window, Amount: l.Amount})
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

func (d *Daemon) hPassRevoke(w http.ResponseWriter, r *http.Request) {
	var req client.PassRevokeRequest
	if err := readBody(r, &req); err != nil {
		d.writeErr(w, err)
		return
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
	d.applyLimits()
}

// ---- keys ------------------------------------------------------------------

func (d *Daemon) hKeys(w http.ResponseWriter, _ *http.Request) {
	auth := d.vault.IsUnlocked()
	out := []client.KeyInfo{}
	for _, e := range d.vault.Entries() {
		if isRootEntry(e) {
			continue
		}
		out = append(out, client.KeyInfo{ID: e.ID, Provider: e.Provider, Kind: e.Kind, Label: e.Label,
			Created: e.Created, Rotated: e.Rotated, Fingerprint: e.Fingerprint, Authenticated: auth})
	}
	writeJSON(w, 200, out)
}

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
	d.auditEvent("key_add", map[string]any{"entry": e.ID, "provider": e.Provider, "kind": e.Kind, "fingerprint": e.Fingerprint})
	writeJSON(w, 200, client.KeyInfo{ID: e.ID, Provider: e.Provider, Kind: e.Kind, Label: e.Label,
		Created: e.Created, Rotated: e.Rotated, Fingerprint: e.Fingerprint, Authenticated: true})
}

func (d *Daemon) hKeyRemove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var target *vault.EntryInfo
	for _, e := range d.vault.Entries() {
		if e.ID == id && !isRootEntry(e) {
			target = &e
			break
		}
	}
	if target == nil {
		d.writeErr(w, statusErr(404, client.CodeNotFound, "no such key"))
		return
	}
	if !d.vault.IsUnlocked() {
		d.writeErr(w, statusErr(423, client.CodeLocked, "keyleash is locked"))
		return
	}
	if _, err := d.stepUp(r.Context(), approval.Request{Kind: "key_remove", Title: "Remove a provider key",
		Detail: "Remove " + target.Provider + " key " + target.Label + " (" + target.Fingerprint + ")", CoalesceKey: "key_remove:" + id}); err != nil {
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
	d.auditEvent("key_remove", map[string]any{"entry": id, "provider": target.Provider, "fingerprint": target.Fingerprint})
	writeJSON(w, 200, struct{}{})
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
		out = append(out, client.Approval{ID: p.ID, Kind: p.Request.Kind, Prompt: p.Prompt, Pass: p.Request.PassID,
			Model: p.Request.Model, Amount: p.Request.Amount, Created: p.Created, Deadline: p.Deadline, Waiters: p.Waiters})
	}
	writeJSON(w, 200, out)
}

func (d *Daemon) hDecide(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req client.DecideRequest
	if err := readBody(r, &req); err != nil {
		d.writeErr(w, err)
		return
	}
	if req.Approved && !d.adminApprove {
		d.writeErr(w, statusErr(403, client.CodeForbidden,
			"approval.method is hello: approve with Windows Hello; the admin API can only deny"))
		return
	}
	var g *approval.Grant
	if req.Grant != nil {
		if req.Grant.Amount <= 0 || req.Grant.For <= 0 || req.Grant.For > maxGrantDuration {
			d.writeErr(w, statusErr(400, client.CodeBadRequest, "bad grant"))
			return
		}
		g = &approval.Grant{Amount: req.Grant.Amount, For: req.Grant.For}
	}
	if err := d.queue.Decide(id, req.Approved, g); err != nil {
		if errors.Is(err, approval.ErrNotFound) {
			d.writeErr(w, statusErr(404, client.CodeNotFound, "no such pending approval"))
			return
		}
		d.writeErr(w, err)
		return
	}
	writeJSON(w, 200, struct{}{})
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

func (d *Daemon) hAcceptRollback(w http.ResponseWriter, _ *http.Request) {
	if d.State() != StateLocked {
		d.writeErr(w, statusErr(409, client.CodeConflict, "only meaningful while locked"))
		return
	}
	d.vault.AcceptRollback()
	d.auditEvent("slot_change", map[string]any{"op": "accept_rollback_armed"})
	writeJSON(w, 200, struct{}{})
}

func (d *Daemon) hRotateRecovery(w http.ResponseWriter, r *http.Request) {
	if !d.vault.IsUnlocked() {
		d.writeErr(w, statusErr(423, client.CodeLocked, "keyleash is locked"))
		return
	}
	if _, err := d.stepUp(r.Context(), approval.Request{Kind: "admin_change", Title: "Rotate the recovery code",
		Detail: "Replace the recovery code and re-key the vault", CoalesceKey: "rotate_recovery"}); err != nil {
		d.writeErr(w, err)
		return
	}
	var code string
	err := d.rekey("rotate_recovery", func() error {
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
		Detail: "Remove slot " + id + " and re-key the vault", CoalesceKey: "remove_slot:" + id}); err != nil {
		d.writeErr(w, err)
		return
	}
	err := d.rekey("remove_slot", func() error { return d.vault.RemoveSlot(id) })
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
