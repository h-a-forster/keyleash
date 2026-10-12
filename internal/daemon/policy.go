package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/h-a-forster/keyleash/internal/approval"
	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/glob"
	"github.com/h-a-forster/keyleash/internal/meter"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/proxy"
	"github.com/h-a-forster/keyleash/internal/vault"
)

// Reasons the daemon adds to the proxy's list.
const (
	ReasonProviderDenied = "provider_denied"
	ReasonNoKey          = "no_key"
)

func denial(status int, reason, msg string) *proxy.Denial {
	return &proxy.Denial{Status: status, Reason: reason, Message: msg}
}

// ---- Authenticator ---------------------------------------------------------

type authenticator struct{ d *Daemon }

// Authenticate implements proxy.Authenticator (docs/DAEMON.md).
func (a authenticator) Authenticate(_ context.Context, prov, token string, ci proxy.ClientInfo) (proxy.Principal, error) {
	d := a.d
	d.syncTrips()
	d.mu.RLock()
	state, awaySince := d.st.state, d.st.awaySince
	d.mu.RUnlock()
	switch state {
	case StateLocked:
		return proxy.Principal{}, denial(http.StatusLocked, proxy.ReasonLocked, "")
	case StateTripped:
		return proxy.Principal{}, denial(http.StatusLocked, proxy.ReasonTripped, "")
	}

	p, err := d.passes.Verify(token)
	if err != nil {
		if errors.Is(err, pass.ErrExpired) {
			return proxy.Principal{}, denial(http.StatusUnauthorized, proxy.ReasonPassExpired, "")
		}
		return proxy.Principal{}, denial(http.StatusUnauthorized, proxy.ReasonPassInvalid, "")
	}
	deny := func(dn *proxy.Denial) (proxy.Principal, error) {
		d.auditEvent("request", map[string]any{
			"provider": prov, "pass": p.ID, "client": clientName(ci), "pid": ci.PID,
			"status": dn.Status, "deny_reason": dn.Reason,
		})
		return proxy.Principal{}, dn
	}
	if !p.AllowsProvider(prov) {
		return deny(denial(http.StatusForbidden, ReasonProviderDenied, "this keyleash pass is not allowed to use "+prov))
	}
	if p.Bind != nil {
		// Never fall back to unbound: unknown peer, lookup failure or a
		// process outside the bound tree are all refusals.
		if ci.PID <= 0 {
			return deny(denial(http.StatusUnauthorized, proxy.ReasonPassInvalid, ""))
		}
		// A member of the run pass's job (even with a broken parent
		// chain) or, by the parent walk, the bound process's tree.
		if !d.inRunTree(p, ci.PID) {
			return deny(denial(http.StatusUnauthorized, proxy.ReasonPassInvalid, ""))
		}
	}
	if state == StateAway && p.Created.After(awaySince) && !(p.Kind == pass.KindRun && d.cfg.Limits.Away.AllowNewRunPasses) {
		return deny(denial(http.StatusForbidden, proxy.ReasonAwayLimit, "keyleash is in away mode: passes created while away are refused"))
	}
	entry, ok, pinnedGone := d.entryFor(p, prov)
	if pinnedGone {
		return deny(denial(http.StatusForbidden, ReasonNoKey, "the "+prov+" key this keyleash pass was issued with has been removed; create a new pass"))
	}
	if !ok {
		return deny(denial(http.StatusForbidden, ReasonNoKey, "keyleash has no key for "+prov+" — run `keyleash add "+prov+"`"))
	}
	return proxy.Principal{PassID: p.ID, PassName: p.Name, EntryID: entry}, nil
}

// syncTrips moves to Tripped when the ledger tripped or the audit log broke
// (their callbacks trip asynchronously; this makes the effect immediate).
func (d *Daemon) syncTrips() {
	if d.ledger.Tripped() {
		d.trip(TripVelocity, "spend tripwire fired")
	}
	if d.isAuditBroken() {
		d.trip(TripAudit, "audit log write failed")
	}
}

// entryFor picks the vault entry a pass uses for prov (spec §6): the entry
// fixed in the pass at issue time; else the provider's active key (set only
// by the step-up protected `keys use`); else the provider's oldest api_key,
// so adding a key never redirects existing traffic. pinnedGone reports that
// the pass's fixed entry no longer exists (the request is refused rather
// than redirected).
func (d *Daemon) entryFor(p pass.Pass, prov string) (id string, ok, pinnedGone bool) {
	ents := d.vault.Entries()
	valid := func(id string) bool {
		for _, e := range ents {
			if e.ID == id && e.Provider == prov && e.Kind == vault.KindAPIKey && !isInternalEntry(e) {
				return true
			}
		}
		return false
	}
	if id, pinned := p.Entries[prov]; pinned {
		if valid(id) {
			return id, true, false
		}
		return "", false, true
	}
	if id := d.activeKey(prov); id != "" && valid(id) {
		return id, true, false
	}
	var best vault.EntryInfo
	for _, e := range ents {
		if e.Provider != prov || e.Kind != vault.KindAPIKey || isInternalEntry(e) {
			continue
		}
		if !ok || e.Created.Before(best.Created) {
			best, ok = e, true
		}
	}
	return best.ID, ok, false
}

func clientName(ci proxy.ClientInfo) string {
	if ci.Image == "" {
		return ""
	}
	return filepath.Base(ci.Image)
}

// ---- Gate ------------------------------------------------------------------

type gate struct{ d *Daemon }

// Admit implements proxy.Gate (docs/DAEMON.md Gate.Admit).
func (g gate) Admit(ctx context.Context, a proxy.Admission) (proxy.Ticket, error) {
	d := g.d
	p, ok := d.passes.Get(a.Principal.PassID)
	if !ok {
		return nil, denial(http.StatusUnauthorized, proxy.ReasonPassInvalid, "")
	}
	deny := func(dn *proxy.Denial) (proxy.Ticket, error) {
		d.auditRequest(a, nil, proxy.Outcome{Status: dn.Status}, 0, false, dn.Reason)
		return nil, dn
	}
	model := a.Info.Model

	// 1. Model policy.
	if a.Endpoint.Metered || model != "" {
		if reason := d.modelDenied(p, model); reason != "" {
			return deny(denial(http.StatusForbidden, proxy.ReasonModelDenied, reason))
		}
	}
	// 2. Unmetered endpoints: no reservation, still audited.
	if !a.Endpoint.Metered {
		return &ticket{d: d, a: a}, nil
	}
	// 3. Estimate. A priced request reserves its estimate. An unpriced model
	// reserves its worst case at the provider's most expensive rates; a
	// request whose cost cannot be bounded at all reserves the per-request
	// limit and always needs approval (spec §7.5).
	amount, priced := d.meter.Estimate(a.Provider.Name, a.Info)
	unpriced, unbounded := false, false
	if !priced || amount < 0 {
		modelPriced := false
		if d.meter != nil && d.meter.Pricing != nil {
			_, modelPriced = d.meter.Pricing.Lookup(a.Provider.Name, model)
		}
		unpriced = !modelPriced
		bounded := false
		if unpriced {
			amount, bounded = d.meter.WorstCaseEstimate(a.Provider.Name, a.Info)
		}
		unbounded = !bounded
		d.mu.Lock()
		if unpriced {
			d.st.modelsSeen[a.Provider.Name+"/"+model] = true
		}
		awayNow := d.st.state == StateAway
		reqLimit := d.requestLimitLocked(a.Provider.Name, model, p.ID)
		d.mu.Unlock()
		if unpriced && awayNow {
			return deny(denial(http.StatusForbidden, proxy.ReasonModelDenied, "keyleash is in away mode: unpriced models are refused"))
		}
		if unpriced && d.cfg.Models.Unknown == "deny" {
			return deny(denial(http.StatusForbidden, proxy.ReasonModelDenied, "keyleash has no price for this model and the policy denies unknown models"))
		}
		if unbounded {
			if awayNow {
				return deny(denial(http.StatusForbidden, proxy.ReasonBudgetExceeded, "keyleash is in away mode: requests whose cost cannot be bounded are refused"))
			}
			if reqLimit <= 0 {
				return deny(denial(http.StatusForbidden, proxy.ReasonBudgetExceeded, "keyleash cannot bound the cost of this request and no per-request limit is configured to cap it"))
			}
			amount = reqLimit
		}
		if unbounded || d.cfg.Models.Unknown == "approve" {
			bucket := powerOfTwoAtLeast(amount)
			why := fmt.Sprintf("%s model %q has no price; each request is reserved and charged at the provider's most expensive rates, up to %s", a.Provider.Name, model, bucket)
			if unbounded {
				why = fmt.Sprintf("the cost of this %s request to %q cannot be bounded; it reserves the per-request limit %s and is charged at the metered cost", a.Provider.Name, model, amount)
				bucket = amount
			}
			dec, err := d.queue.Request(ctx, approval.Request{
				Kind: "unknown_model", Title: "Allow a request keyleash cannot price",
				Detail: why + " (pass " + p.ID + ", client " + clientName(a.Client) + ")",
				PassID: p.ID, Model: model, Amount: bucket,
				CoalesceKey: fmt.Sprintf("unknown_model:%s:%s/%s:%d:%t", p.ID, a.Provider.Name, model, int64(bucket), unbounded),
			})
			d.auditEvent("approval", map[string]any{"kind": "unknown_model", "approved": err == nil && dec.Approved,
				"method": dec.Method, "pass": p.ID, "model": model, "amount_micros": int64(amount), "unbounded": unbounded})
			if dn := approvalDenial(ctx, dec, err); dn != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return deny(dn)
			}
		}
	}

	// 4–5. Reserve against every applicable scope. An approved over-limit
	// request is admitted by skipping exactly the limit(s) the owner saw, for
	// this one reservation; a grant attached to the approval becomes a pass
	// grant for later requests of this pass only (spec §9).
	var skip []budget.LimitKey
	var grants []pendingPassGrant
	for approvals := 0; ; {
		res, err := d.reserve(a, p, amount, skip)
		if err == nil {
			for _, g := range grants {
				d.addPassGrant(g)
			}
			if len(skip) > 0 {
				ks := make([]string, len(skip))
				for i, k := range skip {
					ks[i] = k.Scope + "/" + string(k.Window)
				}
				d.auditEvent("limit_override", map[string]any{"request_id": a.RequestID, "pass": p.ID,
					"limits": ks, "amount_micros": int64(amount)})
			}
			return &ticket{d: d, a: a, res: res, unpriced: unpriced, unbounded: unbounded}, nil
		}
		var ex *budget.ExceededError
		var dn *proxy.Denial
		switch {
		case errors.As(err, &dn):
			return deny(dn)
		case errors.As(err, &ex):
			if ex.Scope == budget.ScopeAway || strings.HasPrefix(ex.Scope, budget.ScopeGrantPrefix+"g_") {
				return deny(denial(http.StatusForbidden, proxy.ReasonAwayLimit, exceededMessage(ex)))
			}
			if strings.HasPrefix(ex.Scope, budget.ScopeGrantPrefix) {
				return deny(denial(http.StatusForbidden, proxy.ReasonBudgetExceeded, "the allowance approved for this keyleash pass is used up: "+exceededMessage(ex)))
			}
			if d.cfg.Limits.OnExceed == "approve" && approvals < maxOverLimitApprovals {
				approvals++
				dec, aerr := d.queue.Request(ctx, approval.Request{
					Kind: "over_limit", Title: "Exceed a keyleash spend limit for one request",
					Detail: fmt.Sprintf("admits this one request only (limit not raised): %s %s limit %s; client %s",
						ex.Scope, ex.Window, ex.Limit, clientName(a.Client)),
					PassID: p.ID, Model: model, Amount: amount,
					Scope: ex.Scope, Window: string(ex.Window), Limit: ex.Limit,
				})
				d.auditEvent("approval", map[string]any{"kind": "over_limit", "approved": aerr == nil && dec.Approved,
					"method": dec.Method, "pass": p.ID, "model": model, "amount_micros": int64(amount), "scope": ex.Scope,
					"window": string(ex.Window), "id": dec.ID})
				if adn := approvalDenial(ctx, dec, aerr); adn != nil {
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					return deny(adn)
				}
				skip = append(skip, budget.LimitKey{Scope: ex.Scope, Window: ex.Window})
				if g := dec.Grant; g != nil && g.Amount > 0 && g.For > 0 {
					grants = append(grants, pendingPassGrant{approval: dec.ID, pass: p.ID, ex: *ex, grant: *g})
				}
				continue
			}
			return deny(denial(http.StatusForbidden, proxy.ReasonBudgetExceeded, exceededMessage(ex)))
		case errors.Is(err, budget.ErrConcurrency):
			return deny(denial(http.StatusTooManyRequests, proxy.ReasonConcurrency, ""))
		case errors.Is(err, budget.ErrTripped):
			d.trip(TripVelocity, "spend tripwire fired")
			return deny(denial(http.StatusLocked, proxy.ReasonTripped, ""))
		default:
			d.log.Error("ledger reserve failed", "err", err)
			return deny(denial(http.StatusServiceUnavailable, proxy.ReasonInternal, "keyleash cannot record spend right now"))
		}
	}
}

// maxOverLimitApprovals bounds the approvals one request may ask for (one
// per distinct exceeded limit).
const maxOverLimitApprovals = 3

// powerOfTwoAtLeast rounds v up to a power of two (in micro-dollars), so
// coalesced unknown-model approvals share a stated upper bound.
func powerOfTwoAtLeast(v money.Micros) money.Micros {
	b := money.Micros(1)
	for b < v && b < money.Micros(1)<<61 {
		b <<= 1
	}
	return b
}

func approvalDenial(ctx context.Context, dec approval.Decision, err error) *proxy.Denial {
	switch {
	case err == nil && dec.Approved:
		return nil
	case errors.Is(err, approval.ErrTimeout):
		return denial(http.StatusForbidden, proxy.ReasonApprovalTimeout, "")
	case ctx.Err() != nil:
		return denial(499, proxy.ReasonApprovalDenied, "")
	default:
		return denial(http.StatusForbidden, proxy.ReasonApprovalDenied, "")
	}
}

func exceededMessage(ex *budget.ExceededError) string {
	if ex.Window == budget.WindowRequest {
		return fmt.Sprintf("keyleash spend limit: this request could cost up to %s (worst case: its full max_tokens of output), over the %s per-request limit of %s; raise it in config.toml or with run --budget",
			ex.Requested, ex.Scope, ex.Limit)
	}
	remaining := ex.Limit - ex.Spent - ex.Reserved
	if remaining < 0 {
		remaining = 0
	}
	msg := fmt.Sprintf("keyleash spend limit reached: %s %s limit %s, remaining %s, this request needs up to %s",
		ex.Scope, ex.Window, ex.Limit, remaining, ex.Requested)
	if ex.Reserved > 0 {
		msg += fmt.Sprintf(" (%s is held by in-flight requests until they finish)", ex.Reserved)
	}
	return msg
}

// modelDenied applies config allow/deny globs, then the pass's model scope.
func (d *Daemon) modelDenied(p pass.Pass, model string) string {
	for _, g := range d.cfg.Models.Deny {
		if glob.Match(g, model) {
			return "model " + model + " is denied by the keyleash config"
		}
	}
	if len(d.cfg.Models.Allow) > 0 {
		allowed := false
		for _, g := range d.cfg.Models.Allow {
			if glob.Match(g, model) {
				allowed = true
				break
			}
		}
		if !allowed {
			return "model " + model + " is not in the keyleash allow list"
		}
	}
	if !p.AllowsModel(model) {
		return "model " + model + " is not allowed for this keyleash pass"
	}
	return ""
}

// reserve checks the state and reserves under the state read lock, so a
// concurrent lock either happens before (and the request is refused) or after
// (and the reservation is settled by the lock). skip lists limits the owner
// approved exceeding for this one request; the pass's active pass grants add
// their own skips and scopes.
func (d *Daemon) reserve(a proxy.Admission, p pass.Pass, amount money.Micros, skip []budget.LimitKey) (*budget.Reservation, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	switch d.st.state {
	case StateLocked:
		return nil, denial(http.StatusLocked, proxy.ReasonLocked, "")
	case StateTripped:
		return nil, denial(http.StatusLocked, proxy.ReasonTripped, "")
	}
	now := d.clk.Now()
	scopes := []string{
		budget.ScopeProviderPrefix + a.Provider.Name,
		budget.ScopePassPrefix + p.ID,
		budgetSessionScope(d.st.session),
	}
	if d.st.state == StateAway {
		if g := d.st.grant; g != nil && now.Before(g.until) && (g.pass == "" || g.pass == p.ID) {
			scopes = append(scopes, budget.ScopeGrantPrefix+g.id)
		} else {
			scopes = append(scopes, budget.ScopeAway)
		}
	}
	opt := budget.ReserveOptions{Skip: append([]budget.LimitKey(nil), skip...)}
	for _, pg := range d.st.passGrants {
		if pg.pass == p.ID && now.Before(pg.until) {
			opt.Skip = append(opt.Skip, budget.LimitKey{Scope: pg.scope, Window: pg.window})
			scopes = append(scopes, budget.ScopeGrantPrefix+pg.id)
		}
	}
	return d.ledger.ReserveWith(scopes, amount, budget.Meta{
		PassID: p.ID, Provider: a.Provider.Name, Model: a.Info.Model, Session: d.st.session,
		Client: clientName(a.Client), RequestID: a.RequestID,
	}, opt)
}

// pendingPassGrant is a grant from an over-limit approval, applied once the
// approved request itself has been admitted.
type pendingPassGrant struct {
	approval string
	pass     string
	ex       budget.ExceededError
	grant    approval.Grant
}

// addPassGrant turns an approval's grant into a pass grant: the pass may
// exceed the one limit the owner saw by up to the grant amount (capped at
// approval.grant_max_multiple times that limit) until the grant ends
// (capped at approval.grant_max_duration). Idempotent by approval id.
func (d *Daemon) addPassGrant(pg pendingPassGrant) {
	amt, dur := pg.grant.Amount, pg.grant.For
	if c := grantCap(pg.ex.Limit, d.cfg.Approval.GrantMaxMultiple); c > 0 && amt > c {
		amt = c
	}
	if mx := d.cfg.Approval.GrantMaxDuration.Duration; mx > 0 && dur > mx {
		dur = mx
	}
	id := "pg_" + pg.approval
	if pg.approval == "" {
		id = newID("pg_")
	}
	g := passGrant{id: id, pass: pg.pass, scope: pg.ex.Scope, window: pg.ex.Window, amount: amt, until: d.clk.Now().Add(dur)}
	d.mu.Lock()
	for _, x := range d.st.passGrants {
		if x.id == g.id {
			d.mu.Unlock()
			return
		}
	}
	d.st.passGrants = append(d.st.passGrants, g)
	d.applyLimitsLocked()
	d.ledger.ResetSession(budget.ScopeGrantPrefix + g.id)
	d.mu.Unlock()
	d.auditEvent("limit_change", map[string]any{"change": "pass_grant", "grant": g.id, "pass": g.pass,
		"scope": g.scope, "window": string(g.window), "amount_micros": int64(g.amount),
		"until": g.until.UTC().Format("2006-01-02T15:04:05Z")})
}

// grantCap is the largest grant an over-limit approval may carry.
func grantCap(limit money.Micros, multiple int) money.Micros {
	if limit <= 0 || multiple <= 0 {
		return 0
	}
	if limit > money.Micros(1)<<55 {
		return limit
	}
	return limit * money.Micros(multiple)
}

// ---- Ticket ----------------------------------------------------------------

type ticket struct {
	d   *Daemon
	a   proxy.Admission
	res *budget.Reservation // nil for unmetered endpoints
	// unpriced: the model has no price (settled at the provider's maximum
	// rates); unbounded: the reservation was the per-request limit.
	unpriced, unbounded bool
}

// Finish implements proxy.Ticket: release when the request never left,
// otherwise settle at the metered cost; an unpriced model at the provider's
// most expensive rates for the reported tokens (marked estimated); the
// reserved amount (marked estimated) when usage is unknown.
func (t *ticket) Finish(o proxy.Outcome) {
	d := t.d
	var cost money.Micros
	estimated := false
	if t.res != nil {
		if !o.Sent {
			t.res.Release()
		} else {
			u := o.Usage
			if u.Model == "" {
				u.Model = t.a.Info.Model
			}
			var c money.Micros
			var ok bool
			if t.unpriced {
				c, ok = d.meter.WorstCaseCost(t.a.Provider.Name, u)
				estimated = true
			} else {
				c, ok = d.meter.Cost(t.a.Provider.Name, u)
			}
			if o.UsageOK && ok && c >= 0 {
				cost = c
			} else if upstreamRefused(o) {
				cost = 0 // refused upstream before any work: providers bill nothing
			} else {
				cost, estimated = t.res.Amount(), true
			}
			if err := t.res.Settle(cost, estimated); err != nil {
				if errors.Is(err, budget.ErrAlreadySettled) {
					// Expired (lock or stale): charged at the reserved amount.
					cost, estimated = t.res.Amount(), true
				} else {
					d.log.Error("ledger settle failed", "request", t.a.RequestID, "err", err)
				}
			}
		}
	}
	d.auditRequest(t.a, t.res, o, cost, estimated, "")
	if err := d.passes.Touch(t.a.Principal.PassID, d.clk.Now()); err != nil {
		d.log.Warn("pass touch", "err", err)
	}
}

// upstreamRefused reports whether the provider itself answered with an error
// that is never billed: any 4xx (bad key, bad request, rate limit) or 529
// (overloaded). Other 5xx keep the reservation, since a gateway error can
// follow work that was already done (spec §7.3).
func upstreamRefused(o proxy.Outcome) bool {
	if o.UpstreamErr != nil || o.UsageOK {
		return false
	}
	return (o.Status >= 400 && o.Status < 500) || o.Status == 529
}

// auditRequest writes the spec §11 "request" record.
func (d *Daemon) auditRequest(a proxy.Admission, res *budget.Reservation, o proxy.Outcome, cost money.Micros, estimated bool, denyReason string) {
	f := map[string]any{
		"request_id": a.RequestID, "provider": a.Provider.Name, "model": a.Info.Model,
		"pass": a.Principal.PassID, "client": clientName(a.Client), "pid": a.Client.PID,
		"status": o.Status, "endpoint": a.Endpoint.Kind,
	}
	if denyReason != "" {
		f["deny_reason"] = denyReason
	} else {
		f["sent"] = o.Sent
		f["latency_ms"] = o.Latency.Milliseconds()
		f["input_tokens"] = o.Usage.InputTokens
		f["output_tokens"] = o.Usage.OutputTokens
		f["cache_read_tokens"] = o.Usage.CacheReadTokens
		f["cache_write_tokens"] = o.Usage.CacheWriteTokens
		f["cost_micros"] = int64(cost)
		f["estimated"] = estimated
		f["usage_ok"] = o.UsageOK
		if res != nil {
			f["reserved_micros"] = int64(res.Amount())
		}
		if o.ClientAborted {
			f["client_aborted"] = true
		}
		if o.UpstreamErr != nil {
			f["upstream_error"] = upstreamErrClass(o.UpstreamErr)
		}
	}
	d.auditEvent("request", f)
}

func upstreamErrClass(err error) string {
	switch {
	case errors.Is(err, proxy.ErrResponseHeaderTimeout):
		return "response_header_timeout"
	case errors.Is(err, proxy.ErrStreamIdleTimeout):
		return "stream_idle_timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "upstream_failed"
	}
}

// ---- KeySource -------------------------------------------------------------

type keySource struct{ d *Daemon }

// WithKey implements proxy.KeySource.
func (k keySource) WithKey(entryID string, fn func(key []byte) error) error {
	err := k.d.vault.WithSecret(entryID, fn)
	if errors.Is(err, vault.ErrLocked) {
		return denial(http.StatusLocked, proxy.ReasonLocked, "")
	}
	return err
}

// ---- Meter adapter ---------------------------------------------------------

// meterAdapter adapts *meter.Meter to proxy.Meter.
type meterAdapter struct{ m *meter.Meter }

func (a meterAdapter) Inspect(p *provider.Provider, ep provider.Endpoint, path string, body []byte) (meter.RequestInfo, error) {
	return a.m.Inspect(p, ep, path, body)
}

func (a meterAdapter) PrepareBody(ep provider.Endpoint, body []byte, info meter.RequestInfo) ([]byte, error) {
	return a.m.PrepareBody(ep, body, info)
}

func (a meterAdapter) NewUsageParser(p *provider.Provider, ep provider.Endpoint, stream bool) meter.UsageParser {
	return a.m.NewProviderUsageParser(p.Name, ep, stream)
}
