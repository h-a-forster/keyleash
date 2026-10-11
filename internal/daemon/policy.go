package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/approval"
	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/glob"
	"github.com/h-a-forster/keyleash/internal/meter"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/procinfo"
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
		ok, err := d.isDescendant(ci.PID, procinfo.Process{PID: p.Bind.PID, StartTime: p.Bind.StartTime})
		if err != nil || !ok {
			return deny(denial(http.StatusUnauthorized, proxy.ReasonPassInvalid, ""))
		}
	}
	if state == StateAway && p.Kind == pass.KindRun && !d.cfg.Limits.Away.AllowNewRunPasses && !p.Created.Before(awaySince) {
		return deny(denial(http.StatusForbidden, proxy.ReasonAwayLimit, "keyleash is in away mode: run passes created while away are refused"))
	}
	entry, ok := d.entryFor(prov)
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

// entryFor returns the newest api_key entry for the provider.
func (d *Daemon) entryFor(prov string) (string, bool) {
	var best vault.EntryInfo
	found := false
	for _, e := range d.vault.Entries() {
		if e.Provider != prov || e.Kind != vault.KindAPIKey || isRootEntry(e) {
			continue
		}
		if !found || !e.Created.Before(best.Created) {
			best, found = e, true
		}
	}
	return best.ID, found
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
	// 3. Estimate.
	amount, priced := d.meter.Estimate(a.Provider.Name, a.Info)
	if !priced || amount < 0 {
		d.mu.Lock()
		d.st.modelsSeen[a.Provider.Name+"/"+model] = true
		awayNow := d.st.state == StateAway
		amount = d.fallbackAmountLocked(a.Provider.Name, p.ID)
		d.mu.Unlock()
		if awayNow {
			return deny(denial(http.StatusForbidden, proxy.ReasonModelDenied, "keyleash is in away mode: unpriced models are refused"))
		}
		switch d.cfg.Models.Unknown {
		case "deny":
			return deny(denial(http.StatusForbidden, proxy.ReasonModelDenied, "keyleash has no price for this model and the policy denies unknown models"))
		case "approve":
			dec, err := d.queue.Request(ctx, approval.Request{
				Kind: "unknown_model", Title: "Allow an unpriced model",
				Detail: fmt.Sprintf("%s model %q has no price; it will be charged %s per request", a.Provider.Name, model, amount),
				PassID: p.ID, Model: model, Amount: amount,
				CoalesceKey: "unknown_model:" + p.ID + ":" + a.Provider.Name + "/" + model,
			})
			d.auditEvent("approval", map[string]any{"kind": "unknown_model", "approved": err == nil && dec.Approved,
				"method": dec.Method, "pass": p.ID, "model": model, "amount_micros": int64(amount)})
			if dn := approvalDenial(ctx, dec, err); dn != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				return deny(dn)
			}
		}
		priced = false
	}

	// 4–5. Reserve against every applicable scope.
	for attempt := 0; ; attempt++ {
		res, err := d.reserve(a, p, amount)
		if err == nil {
			return &ticket{d: d, a: a, res: res, unpriced: !priced}, nil
		}
		var ex *budget.ExceededError
		var dn *proxy.Denial
		switch {
		case errors.As(err, &dn):
			return deny(dn)
		case errors.As(err, &ex):
			if ex.Scope == budget.ScopeAway || strings.HasPrefix(ex.Scope, budget.ScopeGrantPrefix) {
				return deny(denial(http.StatusForbidden, proxy.ReasonAwayLimit, exceededMessage(ex)))
			}
			if d.cfg.Limits.OnExceed == "approve" && attempt == 0 {
				dec, aerr := d.queue.Request(ctx, approval.Request{
					Kind: "over_limit", Title: "Exceed a keyleash spend limit",
					Detail: exceededMessage(ex), PassID: p.ID, Model: model, Amount: amount,
					CoalesceKey: "over_limit:" + p.ID + ":" + ex.Scope + ":" + string(ex.Window),
				})
				d.auditEvent("approval", map[string]any{"kind": "over_limit", "approved": aerr == nil && dec.Approved,
					"method": dec.Method, "pass": p.ID, "model": model, "amount_micros": int64(amount), "scope": ex.Scope})
				if adn := approvalDenial(ctx, dec, aerr); adn != nil {
					if ctx.Err() != nil {
						return nil, ctx.Err()
					}
					return deny(adn)
				}
				d.addOverlay(ex, amount, dec.Grant)
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
		return fmt.Sprintf("keyleash spend limit: this request could cost up to %s, over the %s per-request limit of %s",
			ex.Requested, ex.Scope, ex.Limit)
	}
	remaining := ex.Limit - ex.Spent - ex.Reserved
	if remaining < 0 {
		remaining = 0
	}
	return fmt.Sprintf("keyleash spend limit reached: %s %s limit %s, remaining %s, this request needs up to %s",
		ex.Scope, ex.Window, ex.Limit, remaining, ex.Requested)
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
// (and the reservation is settled by the lock).
func (d *Daemon) reserve(a proxy.Admission, p pass.Pass, amount money.Micros) (*budget.Reservation, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	switch d.st.state {
	case StateLocked:
		return nil, denial(http.StatusLocked, proxy.ReasonLocked, "")
	case StateTripped:
		return nil, denial(http.StatusLocked, proxy.ReasonTripped, "")
	}
	scopes := []string{
		budget.ScopeProviderPrefix + a.Provider.Name,
		budget.ScopePassPrefix + p.ID,
		budgetSessionScope(d.st.session),
	}
	if d.st.state == StateAway {
		if g := d.st.grant; g != nil && d.clk.Now().Before(g.until) && (g.pass == "" || g.pass == p.ID) {
			scopes = append(scopes, budget.ScopeGrantPrefix+g.id)
		} else {
			scopes = append(scopes, budget.ScopeAway)
		}
	}
	return d.ledger.Reserve(scopes, amount, budget.Meta{
		PassID: p.ID, Provider: a.Provider.Name, Model: a.Info.Model, Session: d.st.session,
		Client: clientName(a.Client), RequestID: a.RequestID,
	})
}

// addOverlay raises the exceeded limit after an approval: by the grant (if
// any) for its duration, else by the shortfall for this request only
// (five minutes).
func (d *Daemon) addOverlay(ex *budget.ExceededError, amount money.Micros, g *approval.Grant) {
	now := d.clk.Now()
	o := overlay{scope: ex.Scope, window: ex.Window}
	if g != nil && g.Amount > 0 && g.For > 0 {
		o.amount, o.until = g.Amount, now.Add(g.For)
	} else {
		short := ex.Spent + ex.Reserved + ex.Requested - ex.Limit
		if ex.Window == budget.WindowRequest {
			short = ex.Requested - ex.Limit
		}
		o.amount, o.until = max(short, amount), now.Add(5*time.Minute)
	}
	d.mu.Lock()
	d.st.overlays = append(d.st.overlays, o)
	d.applyLimitsLocked()
	d.mu.Unlock()
	d.auditEvent("limit_change", map[string]any{"change": "approved_overlay", "scope": o.scope,
		"window": string(o.window), "amount_micros": int64(o.amount), "until": o.until.UTC().Format("2006-01-02T15:04:05Z")})
}

// ---- Ticket ----------------------------------------------------------------

type ticket struct {
	d        *Daemon
	a        proxy.Admission
	res      *budget.Reservation // nil for unmetered endpoints
	unpriced bool
}

// Finish implements proxy.Ticket: release when the request never left,
// otherwise settle at the metered cost, or at the reserved amount (marked
// estimated) when usage or price is unknown.
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
			c, priced := d.meter.Cost(t.a.Provider.Name, u)
			if o.UsageOK && priced && c >= 0 {
				cost = c
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
