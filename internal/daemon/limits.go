package daemon

import (
	"sort"
	"strings"

	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/glob"
	"github.com/h-a-forster/keyleash/internal/money"
)

// applyLimits rebuilds every ledger limit and concurrency cap.
func (d *Daemon) applyLimits() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.applyLimitsLocked()
}

// applyLimitsLocked pushes the limits of buildLimitsLocked to the ledger and
// reconciles concurrency caps. Caller holds d.mu.
func (d *Daemon) applyLimitsLocked() {
	d.ledger.SetLimits(d.buildLimitsLocked())
	want := d.concurrencyLocked()
	for sc := range d.st.concScopes {
		if _, ok := want[sc]; !ok {
			d.ledger.SetConcurrency(sc, 0)
			delete(d.st.concScopes, sc)
		}
	}
	for sc, n := range want {
		d.ledger.SetConcurrency(sc, n)
		d.st.concScopes[sc] = true
	}
}

func addWindows(out []budget.Limit, scope string, l config.Limits) []budget.Limit {
	ws := l.Windows()
	names := make([]string, 0, len(ws))
	for w := range ws {
		names = append(names, w)
	}
	sort.Strings(names)
	for _, w := range names {
		out = append(out, budget.Limit{Scope: scope, Window: budget.Window(w), Amount: ws[w]})
	}
	return out
}

// buildLimitsLocked derives the ledger limits from config, active passes,
// the active away grant and the pass grants of over-limit approvals (docs/DAEMON.md "Scopes").
func (d *Daemon) buildLimitsLocked() []budget.Limit {
	var out []budget.Limit
	c := d.cfg
	out = addWindows(out, budget.ScopeGlobal, c.Limits.Global)
	for _, p := range sortedKeys(c.Limits.Provider) {
		out = addWindows(out, budget.ScopeProviderPrefix+p, c.Limits.Provider[p])
	}
	for _, g := range sortedKeys(c.Limits.Model) {
		out = addWindows(out, budget.ScopeModelPrefix+g, c.Limits.Model[g])
	}
	if c.Limits.Away.Total != nil {
		out = append(out, budget.Limit{Scope: budget.ScopeAway, Window: budget.WindowSession, Amount: c.Limits.Away.Total.Micros})
	}
	now := d.clk.Now()
	for _, p := range d.passes.List() {
		if p.Revoked || p.Expired(now) {
			continue
		}
		for _, ls := range p.Limits {
			out = append(out, budget.Limit{Scope: budget.ScopePassPrefix + p.ID, Window: budget.Window(ls.Window), Amount: ls.Amount})
		}
	}
	if g := d.st.grant; g != nil {
		out = append(out, budget.Limit{Scope: budget.ScopeGrantPrefix + g.id, Window: budget.WindowSession, Amount: g.amount})
	}
	for _, pg := range d.st.passGrants {
		if now.Before(pg.until) {
			out = append(out, budget.Limit{Scope: budget.ScopeGrantPrefix + pg.id, Window: budget.WindowSession, Amount: pg.amount})
		}
	}
	return out
}

// concurrencyLocked returns the concurrency caps by scope.
func (d *Daemon) concurrencyLocked() map[string]int {
	c := d.cfg
	want := map[string]int{}
	if c.Limits.Global.Concurrency > 0 {
		want[budget.ScopeGlobal] = c.Limits.Global.Concurrency
	}
	for p, l := range c.Limits.Provider {
		if l.Concurrency > 0 {
			want[budget.ScopeProviderPrefix+p] = l.Concurrency
		}
	}
	for g, l := range c.Limits.Model {
		if l.Concurrency > 0 {
			want[budget.ScopeModelPrefix+g] = l.Concurrency
		}
	}
	if c.Limits.Away.Concurrency > 0 {
		want[budget.ScopeAway] = c.Limits.Away.Concurrency
	}
	now := d.clk.Now()
	for _, p := range d.passes.List() {
		if p.Revoked || p.Expired(now) || p.MaxConcurrency <= 0 {
			continue
		}
		want[budget.ScopePassPrefix+p.ID] = p.MaxConcurrency
	}
	return want
}

// requestLimitLocked is the smallest per-request limit that applies to a
// request (global, provider, model or pass scope), or 0 when none does. It
// is the reservation for a request whose cost cannot be bounded (spec §7.5).
func (d *Daemon) requestLimitLocked(providerName, model, passID string) money.Micros {
	amt := money.Micros(0)
	for _, l := range d.buildLimitsLocked() {
		if l.Window != budget.WindowRequest {
			continue
		}
		match := l.Scope == budget.ScopeGlobal || l.Scope == budget.ScopeProviderPrefix+providerName || l.Scope == budget.ScopePassPrefix+passID
		if pat, ok := strings.CutPrefix(l.Scope, budget.ScopeModelPrefix); ok {
			match = !glob.Valid(pat) || glob.Match(pat, model)
		}
		if match && (amt == 0 || l.Amount < amt) {
			amt = l.Amount
		}
	}
	return amt
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
