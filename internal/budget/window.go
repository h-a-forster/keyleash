package budget

import (
	"slices"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/glob"
	"github.com/h-a-forster/keyleash/internal/money"
)

// charge is one settled amount held in memory for window accounting.
type charge struct {
	t      time.Time
	amount money.Micros
	scopes []string
	model  string
	// seq is a process-local sequence number (> 0) for charges settled in
	// this process; replayed charges have seq 0 and never count toward
	// session windows.
	seq uint64
}

// scopeMatches reports whether a limit/concurrency scope applies to a request
// charged against scopes for model. Explicit scopes match exactly; a
// "model:<glob>" scope also matches when the glob matches the model (package
// glob: '*' crosses '/', case-insensitive). A malformed glob matches
// everything (fail closed).
func scopeMatches(scope string, scopes []string, model string) bool {
	if slices.Contains(scopes, scope) {
		return true
	}
	if pat, ok := strings.CutPrefix(scope, ScopeModelPrefix); ok {
		return !glob.Valid(pat) || glob.Match(pat, model)
	}
	return false
}

// periodStart is the start of the calendar period of w containing t, in loc.
func periodStart(w Window, t time.Time, loc *time.Location) time.Time {
	y, m, d := t.In(loc).Date()
	if w == WindowMonth {
		d = 1
	}
	return time.Date(y, m, d, 0, 0, 0, 0, loc)
}

type event struct {
	t      time.Time
	amount money.Micros
}

// agg accumulates settled spend for one (scope, window). It is not safe for
// concurrent use; the Ledger's mutex guards it.
type agg struct {
	lim Limit
	// matchAll makes the aggregator count every charge (used by the tripwire).
	matchAll bool
	// rolling windows: events newer than now-dur, oldest first from head.
	dur  time.Duration
	evs  []event
	head int
	sum  money.Micros
	// calendar windows.
	start time.Time
	total money.Micros
}

func (a *agg) matches(c *charge) bool {
	return a.matchAll || scopeMatches(a.lim.Scope, c.scopes, c.model)
}

// refresh drops expired rolling events and resets a calendar total when a
// period boundary has been crossed. A clock that moves backwards never
// resets anything (fail closed).
func (a *agg) refresh(now time.Time, loc *time.Location) {
	switch {
	case a.dur > 0:
		cutoff := now.Add(-a.dur)
		for a.head < len(a.evs) && !a.evs[a.head].t.After(cutoff) {
			a.sum -= a.evs[a.head].amount
			a.evs[a.head] = event{}
			a.head++
		}
		if a.head == len(a.evs) {
			a.evs, a.head = a.evs[:0], 0
		} else if a.head > 64 && a.head > len(a.evs)/2 {
			n := copy(a.evs, a.evs[a.head:])
			clear(a.evs[n:])
			a.evs, a.head = a.evs[:n], 0
		}
	case a.lim.Window == WindowDay || a.lim.Window == WindowMonth:
		if ps := periodStart(a.lim.Window, now, loc); ps.After(a.start) {
			a.start, a.total = ps, 0
		}
	}
}

// settled returns spend in the window as of now.
func (a *agg) settled(now time.Time, loc *time.Location) money.Micros {
	a.refresh(now, loc)
	if a.dur > 0 {
		return a.sum
	}
	return a.total
}

// addLive adds a charge settled just now (after refresh). It always counts in
// the current period, even if the clock has stepped backwards.
func (a *agg) addLive(c *charge, now time.Time, loc *time.Location) {
	a.refresh(now, loc)
	if a.dur > 0 {
		a.evs = append(a.evs, event{t: c.t, amount: c.amount})
		a.sum = addSat(a.sum, c.amount)
		return
	}
	a.total = addSat(a.total, c.amount)
}

// newAgg builds an aggregator for lim from the retained history.
// sessionSeq is the sequence number at the scope's last session reset.
func newAgg(lim Limit, hist []*charge, now time.Time, loc *time.Location, sessionSeq uint64) *agg {
	a := &agg{lim: lim, dur: lim.Window.rolling()}
	switch lim.Window {
	case WindowDay, WindowMonth:
		a.start = periodStart(lim.Window, now, loc)
	}
	for _, c := range hist {
		if !a.matches(c) {
			continue
		}
		switch {
		case a.dur > 0:
			a.evs = append(a.evs, event{t: c.t, amount: c.amount})
			a.sum = addSat(a.sum, c.amount)
		case lim.Window == WindowDay || lim.Window == WindowMonth:
			if !c.t.Before(a.start) {
				a.total = addSat(a.total, c.amount)
			}
		case lim.Window == WindowSession:
			if c.seq > sessionSeq {
				a.total = addSat(a.total, c.amount)
			}
		}
	}
	a.refresh(now, loc)
	return a
}
