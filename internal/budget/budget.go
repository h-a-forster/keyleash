// Package budget is the spend ledger (spec §7.2–§7.4, §7.7): atomic
// reserve → settle accounting against limits on scopes and time windows,
// per-scope concurrency caps, a velocity tripwire, and an append-only JSONL
// record of settled charges that is replayed on start.
//
// All amounts are money.Micros. Every limit is hard: at any instant, for every
// limit, settled spend in the window plus all in-flight reservations that the
// limit applies to never exceeds the limit (a settle whose actual cost exceeds
// its reservation is the one documented exception: it is charged in full and
// flagged as an overrun, and later reservations see the overshoot).
package budget

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

// Window is the period a Limit is measured over.
type Window string

// Windows. Minute and hour are rolling (the last 60 s / 60 min). Day and month
// are calendar periods in the ledger's configured Location. Session covers
// spend settled since the daemon started or since ResetSession for that scope.
// Request limits a single reservation's amount.
const (
	WindowRequest Window = "request"
	WindowMinute  Window = "minute"
	WindowHour    Window = "hour"
	WindowDay     Window = "day"
	WindowMonth   Window = "month"
	WindowSession Window = "session"
)

// Valid reports whether w is a known window.
func (w Window) Valid() bool {
	switch w {
	case WindowRequest, WindowMinute, WindowHour, WindowDay, WindowMonth, WindowSession:
		return true
	}
	return false
}

// rolling returns the duration of a rolling window, or 0 if w is not rolling.
func (w Window) rolling() time.Duration {
	switch w {
	case WindowMinute:
		return time.Minute
	case WindowHour:
		return time.Hour
	}
	return 0
}

// Scope prefixes. A scope is "global" or one of these prefixes followed by a
// non-empty name; "model:" is followed by a path.Match glob.
const (
	ScopeGlobal         = "global"
	ScopeProviderPrefix = "provider:"
	ScopePassPrefix     = "pass:"
	ScopeSessionPrefix  = "session:"
	ScopeModelPrefix    = "model:"
)

// Limit caps spend for one scope over one window.
type Limit struct {
	// Scope is "global", "provider:<name>", "pass:<id>", "session:<id>" or
	// "model:<glob>".
	Scope string
	// Window is the period the limit is measured over.
	Window Window
	// Amount is the maximum settled+reserved spend in the window (for
	// WindowRequest: the maximum amount of a single reservation).
	Amount money.Micros
}

// Validate reports whether the limit is well formed. SetLimits accepts
// invalid limits too but applies them fail-closed (a bad model glob matches
// every request); config loading should call Validate to surface mistakes.
func (l Limit) Validate() error {
	if err := ValidateScope(l.Scope); err != nil {
		return err
	}
	if !l.Window.Valid() {
		return fmt.Errorf("budget: unknown window %q", string(l.Window))
	}
	if l.Amount < 0 {
		return fmt.Errorf("budget: negative limit for %s/%s", l.Scope, l.Window)
	}
	return nil
}

// ValidateScope checks a scope string's syntax.
func ValidateScope(s string) error {
	if s == ScopeGlobal {
		return nil
	}
	for _, p := range []string{ScopeProviderPrefix, ScopePassPrefix, ScopeSessionPrefix, ScopeModelPrefix} {
		if rest, ok := strings.CutPrefix(s, p); ok {
			if rest == "" {
				return fmt.Errorf("budget: scope %q has an empty name", s)
			}
			if p == ScopeModelPrefix {
				if _, err := path.Match(rest, ""); err != nil {
					return fmt.Errorf("budget: scope %q: bad model glob", s)
				}
			}
			return nil
		}
	}
	return fmt.Errorf("budget: unknown scope %q", s)
}

// Clock supplies the current time. Tests inject a fake one.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Meta describes the request a reservation is for. It is written to the
// ledger record; it must never contain secrets (identify passes by id).
type Meta struct {
	PassID, Provider, Model, Session, Client string
	// RequestID becomes the record id; a random id is used when empty.
	RequestID string
}

// LimitStatus is one limit's current state, for the UI.
type LimitStatus struct {
	Limit
	Settled   money.Micros
	Reserved  money.Micros
	Remaining money.Micros
}

// Sentinel errors. Use errors.Is.
var (
	// ErrExceeded: a reservation would exceed a limit (see *ExceededError).
	ErrExceeded = errors.New("budget: limit exceeded")
	// ErrConcurrency: a scope's concurrency cap is full (see *ConcurrencyError).
	ErrConcurrency = errors.New("budget: concurrency limit reached")
	// ErrTripped: the velocity tripwire has tripped; call ResetTrip.
	ErrTripped = errors.New("budget: velocity tripwire tripped")
	// ErrClosed: the ledger has been closed.
	ErrClosed = errors.New("budget: ledger closed")
	// ErrAlreadySettled: the reservation was already settled or released.
	ErrAlreadySettled = errors.New("budget: reservation already settled or released")
	// ErrPersist: an earlier write of the ledger file failed; new reservations
	// are refused because spend could no longer be reconstructed after restart.
	ErrPersist = errors.New("budget: ledger persistence failed")
	// ErrInvalid: bad arguments (negative amount, malformed scope).
	ErrInvalid = errors.New("budget: invalid argument")
)

// ExceededError names the limit a reservation would have exceeded.
type ExceededError struct {
	Scope     string
	Window    Window
	Limit     money.Micros
	Spent     money.Micros // settled in the window
	Reserved  money.Micros // other in-flight reservations
	Requested money.Micros
}

func (e *ExceededError) Error() string {
	return fmt.Sprintf("budget: %s %s limit %s exceeded (spent %s, reserved %s, requested %s)",
		e.Scope, e.Window, e.Limit, e.Spent, e.Reserved, e.Requested)
}

// Is makes errors.Is(err, ErrExceeded) true.
func (e *ExceededError) Is(target error) bool { return target == ErrExceeded }

// ConcurrencyError names the scope whose concurrency cap is full.
type ConcurrencyError struct {
	Scope string
	Limit int
}

func (e *ConcurrencyError) Error() string {
	return fmt.Sprintf("budget: concurrency limit %d reached for %s", e.Limit, e.Scope)
}

// Is makes errors.Is(err, ErrConcurrency) true.
func (e *ConcurrencyError) Is(target error) bool { return target == ErrConcurrency }

// addSat adds two amounts, saturating instead of overflowing.
func addSat(a, b money.Micros) money.Micros {
	s := a + b
	if b > 0 && s < a {
		return money.Micros(1<<63 - 1)
	}
	if b < 0 && s > a {
		return money.Micros(-1 << 63)
	}
	return s
}
