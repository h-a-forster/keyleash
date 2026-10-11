// Package pass issues, verifies and revokes passes: scoped, revocable,
// local-only stand-ins that clients hold instead of real provider keys
// (spec §6).
//
// A pass token is "klp_<id>_<secret>". The store keeps only
// SHA-256(secret) (over the 32 decoded secret bytes) next to the pass scope;
// the secret itself is shown once at issue time and never persisted, logged
// or echoed in errors.
package pass

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/h-a-forster/keyleash/internal/glob"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// Pass kinds.
const (
	KindNamed = "named" // created by the owner, e.g. for an editor
	KindRun   = "run"   // ephemeral, created by `keyleash run`, process-bound
)

// AllProviders in Pass.Providers allows every registered provider.
const AllProviders = "*"

// Errors returned by Verify and the store. They never contain the token.
var (
	ErrInvalid  = errors.New("pass: invalid pass")
	ErrExpired  = errors.New("pass: pass expired")
	ErrRevoked  = errors.New("pass: pass revoked")
	ErrNotFound = errors.New("pass: no such pass")
)

// Clock supplies the current time. Tests inject a fake one.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// LimitSpec is a per-pass spend limit; Window uses the budget package's
// window names ("request", "minute", "hour", "day", "month", "session").
type LimitSpec struct {
	Window string       `json:"window"`
	Amount money.Micros `json:"amount_micros"`
}

// Binding ties a pass to a process (spec §6 bind). StartTime guards against
// PID reuse; its unit is whatever procinfo reports.
type Binding struct {
	PID       int    `json:"pid"`
	StartTime int64  `json:"start_time"`
	Image     string `json:"image,omitempty"`
}

// Pass is a pass's metadata and scope. It never contains the secret.
type Pass struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
	// Providers lists provider names this pass may use; AllProviders ("*")
	// allows all. An empty list allows none (fail closed); Issue rejects it.
	Providers []string `json:"providers"`
	// ModelAllow / ModelDeny are case-insensitive internal/glob patterns;
	// '*' also matches '/', so "*opus*" covers "anthropic/claude-opus-4".
	ModelAllow     []string    `json:"model_allow,omitempty"`
	ModelDeny      []string    `json:"model_deny,omitempty"`
	MaxConcurrency int         `json:"max_concurrency,omitempty"` // 0 = no per-pass cap beyond policy
	Limits         []LimitSpec `json:"limits,omitempty"`
	Bind           *Binding    `json:"bind,omitempty"`
	Revoked        bool        `json:"revoked,omitempty"`
	RevokedAt      time.Time   `json:"revoked_at,omitzero"`
	LastUsed       time.Time   `json:"last_used,omitzero"`
}

// AllowsModel reports whether model may be used with this pass. Deny globs
// win; an empty allow list allows every model not denied. Matching uses
// internal/glob (case-insensitive, '*' matches '/'). A pattern glob.Valid
// rejects (Issue refuses them) counts as matching in the deny list and not
// matching in the allow list, so it always fails closed.
func (p Pass) AllowsModel(model string) bool {
	for _, g := range p.ModelDeny {
		if !glob.Valid(g) || glob.Match(g, model) {
			return false
		}
	}
	if len(p.ModelAllow) == 0 {
		return true
	}
	for _, g := range p.ModelAllow {
		if glob.Valid(g) && glob.Match(g, model) {
			return true
		}
	}
	return false
}

// AllowsProvider reports whether the pass may use provider name
// (case-insensitive). "*" allows all; an empty list allows none.
func (p Pass) AllowsProvider(name string) bool {
	n := strings.ToLower(name)
	if n == "" {
		return false
	}
	for _, q := range p.Providers {
		if q == AllProviders || strings.ToLower(q) == n {
			return true
		}
	}
	return false
}

// Expired reports whether the pass has expired at now.
func (p Pass) Expired(now time.Time) bool {
	return !now.Before(p.Expires)
}

func (p Pass) clone() Pass {
	c := p
	c.Providers = append([]string(nil), p.Providers...)
	c.ModelAllow = append([]string(nil), p.ModelAllow...)
	c.ModelDeny = append([]string(nil), p.ModelDeny...)
	c.Limits = append([]LimitSpec(nil), p.Limits...)
	if p.Bind != nil {
		b := *p.Bind
		c.Bind = &b
	}
	return c
}

const (
	maxNameLen  = 128
	maxGlobs    = 64
	maxGlobLen  = 256
	maxLimits   = 32
	maxImageLen = 4096
)

var validWindows = map[string]bool{
	"request": true, "minute": true, "hour": true, "day": true, "month": true, "session": true,
}

// validate checks a pass submitted to Issue. now is the issue time.
func validate(p *Pass, now time.Time) error {
	switch p.Kind {
	case KindNamed, KindRun:
	default:
		return fmt.Errorf("pass: unknown kind %q", p.Kind)
	}
	if len(p.Name) > maxNameLen {
		return errors.New("pass: name too long")
	}
	for _, r := range p.Name {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return errors.New("pass: name contains control or invalid characters")
		}
	}
	if p.Expires.IsZero() {
		return errors.New("pass: expiry is required")
	}
	if !p.Expires.After(now) {
		return errors.New("pass: expiry is in the past")
	}
	if len(p.Providers) == 0 {
		return errors.New("pass: at least one provider (or \"*\") is required")
	}
	for i, q := range p.Providers {
		if q == AllProviders {
			continue
		}
		q = strings.ToLower(q)
		if _, ok := provider.Get(q); !ok {
			return fmt.Errorf("pass: unknown provider %q", q)
		}
		p.Providers[i] = q
	}
	for _, list := range [][]string{p.ModelAllow, p.ModelDeny} {
		if len(list) > maxGlobs {
			return errors.New("pass: too many model patterns")
		}
		for _, g := range list {
			if len(g) > maxGlobLen {
				return errors.New("pass: overlong model pattern")
			}
			if !glob.Valid(g) {
				return fmt.Errorf("pass: bad model pattern %q", g)
			}
		}
	}
	if p.MaxConcurrency < 0 {
		return errors.New("pass: negative max concurrency")
	}
	if len(p.Limits) > maxLimits {
		return errors.New("pass: too many limits")
	}
	for _, l := range p.Limits {
		if !validWindows[l.Window] {
			return fmt.Errorf("pass: unknown limit window %q", l.Window)
		}
		if l.Amount <= 0 {
			return errors.New("pass: limit amount must be positive")
		}
	}
	if p.Bind != nil {
		if p.Bind.PID <= 0 {
			return errors.New("pass: binding needs a positive PID")
		}
		if len(p.Bind.Image) > maxImageLen {
			return errors.New("pass: binding image path too long")
		}
	}
	return nil
}
