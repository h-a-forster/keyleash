package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// DefaultTimeout is used when NewQueue is given a non-positive timeout
// (spec §14 approval.timeout).
const DefaultTimeout = 60 * time.Second

// Clock supplies time and timers. Tests inject a fake one.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// PendingInfo describes a request waiting for a decision.
type PendingInfo struct {
	ID       string
	Request  Request
	Prompt   string // sanitised text, safe to display
	Created  time.Time
	Deadline time.Time
	Waiters  int
}

type pending struct {
	id       string
	req      Request
	created  time.Time
	deadline time.Time
	waiters  int
	done     chan struct{}
	resolved bool
	dec      Decision
	err      error
	cancel   context.CancelFunc
}

// Queue serialises step-up approvals. For each new request it runs the
// Approver and a timeout concurrently; an external Decide (admin API) races
// both. The first answer wins and the losers are cancelled. It is safe for
// concurrent use.
type Queue struct {
	a       Approver
	timeout time.Duration
	clk     Clock

	mu    sync.Mutex
	byID  map[string]*pending
	byKey map[string]*pending
}

// NewQueue returns a queue using approver a. A nil a denies everything; a
// non-positive timeout means DefaultTimeout; a nil clk is the real clock.
func NewQueue(a Approver, timeout time.Duration, clk Clock) *Queue {
	if a == nil {
		a = DenyApprover{}
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if clk == nil {
		clk = realClock{}
	}
	return &Queue{a: a, timeout: timeout, clk: clk, byID: map[string]*pending{}, byKey: map[string]*pending{}}
}

// Request asks for approval and blocks until a decision, the timeout or ctx
// cancellation.
//
//   - Approved or denied: (Decision, nil).
//   - Timeout: Decision{Approved: false, Method: "timeout"} and ErrTimeout.
//   - Approver failure or panic: a denial and an error wrapping ErrApprover.
//   - ctx cancelled: a denial and ctx.Err(). The pending request itself is
//     cancelled only when its last waiter leaves.
//
// Requests with the same non-empty CoalesceKey join the pending one and all
// receive the same decision. Every non-nil error comes with Approved=false.
func (q *Queue) Request(ctx context.Context, req Request) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return Decision{Method: "cancelled"}, err
	}
	q.mu.Lock()
	if req.CoalesceKey != "" {
		if p, ok := q.byKey[req.CoalesceKey]; ok {
			p.waiters++
			q.mu.Unlock()
			return q.wait(ctx, p)
		}
	}
	id, err := newID()
	if err != nil {
		q.mu.Unlock()
		return Decision{}, err
	}
	actx, cancel := context.WithCancel(context.Background())
	now := q.clk.Now()
	p := &pending{
		id: id, req: req, created: now, deadline: now.Add(q.timeout),
		waiters: 1, done: make(chan struct{}), cancel: cancel,
	}
	q.byID[id] = p
	if req.CoalesceKey != "" {
		q.byKey[req.CoalesceKey] = p
	}
	timer := q.clk.After(q.timeout)
	q.mu.Unlock()

	go q.runApprover(actx, p)
	go func() {
		select {
		case <-timer:
			q.resolve(p, Decision{Method: "timeout"}, ErrTimeout)
		case <-p.done:
		}
	}()
	return q.wait(ctx, p)
}

func (q *Queue) wait(ctx context.Context, p *pending) (Decision, error) {
	select {
	case <-p.done:
		return p.result()
	case <-ctx.Done():
		q.mu.Lock()
		p.waiters--
		if p.waiters == 0 {
			q.resolveLocked(p, Decision{Method: "cancelled"}, context.Canceled)
		}
		q.mu.Unlock()
		return Decision{ID: p.id, Method: "cancelled"}, ctx.Err()
	}
}

// result returns a per-waiter copy of the decision (done is closed, so the
// fields are immutable).
func (p *pending) result() (Decision, error) {
	d := p.dec
	d.ID = p.id
	if d.Grant != nil {
		g := *d.Grant
		d.Grant = &g
	}
	if p.err != nil {
		d.Approved = false
		d.Grant = nil
	}
	return d, p.err
}

func (q *Queue) runApprover(ctx context.Context, p *pending) {
	method := methodOf(q.a)
	defer func() {
		if r := recover(); r != nil {
			q.resolve(p, Decision{Method: method}, fmt.Errorf("%w: panic", ErrApprover))
		}
	}()
	ok, err := q.a.Approve(ctx, p.req)
	if ctx.Err() != nil {
		return // someone else already decided
	}
	if err != nil {
		q.resolve(p, Decision{Method: method}, fmt.Errorf("%w: %v", ErrApprover, err))
		return
	}
	q.resolve(p, Decision{Approved: ok, Method: method}, nil)
}

func (q *Queue) resolve(p *pending, d Decision, err error) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.resolveLocked(p, d, err)
}

// resolveLocked records the first decision for p and wakes all waiters.
func (q *Queue) resolveLocked(p *pending, d Decision, err error) bool {
	if p.resolved {
		return false
	}
	p.resolved = true
	p.dec, p.err = d, err
	delete(q.byID, p.id)
	if p.req.CoalesceKey != "" && q.byKey[p.req.CoalesceKey] == p {
		delete(q.byKey, p.req.CoalesceKey)
	}
	p.cancel()
	close(p.done)
	return true
}

// Pending lists requests awaiting a decision, oldest first.
func (q *Queue) Pending() []PendingInfo {
	q.mu.Lock()
	out := make([]PendingInfo, 0, len(q.byID))
	for _, p := range q.byID {
		out = append(out, PendingInfo{
			ID: p.id, Request: p.req, Prompt: PromptText(p.req),
			Created: p.created, Deadline: p.deadline, Waiters: p.waiters,
		})
	}
	q.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Decide answers pending request id from outside the approver (e.g. the
// admin API). It races the approver and the timeout; the loser is cancelled.
// grant is attached only to approvals. Returns ErrNotFound if id is not
// pending (unknown or already decided).
func (q *Queue) Decide(id string, approved bool, grant *Grant) error {
	d := Decision{Approved: approved, Method: "external"}
	if approved && grant != nil {
		if grant.Amount < 0 || grant.For < 0 {
			return errors.New("approval: negative grant")
		}
		g := *grant
		d.Grant = &g
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	p, ok := q.byID[id]
	if !ok || !q.resolveLocked(p, d, nil) {
		return ErrNotFound
	}
	return nil
}

func newID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("approval: random id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
