package budget

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

// DefaultFlushInterval is used when Options.FlushInterval is zero (spec §7.7:
// fsync'd in batches of at most one second).
const DefaultFlushInterval = time.Second

// histTail is how far back history is kept (and replayed from the previous
// month) beyond the current calendar month, so rolling windows and the
// tripwire see spend across a month boundary.
const histTail = 24 * time.Hour

// Options configures Open.
type Options struct {
	// Dir holds the ledger files ledger-YYYY-MM.jsonl. It is created (0700)
	// if missing. Required.
	Dir string
	// Clock defaults to the system clock.
	Clock Clock
	// Location is used for calendar windows (day, month) and file names.
	// Defaults to time.Local.
	Location *time.Location
	// FlushInterval bounds how long a settled record may sit in memory
	// before it is written and fsync'd. Defaults to DefaultFlushInterval.
	FlushInterval time.Duration
}

// Ledger is the spend ledger. All methods are safe for concurrent use.
type Ledger struct {
	dir   string
	clock Clock
	loc   *time.Location

	mu         sync.Mutex
	limits     []Limit
	aggs       []*agg // parallel to limits; nil for request windows
	conc       map[string]int
	active     map[*Reservation]struct{}
	hist       []*charge
	histHead   int
	seq        uint64
	sessionSeq map[string]uint64

	tripDur       time.Duration
	tripThreshold money.Micros
	onTrip        func(money.Micros)
	trip          *agg
	tripped       bool

	closed     bool
	persistErr error
	w          *writer

	stop     chan struct{}
	stopOnce sync.Once
	done     chan struct{}
}

// Reservation is an amount held against limits while a request is in flight.
// Exactly one of Settle or Release should be called.
type Reservation struct {
	l      *Ledger
	id     string
	scopes []string
	meta   Meta
	amount money.Micros
	done   bool // guarded by l.mu
}

// ID is the reservation's record id (Meta.RequestID or a random id).
func (r *Reservation) ID() string { return r.id }

// Amount is the reserved amount.
func (r *Reservation) Amount() money.Micros { return r.amount }

// Open loads the ledger in opts.Dir, replaying the current month's file (and
// the last day of the previous month's) to rebuild windows. A truncated final
// line (crash mid-write) is discarded and cut from the file; any other
// corruption is an error.
func Open(opts Options) (*Ledger, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("%w: ledger dir is required", ErrInvalid)
	}
	if opts.Clock == nil {
		opts.Clock = realClock{}
	}
	if opts.Location == nil {
		opts.Location = time.Local
	}
	if opts.FlushInterval < 0 {
		return nil, fmt.Errorf("%w: negative flush interval", ErrInvalid)
	}
	if opts.FlushInterval == 0 {
		opts.FlushInterval = DefaultFlushInterval
	}
	l := &Ledger{
		dir:        opts.Dir,
		clock:      opts.Clock,
		loc:        opts.Location,
		conc:       map[string]int{},
		active:     map[*Reservation]struct{}{},
		sessionSeq: map[string]uint64{},
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	hist, err := replay(opts.Dir, opts.Clock.Now(), opts.Location)
	if err != nil {
		return nil, err
	}
	l.hist = hist
	l.w = newWriter(opts.Dir)
	go l.flusher(opts.FlushInterval)
	return l, nil
}

func (l *Ledger) flusher(every time.Duration) {
	defer close(l.done)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			_ = l.Flush() // a failure is recorded in persistErr
		}
	}
}

// SetLimits replaces all limits. Spend already recorded counts toward new
// limits immediately (aggregators for an unchanged scope+window are kept).
func (l *Ledger) SetLimits(limits []Limit) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	old := map[Limit]*agg{}
	for i, lim := range l.limits {
		if l.aggs[i] != nil {
			old[Limit{Scope: lim.Scope, Window: lim.Window}] = l.aggs[i]
		}
	}
	l.limits = slices.Clone(limits)
	l.aggs = make([]*agg, len(limits))
	for i, lim := range l.limits {
		if lim.Window == WindowRequest {
			continue
		}
		key := Limit{Scope: lim.Scope, Window: lim.Window}
		if a, ok := old[key]; ok {
			a.lim = lim
			l.aggs[i] = a
			continue
		}
		a := newAgg(lim, l.hist[l.histHead:], now, l.loc, l.sessionSeq[lim.Scope])
		old[key] = a // duplicate limits on one scope+window share counters
		l.aggs[i] = a
	}
}

// SetConcurrency caps in-flight reservations matching scope at n (0 or less
// removes the cap).
func (l *Ledger) SetConcurrency(scope string, n int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if n <= 0 {
		delete(l.conc, scope)
		return
	}
	l.conc[scope] = n
}

// SetTripwire configures the velocity tripwire: when settled spend in the
// rolling window plus all in-flight reservations would exceed threshold, the
// ledger trips. onTrip (may be nil) is called once per trip, outside the
// ledger's lock, with the amount that tripped it. A window or threshold of 0
// disables the tripwire.
func (l *Ledger) SetTripwire(window time.Duration, threshold money.Micros, onTrip func(spent money.Micros)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tripDur, l.tripThreshold, l.onTrip = window, threshold, onTrip
	l.trip = nil
	if window > 0 && threshold > 0 {
		l.trip = l.newTripAgg(l.clock.Now())
	}
}

func (l *Ledger) newTripAgg(now time.Time) *agg {
	a := &agg{matchAll: true, dur: l.tripDur}
	for _, c := range l.hist[l.histHead:] {
		a.evs = append(a.evs, event{t: c.t, amount: c.amount})
		a.sum = addSat(a.sum, c.amount)
	}
	a.refresh(now, l.loc)
	return a
}

// Reserve atomically holds amount against every limit that applies to scopes
// (plus "global", always) and meta.Model, and takes a concurrency slot in
// every capped scope that applies. Either everything is reserved or nothing
// is. Errors: *ExceededError (ErrExceeded), *ConcurrencyError
// (ErrConcurrency), ErrTripped, ErrClosed, ErrPersist, ErrInvalid.
func (l *Ledger) Reserve(scopes []string, amount money.Micros, meta Meta) (*Reservation, error) {
	if amount < 0 {
		return nil, fmt.Errorf("%w: negative amount", ErrInvalid)
	}
	sc := make([]string, 0, len(scopes)+1)
	sc = append(sc, ScopeGlobal)
	for _, s := range scopes {
		if err := ValidateScope(s); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if !slices.Contains(sc, s) {
			sc = append(sc, s)
		}
	}
	id := meta.RequestID
	if id == "" {
		id = newID()
	}
	r := &Reservation{l: l, id: id, scopes: sc, meta: meta, amount: amount}

	var fire func(money.Micros)
	var fired money.Micros
	err := func() error {
		l.mu.Lock()
		defer l.mu.Unlock()
		switch {
		case l.closed:
			return ErrClosed
		case l.persistErr != nil:
			return fmt.Errorf("%w; refusing new reservations", ErrPersist)
		case l.tripped:
			return ErrTripped
		}
		now := l.clock.Now()
		for i, lim := range l.limits {
			if !scopeMatches(lim.Scope, sc, meta.Model) {
				continue
			}
			if lim.Window == WindowRequest {
				if amount > lim.Amount {
					return &ExceededError{Scope: lim.Scope, Window: lim.Window, Limit: lim.Amount, Requested: amount}
				}
				continue
			}
			spent := l.aggs[i].settled(now, l.loc)
			held := l.reservedLocked(lim.Scope)
			if addSat(addSat(spent, held), amount) > lim.Amount {
				return &ExceededError{Scope: lim.Scope, Window: lim.Window, Limit: lim.Amount,
					Spent: spent, Reserved: held, Requested: amount}
			}
		}
		for _, scope := range sortedKeys(l.conc) {
			n := l.conc[scope]
			if !scopeMatches(scope, sc, meta.Model) {
				continue
			}
			if l.inflightLocked(scope) >= n {
				return &ConcurrencyError{Scope: scope, Limit: n}
			}
		}
		if l.trip != nil {
			total := addSat(addSat(l.trip.settled(now, l.loc), l.reservedLocked("")), amount)
			if total > l.tripThreshold {
				// Fail closed: the request that would cross the threshold is
				// refused, and the ledger trips.
				l.tripped = true
				fire, fired = l.onTrip, total
				return ErrTripped
			}
		}
		l.active[r] = struct{}{}
		return nil
	}()
	if fire != nil {
		fire(fired)
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// reservedLocked sums in-flight reservations matching scope ("" = all).
func (l *Ledger) reservedLocked(scope string) money.Micros {
	var s money.Micros
	for r := range l.active {
		if scope == "" || scopeMatches(scope, r.scopes, r.meta.Model) {
			s = addSat(s, r.amount)
		}
	}
	return s
}

func (l *Ledger) inflightLocked(scope string) int {
	n := 0
	for r := range l.active {
		if scopeMatches(scope, r.scopes, r.meta.Model) {
			n++
		}
	}
	return n
}

// Settle replaces the reservation with the actual cost in every window and
// appends a record to the ledger file. actual may exceed the reserved amount:
// it is charged in full and the record is flagged as an overrun. estimated
// marks a cost that could not be measured (the caller charges the reserved
// amount, spec §7.3). A negative actual is charged as the reserved amount,
// marked estimated, and reported as ErrInvalid. A second Settle (or Settle
// after Release) charges nothing and returns ErrAlreadySettled. After Close
// the charge still counts in memory but cannot be written: ErrClosed.
func (r *Reservation) Settle(actual money.Micros, estimated bool) error {
	l := r.l
	var retErr error
	if actual < 0 {
		actual, estimated = r.amount, true
		retErr = fmt.Errorf("%w: negative actual cost; charged the reservation", ErrInvalid)
	}
	var fire func(money.Micros)
	var fired money.Micros
	err := func() error {
		l.mu.Lock()
		defer l.mu.Unlock()
		if r.done {
			return ErrAlreadySettled
		}
		r.done = true
		delete(l.active, r)
		now := l.clock.Now()
		l.seq++
		c := &charge{t: now, amount: actual, scopes: r.scopes, model: r.meta.Model, seq: l.seq}
		l.hist = append(l.hist, c)
		l.pruneHistLocked(now)
		for i, a := range l.aggs {
			if a != nil && a.matches(c) && !slices.ContainsFunc(l.aggs[:i], func(b *agg) bool { return b == a }) {
				a.addLive(c, now, l.loc)
			}
		}
		if l.trip != nil {
			l.trip.addLive(c, now, l.loc)
			total := addSat(l.trip.sum, l.reservedLocked(""))
			if !l.tripped && total > l.tripThreshold {
				l.tripped = true
				fire, fired = l.onTrip, total
			}
		}
		rec := record{
			TS: now.UTC(), ID: r.id, Scopes: r.scopes,
			Amount: actual, Reserved: r.amount, Estimated: estimated, Overrun: actual > r.amount,
			Pass: r.meta.PassID, Provider: r.meta.Provider, Model: r.meta.Model,
			Session: r.meta.Session, Client: r.meta.Client,
		}
		if l.closed {
			return ErrClosed
		}
		return l.w.enqueue(rec, now.In(l.loc))
	}()
	if fire != nil {
		fire(fired)
	}
	if err != nil {
		return err
	}
	return retErr
}

// Release drops the reservation without charging (the request never reached
// upstream) and frees its concurrency slots. It is a no-op after Settle or a
// previous Release.
func (r *Reservation) Release() {
	l := r.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if r.done {
		return
	}
	r.done = true
	delete(l.active, r)
}

// pruneHistLocked drops charges older than both the current calendar month
// and the rolling tail (max of histTail and the tripwire window).
func (l *Ledger) pruneHistLocked(now time.Time) {
	tail := max(histTail, l.tripDur)
	cutoff := periodStart(WindowMonth, now, l.loc)
	if t := now.Add(-tail); t.Before(cutoff) {
		cutoff = t
	}
	for l.histHead < len(l.hist) && l.hist[l.histHead].t.Before(cutoff) {
		l.hist[l.histHead] = nil
		l.histHead++
	}
	if l.histHead > 1024 && l.histHead > len(l.hist)/2 {
		n := copy(l.hist, l.hist[l.histHead:])
		clear(l.hist[n:])
		l.hist, l.histHead = l.hist[:n], 0
	}
}

// Spent returns settled spend for scope over window w, and the in-flight
// reservations that scope's limits would see. For WindowRequest both are 0.
func (l *Ledger) Spent(scope string, w Window) (settled, reserved money.Micros) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if w == WindowRequest || !w.Valid() {
		return 0, 0
	}
	now := l.clock.Now()
	reserved = l.reservedLocked(scope)
	for i, lim := range l.limits {
		if l.aggs[i] != nil && lim.Scope == scope && lim.Window == w {
			return l.aggs[i].settled(now, l.loc), reserved
		}
	}
	a := newAgg(Limit{Scope: scope, Window: w}, l.hist[l.histHead:], now, l.loc, l.sessionSeq[scope])
	return a.settled(now, l.loc), reserved
}

// Status reports every limit with its settled, reserved and remaining amounts.
func (l *Ledger) Status() []LimitStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	out := make([]LimitStatus, 0, len(l.limits))
	for i, lim := range l.limits {
		st := LimitStatus{Limit: lim, Remaining: lim.Amount}
		if l.aggs[i] != nil {
			st.Settled = l.aggs[i].settled(now, l.loc)
			st.Reserved = l.reservedLocked(lim.Scope)
			st.Remaining = max(0, lim.Amount-addSat(st.Settled, st.Reserved))
		}
		out = append(out, st)
	}
	return out
}

// ResetSession starts a new session window for sessionScope (e.g. "global" or
// "session:<id>" on unlock): session limits on that exact scope count only
// spend settled from now on.
func (l *Ledger) ResetSession(sessionScope string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sessionSeq[sessionScope] = l.seq
	for i, lim := range l.limits {
		if lim.Window == WindowSession && lim.Scope == sessionScope && l.aggs[i] != nil {
			l.aggs[i].total = 0
		}
	}
}

// Tripped reports whether the velocity tripwire has tripped.
func (l *Ledger) Tripped() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tripped
}

// ResetTrip leaves the tripped state (after step-up approval). Spend that
// tripped the wire is treated as approved: the tripwire window restarts from
// zero settled spend (in-flight reservations still count).
func (l *Ledger) ResetTrip() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tripped = false
	if l.trip != nil {
		l.trip = &agg{matchAll: true, dur: l.tripDur}
	}
}

// Flush writes and fsyncs all pending records.
func (l *Ledger) Flush() error {
	l.w.mu.Lock()
	defer l.w.mu.Unlock()
	l.mu.Lock()
	batch := l.w.take()
	l.mu.Unlock()
	if err := l.w.writeLocked(batch); err != nil {
		l.mu.Lock()
		l.w.putBack(batch)
		if l.persistErr == nil {
			l.persistErr = err
		}
		l.mu.Unlock()
		return err
	}
	if len(batch) > 0 {
		// Everything that failed earlier was put back and is now on disk.
		l.mu.Lock()
		l.persistErr = nil
		l.mu.Unlock()
	}
	return nil
}

// Close stops the background flusher, flushes pending records and closes the
// file. New reservations fail with ErrClosed. Close is idempotent.
func (l *Ledger) Close() error {
	l.mu.Lock()
	l.closed = true
	l.mu.Unlock()
	l.stopOnce.Do(func() { close(l.stop) })
	<-l.done
	err := l.Flush()
	l.w.mu.Lock()
	cerr := l.w.closeLocked()
	l.w.mu.Unlock()
	return errors.Join(err, cerr)
}

func newID() string {
	var b [12]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go ≥ 1.24)
	return hex.EncodeToString(b[:])
}

func sortedKeys(m map[string]int) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}
