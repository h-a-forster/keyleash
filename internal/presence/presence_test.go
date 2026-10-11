package presence

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeSource struct {
	mu       sync.Mutex
	idle     time.Duration
	locked   bool
	idleErr  error
	lockErr  error
	panicIdl bool
}

func (f *fakeSource) IdleFor() (time.Duration, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.panicIdl {
		panic("boom")
	}
	return f.idle, f.idleErr
}

func (f *fakeSource) ScreenLocked() (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.locked, f.lockErr
}

func (f *fakeSource) set(fn func(*fakeSource)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type recorder struct {
	mu  sync.Mutex
	evs []Event
}

func (r *recorder) emit(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, e)
}

func (r *recorder) take() []EventKind {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]EventKind, len(r.evs))
	for i, e := range r.evs {
		out[i] = e.Kind
	}
	r.evs = nil
	return out
}

func eq(a, b []EventKind) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

var cfg = Config{IdleAfter: 10 * time.Minute, Poll: 5 * time.Second, SleepGap: 30 * time.Second}

func TestStepSequence(t *testing.T) {
	src := &fakeSource{}
	clk := &fakeClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	m := NewMonitor(src, clk, cfg)
	rec := &recorder{}

	type step struct {
		name    string
		advance time.Duration
		mutate  func(*fakeSource)
		want    []EventKind
	}
	steps := []step{
		{"initial active", 0, nil, []EventKind{Active}},
		{"steady", 5 * time.Second, nil, nil},
		{"just under threshold", 5 * time.Second, func(s *fakeSource) { s.idle = 10*time.Minute - time.Millisecond }, nil},
		{"idle at threshold", 5 * time.Second, func(s *fakeSource) { s.idle = 10 * time.Minute }, []EventKind{Idle}},
		{"still idle no repeat", 5 * time.Second, func(s *fakeSource) { s.idle = 11 * time.Minute }, nil},
		{"input resumes", 5 * time.Second, func(s *fakeSource) { s.idle = time.Second }, []EventKind{Active}},
		{"lock", 5 * time.Second, func(s *fakeSource) { s.locked = true }, []EventKind{ScreenLocked}},
		{"still locked", 5 * time.Second, nil, nil},
		{"unlock", 5 * time.Second, func(s *fakeSource) { s.locked = false }, []EventKind{ScreenUnlocked}},
		{"gap exactly poll+sleepgap is not sleep", 35 * time.Second, nil, nil},
		{"sleep then idle", 2 * time.Hour, func(s *fakeSource) { s.idle = 2 * time.Hour }, []EventKind{Resumed, Idle}},
		{"sleep then locked while still idle", time.Hour, func(s *fakeSource) { s.locked = true }, []EventKind{Resumed, ScreenLocked}},
		{"unlock and active together", 5 * time.Second, func(s *fakeSource) { s.locked = false; s.idle = 0 }, []EventKind{ScreenUnlocked, Active}},
	}
	for _, st := range steps {
		clk.advance(st.advance)
		if st.mutate != nil {
			src.set(st.mutate)
		}
		m.Step(rec.emit)
		if got := rec.take(); !eq(got, st.want) {
			t.Fatalf("%s: got %v, want %v", st.name, got, st.want)
		}
	}
}

func TestResumedGap(t *testing.T) {
	src := &fakeSource{}
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m := NewMonitor(src, clk, cfg)
	var got []Event
	m.Step(func(e Event) { got = append(got, e) })
	clk.advance(90 * time.Second)
	got = nil
	m.Step(func(e Event) { got = append(got, e) })
	if len(got) != 1 || got[0].Kind != Resumed || got[0].Gap != 90*time.Second {
		t.Fatalf("got %+v", got)
	}
	if !got[0].At.Equal(clk.Now()) {
		t.Fatalf("At = %v", got[0].At)
	}
}

func TestMonotonicStripped(t *testing.T) {
	// time.Now() values carry a monotonic reading; a clock returning a
	// wall-shifted copy of the same instant must still be seen as a gap.
	base := time.Now() // has monotonic
	clk := &fakeClock{t: base}
	m := NewMonitor(&fakeSource{}, clk, cfg)
	m.Step(nil)
	// Go cannot build a Time whose wall and monotonic readings disagree,
	// so this only checks that a monotonic-carrying start and a wall-only
	// later reading are compared on wall time.
	clk.mu.Lock()
	clk.t = base.Round(0).Add(time.Hour)
	clk.mu.Unlock()
	rec := &recorder{}
	m.Step(rec.emit)
	if got := rec.take(); !eq(got, []EventKind{Resumed}) {
		t.Fatalf("got %v", got)
	}
}

func TestWallClockBackwardsIsNotSleep(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	m := NewMonitor(&fakeSource{}, clk, cfg)
	m.Step(nil)
	clk.advance(-time.Hour)
	rec := &recorder{}
	m.Step(rec.emit)
	if got := rec.take(); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestSourceErrorsFailClosed(t *testing.T) {
	boom := errors.New("os failure")
	tests := []struct {
		name   string
		mutate func(*fakeSource)
		want   []EventKind
	}{
		{"idle error", func(s *fakeSource) { s.idleErr = boom }, []EventKind{Idle}},
		{"lock error", func(s *fakeSource) { s.lockErr = boom }, []EventKind{Idle}},
		{"idle panic", func(s *fakeSource) { s.panicIdl = true }, []EventKind{Idle}},
		{"negative idle", func(s *fakeSource) { s.idle = -time.Second }, []EventKind{Idle}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := &fakeSource{}
			clk := &fakeClock{t: time.Unix(1_000_000, 0)}
			m := NewMonitor(src, clk, cfg)
			m.Step(nil) // Active baseline
			src.set(tc.mutate)
			clk.advance(5 * time.Second)
			var evs []Event
			m.Step(func(e Event) { evs = append(evs, e) })
			if len(evs) != 1 || evs[0].Kind != Idle || evs[0].Err == nil {
				t.Fatalf("got %+v", evs)
			}
			// Recovery returns to Active.
			src.set(func(s *fakeSource) { s.idle, s.locked, s.idleErr, s.lockErr, s.panicIdl = 0, false, nil, nil, false })
			clk.advance(5 * time.Second)
			evs = nil
			m.Step(func(e Event) { evs = append(evs, e) })
			if len(evs) != 1 || evs[0].Kind != Active || evs[0].Err != nil {
				t.Fatalf("recovery got %+v", evs)
			}
		})
	}
}

func TestInitialErrorIsIdle(t *testing.T) {
	m := NewMonitor(nil, &fakeClock{t: time.Unix(1, 0)}, cfg)
	rec := &recorder{}
	m.Step(rec.emit)
	if got := rec.take(); !eq(got, []EventKind{Idle}) {
		t.Fatalf("got %v", got)
	}
}

func TestInitialLocked(t *testing.T) {
	m := NewMonitor(&fakeSource{locked: true, idle: time.Hour}, &fakeClock{t: time.Unix(1, 0)}, cfg)
	rec := &recorder{}
	m.Step(rec.emit)
	if got := rec.take(); !eq(got, []EventKind{ScreenLocked, Idle}) {
		t.Fatalf("got %v", got)
	}
}

func TestConfigDefaults(t *testing.T) {
	m := NewMonitor(&fakeSource{}, nil, Config{Poll: -1})
	c := m.Config()
	if c.IdleAfter != DefaultIdleAfter || c.Poll != DefaultPoll || c.SleepGap != DefaultSleepGap {
		t.Fatalf("defaults = %+v", c)
	}
	if _, ok := m.clk.(RealClock); !ok {
		t.Fatal("nil clock not replaced")
	}
}

func TestEventKindString(t *testing.T) {
	want := map[EventKind]string{Active: "active", Idle: "idle", ScreenLocked: "screen_locked",
		ScreenUnlocked: "screen_unlocked", Resumed: "resumed", EventKind(42): "event(42)"}
	for k, s := range want {
		if k.String() != s {
			t.Errorf("%d: %q", int(k), k.String())
		}
	}
}

func TestRunEmitsAndStops(t *testing.T) {
	src := &fakeSource{}
	m := NewMonitor(src, RealClock{}, Config{Poll: time.Millisecond, IdleAfter: time.Minute, SleepGap: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	evs := make(chan Event, 16)
	done := make(chan struct{})
	go func() {
		m.Run(ctx, func(e Event) {
			select {
			case evs <- e:
			default:
			}
		})
		close(done)
	}()
	if e := <-evs; e.Kind != Active {
		t.Fatalf("first event %v", e.Kind)
	}
	src.set(func(s *fakeSource) { s.locked = true })
	deadline := time.After(5 * time.Second)
	for {
		select {
		case e := <-evs:
			if e.Kind == ScreenLocked {
				cancel()
				select {
				case <-done:
					return
				case <-time.After(5 * time.Second):
					t.Fatal("Run did not stop")
				}
			}
		case <-deadline:
			t.Fatal("no ScreenLocked event")
		}
	}
}

func TestRunCancelledBeforeStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	NewMonitor(&fakeSource{}, nil, cfg).Run(ctx, func(Event) { called = true })
	if called {
		t.Fatal("emitted after cancel")
	}
}

func TestOSSourceSmoke(t *testing.T) {
	src := NewOSSource()
	d, err := src.IdleFor()
	if err != nil {
		t.Fatalf("IdleFor: %v", err)
	}
	if d < 0 {
		t.Fatalf("IdleFor = %v", d)
	}
	locked, err := src.ScreenLocked()
	if err != nil {
		t.Fatalf("ScreenLocked: %v", err)
	}
	t.Logf("idle=%v locked=%v", d, locked)
}
