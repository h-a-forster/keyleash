// Package presence watches whether the owner is at the machine (spec §8).
//
// A Monitor polls a Source (keyboard/mouse idle time and screen-lock state)
// and a wall Clock, and emits edge-triggered Events: Active/Idle when the
// idle threshold is crossed, ScreenLocked/ScreenUnlocked, and Resumed when
// the wall clock jumped between polls (sleep, hibernate or a long stall).
// The daemon's state machine turns these into Unlocked/Away/Locked.
//
// Errors from the Source are treated fail-closed: the owner is reported as
// Idle, never as present.
package presence

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Source reports raw presence signals from the OS.
type Source interface {
	// IdleFor returns how long ago the last keyboard/mouse input happened.
	IdleFor() (time.Duration, error)
	// ScreenLocked reports whether the interactive session is locked.
	ScreenLocked() (bool, error)
}

// Clock supplies the current time. Monitor strips the monotonic reading
// (t.Round(0)) and compares wall-clock times; see Monitor for why.
type Clock interface {
	Now() time.Time
}

// RealClock is the system clock.
type RealClock struct{}

// Now returns time.Now().
func (RealClock) Now() time.Time { return time.Now() }

// EventKind classifies an Event.
type EventKind int

// Event kinds.
const (
	// Active: input seen within IdleAfter (after being Idle, or at start).
	Active EventKind = iota
	// Idle: no input for at least IdleAfter, or the Source failed.
	Idle
	// ScreenLocked: the session became locked.
	ScreenLocked
	// ScreenUnlocked: the session became unlocked.
	ScreenUnlocked
	// Resumed: wall-clock time jumped between polls by more than
	// Poll+SleepGap, i.e. the machine slept/hibernated or the process was
	// suspended. Gap holds the observed elapsed wall time.
	Resumed
)

// String returns a stable lower-case name for logs and audit records.
func (k EventKind) String() string {
	switch k {
	case Active:
		return "active"
	case Idle:
		return "idle"
	case ScreenLocked:
		return "screen_locked"
	case ScreenUnlocked:
		return "screen_unlocked"
	case Resumed:
		return "resumed"
	default:
		return fmt.Sprintf("event(%d)", int(k))
	}
}

// Event is one presence transition.
type Event struct {
	Kind EventKind
	// At is the wall-clock time of the poll that observed the transition.
	At time.Time
	// Gap is the wall time elapsed since the previous poll (Resumed only).
	Gap time.Duration
	// Err is set when an Idle event was forced by a Source error. It
	// describes the OS failure only and never contains secrets.
	Err error
}

// Config tunes a Monitor. Zero or negative fields take the defaults.
type Config struct {
	// IdleAfter is how long without input counts as idle. Default 10m.
	IdleAfter time.Duration
	// Poll is the polling interval. Default 5s.
	Poll time.Duration
	// SleepGap is the extra wall time beyond Poll that signals a sleep.
	// Default 30s.
	SleepGap time.Duration
}

// Defaults for Config.
const (
	DefaultIdleAfter = 10 * time.Minute
	DefaultPoll      = 5 * time.Second
	DefaultSleepGap  = 30 * time.Second
)

func (c Config) withDefaults() Config {
	if c.IdleAfter <= 0 {
		c.IdleAfter = DefaultIdleAfter
	}
	if c.Poll <= 0 {
		c.Poll = DefaultPoll
	}
	if c.SleepGap <= 0 {
		c.SleepGap = DefaultSleepGap
	}
	return c
}

// Monitor turns polled Source readings into edge-triggered Events.
//
// Sleep detection compares wall-clock readings between polls. Go's
// monotonic clock cannot be used for this: on Windows it is based on
// unbiased interrupt time and on Linux/macOS on CLOCK_MONOTONIC-style
// clocks, all of which stop while the machine is suspended, so a monotonic
// difference across a sleep looks like a normal poll interval. Time values
// are therefore stripped with t.Round(0) before subtracting. The cost is
// that a large forward wall-clock adjustment also reads as a sleep; that
// errs towards locking, which is the safe direction.
//
// A Monitor is not safe for concurrent use: call Step or Run from one
// goroutine.
type Monitor struct {
	src Source
	clk Clock
	cfg Config

	started  bool
	lastWall time.Time
	idle     bool
	locked   bool
}

// NewMonitor returns a Monitor. A nil clk means RealClock.
func NewMonitor(src Source, clk Clock, cfg Config) *Monitor {
	if clk == nil {
		clk = RealClock{}
	}
	return &Monitor{src: src, clk: clk, cfg: cfg.withDefaults()}
}

// Config returns the effective configuration (defaults applied).
func (m *Monitor) Config() Config { return m.cfg }

// Run polls every Config.Poll until ctx is done, calling emit for each
// event. The first poll happens immediately and reports the initial state
// (Active or Idle, plus ScreenLocked if locked). emit is called on Run's
// goroutine and should not block for long.
func (m *Monitor) Run(ctx context.Context, emit func(Event)) {
	if ctx.Err() != nil {
		return
	}
	m.Step(emit)
	t := time.NewTicker(m.cfg.Poll)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.Step(emit)
		}
	}
}

// Step performs one poll and emits any transitions, in this order:
// Resumed, lock changes, idle/active changes. Run calls it on each tick;
// tests call it directly with a fake Clock.
func (m *Monitor) Step(emit func(Event)) {
	now := m.clk.Now().Round(0)
	var events []Event

	if m.started {
		if gap := now.Sub(m.lastWall); gap > m.cfg.Poll+m.cfg.SleepGap {
			events = append(events, Event{Kind: Resumed, At: now, Gap: gap})
		}
	}
	m.lastWall = now

	locked, lockErr := safeLocked(m.src)
	idleFor, idleErr := safeIdle(m.src)

	if lockErr == nil && (locked != m.locked || !m.started) {
		if locked {
			events = append(events, Event{Kind: ScreenLocked, At: now})
		} else if m.started {
			events = append(events, Event{Kind: ScreenUnlocked, At: now})
		}
		m.locked = locked
	}

	srcErr := errors.Join(idleErr, lockErr)
	idle := srcErr != nil || idleFor >= m.cfg.IdleAfter
	if idle != m.idle || !m.started {
		kind := Active
		if idle {
			kind = Idle
		}
		events = append(events, Event{Kind: kind, At: now, Err: srcErr})
		m.idle = idle
	}
	m.started = true

	if emit == nil {
		return
	}
	for _, e := range events {
		emit(e)
	}
}

// safeIdle calls src.IdleFor, converting panics and nonsense into errors.
func safeIdle(src Source) (d time.Duration, err error) {
	if src == nil {
		return 0, errors.New("presence: no source")
	}
	defer func() {
		if r := recover(); r != nil {
			d, err = 0, fmt.Errorf("presence: idle source panicked: %v", r)
		}
	}()
	d, err = src.IdleFor()
	if err == nil && d < 0 {
		return 0, errors.New("presence: negative idle time")
	}
	return d, err
}

// safeLocked calls src.ScreenLocked, converting panics into errors.
func safeLocked(src Source) (locked bool, err error) {
	if src == nil {
		return false, errors.New("presence: no source")
	}
	defer func() {
		if r := recover(); r != nil {
			locked, err = false, fmt.Errorf("presence: lock source panicked: %v", r)
		}
	}()
	return src.ScreenLocked()
}
