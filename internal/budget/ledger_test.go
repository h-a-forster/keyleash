package budget

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	_ "time/tzdata" // deterministic zone data on every OS

	"github.com/h-a-forster/keyleash/internal/money"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time  { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Set(t time.Time) { c.mu.Lock(); c.t = t; c.mu.Unlock() }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func mustLoc(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func open(t *testing.T, dir string, clk Clock, loc *time.Location) *Ledger {
	t.Helper()
	l, err := Open(Options{Dir: dir, Clock: clk, Location: loc, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func newTest(t *testing.T) (*Ledger, *fakeClock, string) {
	t.Helper()
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)}
	return open(t, dir, clk, time.UTC), clk, dir
}

func reserve(t *testing.T, l *Ledger, scopes []string, amt money.Micros, m Meta) *Reservation {
	t.Helper()
	r, err := l.Reserve(scopes, amt, m)
	if err != nil {
		t.Fatalf("Reserve(%v, %s): %v", scopes, amt, err)
	}
	return r
}

func settle(t *testing.T, r *Reservation, amt money.Micros) {
	t.Helper()
	if err := r.Settle(amt, false); err != nil {
		t.Fatalf("Settle: %v", err)
	}
}

func checkSpent(t *testing.T, l *Ledger, scope string, w Window, wantS, wantR money.Micros) {
	t.Helper()
	s, r := l.Spent(scope, w)
	if s != wantS || r != wantR {
		t.Fatalf("Spent(%s,%s) = %s,%s want %s,%s", scope, w, s, r, wantS, wantR)
	}
}

func TestReserveSettleBasic(t *testing.T) {
	l, _, _ := newTest(t)
	l.SetLimits([]Limit{{Scope: "global", Window: WindowDay, Amount: money.Dollar}})
	r := reserve(t, l, []string{"pass:a"}, 300_000, Meta{PassID: "a"})
	checkSpent(t, l, "global", WindowDay, 0, 300_000)
	checkSpent(t, l, "pass:a", WindowDay, 0, 300_000)
	settle(t, r, 100_000)
	checkSpent(t, l, "global", WindowDay, 100_000, 0)
	st := l.Status()
	if len(st) != 1 || st[0].Settled != 100_000 || st[0].Remaining != 900_000 {
		t.Fatalf("Status = %+v", st)
	}
	// 900k fits exactly; 1 more micro does not.
	r2 := reserve(t, l, nil, 900_000, Meta{})
	_, err := l.Reserve(nil, 1, Meta{})
	var ee *ExceededError
	if !errors.As(err, &ee) || !errors.Is(err, ErrExceeded) {
		t.Fatalf("want ExceededError, got %v", err)
	}
	if ee.Scope != "global" || ee.Window != WindowDay || ee.Spent != 100_000 || ee.Reserved != 900_000 || ee.Requested != 1 {
		t.Fatalf("bad ExceededError %+v", ee)
	}
	r2.Release()
	reserve(t, l, nil, 1, Meta{}).Release()
}

func TestInvalidArgs(t *testing.T) {
	l, _, _ := newTest(t)
	cases := []struct {
		scopes []string
		amt    money.Micros
	}{
		{nil, -1},
		{[]string{""}, 1},
		{[]string{"pass:"}, 1},
		{[]string{"bogus:x"}, 1},
		{[]string{"model:[a"}, 1},
	}
	for _, c := range cases {
		if _, err := l.Reserve(c.scopes, c.amt, Meta{}); !errors.Is(err, ErrInvalid) {
			t.Errorf("Reserve(%q,%d) = %v, want ErrInvalid", c.scopes, c.amt, err)
		}
	}
	bad := []Limit{
		{Scope: "global", Window: "week", Amount: 1},
		{Scope: "global", Window: WindowDay, Amount: -1},
		{Scope: "model:[", Window: WindowDay, Amount: 1},
		{Scope: "provider:", Window: WindowDay, Amount: 1},
	}
	for _, b := range bad {
		if b.Validate() == nil {
			t.Errorf("Validate(%+v) = nil", b)
		}
	}
	if err := (Limit{Scope: "model:claude-*", Window: WindowMonth, Amount: 5}).Validate(); err != nil {
		t.Error(err)
	}
	if _, err := Open(Options{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("Open without dir: %v", err)
	}
}

func TestAtomicity(t *testing.T) {
	l, _, _ := newTest(t)
	l.SetLimits([]Limit{
		{Scope: "provider:a", Window: WindowDay, Amount: money.Dollar},
		{Scope: "pass:b", Window: WindowDay, Amount: 100},
	})
	l.SetConcurrency("provider:a", 1)
	_, err := l.Reserve([]string{"provider:a", "pass:b"}, 101, Meta{})
	if !errors.Is(err, ErrExceeded) {
		t.Fatal(err)
	}
	checkSpent(t, l, "provider:a", WindowDay, 0, 0)
	checkSpent(t, l, "global", WindowDay, 0, 0)
	// The concurrency slot on provider:a was not taken either.
	reserve(t, l, []string{"provider:a"}, 1, Meta{}).Release()

	// Concurrency failure on a later scope also reserves nothing.
	l.SetConcurrency("pass:b", 1)
	hold := reserve(t, l, []string{"pass:b"}, 1, Meta{})
	_, err = l.Reserve([]string{"provider:a", "pass:b"}, 5, Meta{})
	var ce *ConcurrencyError
	if !errors.As(err, &ce) || ce.Scope != "pass:b" || !errors.Is(err, ErrConcurrency) {
		t.Fatal(err)
	}
	checkSpent(t, l, "provider:a", WindowDay, 0, 0)
	hold.Release()
}

func TestRequestWindowAndModelGlob(t *testing.T) {
	l, _, _ := newTest(t)
	l.SetLimits([]Limit{
		{Scope: "global", Window: WindowRequest, Amount: 500},
		{Scope: "model:gpt-*", Window: WindowDay, Amount: 1000},
	})
	if _, err := l.Reserve(nil, 501, Meta{}); !errors.Is(err, ErrExceeded) {
		t.Fatal(err)
	}
	settle(t, reserve(t, l, nil, 500, Meta{Model: "gpt-5"}), 500)
	settle(t, reserve(t, l, nil, 500, Meta{Model: "gpt-4o"}), 500)
	if _, err := l.Reserve(nil, 1, Meta{Model: "gpt-5-mini"}); !errors.Is(err, ErrExceeded) {
		t.Fatalf("glob limit not applied: %v", err)
	}
	// A non-matching model is not limited by it.
	settle(t, reserve(t, l, nil, 500, Meta{Model: "claude-x"}), 500)
	checkSpent(t, l, "model:gpt-*", WindowDay, 1000, 0)
	checkSpent(t, l, "global", WindowDay, 1500, 0)

	// A malformed glob fails closed: it applies to every model.
	l.SetLimits([]Limit{{Scope: "model:[", Window: WindowDay, Amount: 0}})
	if _, err := l.Reserve(nil, 1, Meta{Model: "anything"}); !errors.Is(err, ErrExceeded) {
		t.Fatalf("bad glob should match: %v", err)
	}
}

func TestReleaseAndDoubleSettle(t *testing.T) {
	l, _, dir := newTest(t)
	l.SetConcurrency("pass:p", 2)
	a := reserve(t, l, []string{"pass:p"}, 10, Meta{})
	b := reserve(t, l, []string{"pass:p"}, 10, Meta{})
	if _, err := l.Reserve([]string{"pass:p"}, 10, Meta{}); !errors.Is(err, ErrConcurrency) {
		t.Fatal(err)
	}
	a.Release()
	a.Release() // no-op
	if err := a.Settle(10, false); !errors.Is(err, ErrAlreadySettled) {
		t.Fatalf("settle after release: %v", err)
	}
	c := reserve(t, l, []string{"pass:p"}, 10, Meta{})
	settle(t, b, 7)
	if err := b.Settle(7, false); !errors.Is(err, ErrAlreadySettled) {
		t.Fatal(err)
	}
	b.Release() // no-op after settle
	settle(t, c, 3)
	checkSpent(t, l, "pass:p", WindowSession, 10, 0)
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	if n := len(readRecords(t, dir)); n != 2 {
		t.Fatalf("want 2 records, got %d", n)
	}
}

func TestOverrunAndRecord(t *testing.T) {
	l, clk, dir := newTest(t)
	m := Meta{PassID: "p1", Provider: "anthropic", Model: "claude-x", Session: "s1", Client: "agent.exe", RequestID: "req-1"}
	r := reserve(t, l, []string{"provider:anthropic", "pass:p1", "session:s1"}, 100, m)
	settle(t, r, 250)
	checkSpent(t, l, "global", WindowMonth, 250, 0)
	r2 := reserve(t, l, nil, 100, Meta{})
	if err := r2.Settle(-5, false); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	checkSpent(t, l, "global", WindowMonth, 350, 0)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	recs := readRecords(t, dir)
	if len(recs) != 2 {
		t.Fatalf("records: %d", len(recs))
	}
	got := recs[0]
	want := record{TS: clk.Now().UTC(), ID: "req-1", Scopes: []string{"global", "provider:anthropic", "pass:p1", "session:s1"},
		Amount: 250, Reserved: 100, Overrun: true, Pass: "p1", Provider: "anthropic", Model: "claude-x", Session: "s1", Client: "agent.exe"}
	gj, _ := json.Marshal(got)
	wj, _ := json.Marshal(want)
	if string(gj) != string(wj) {
		t.Fatalf("record\n got %s\nwant %s", gj, wj)
	}
	if !recs[1].Estimated || recs[1].Amount != 100 || recs[1].ID == "" {
		t.Fatalf("negative settle record %+v", recs[1])
	}
	// Exact key set: nothing beyond the documented schema.
	raw, _ := os.ReadFile(filepath.Join(dir, "ledger-2026-06.jsonl"))
	var keys map[string]any
	_ = json.Unmarshal([]byte(strings.SplitN(string(raw), "\n", 2)[0]), &keys)
	for _, k := range []string{"ts", "id", "scopes", "amount_micros", "reserved_micros", "estimated", "overrun", "pass", "provider", "model", "session", "client"} {
		delete(keys, k)
	}
	if len(keys) != 0 {
		t.Fatalf("unexpected record keys %v", keys)
	}
}

func readRecords(t *testing.T, dir string) []record {
	t.Helper()
	var out []record
	files, _ := filepath.Glob(filepath.Join(dir, "ledger-*.jsonl"))
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			if strings.TrimSpace(sc.Text()) == "" {
				continue
			}
			var r record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			out = append(out, r)
		}
		fh.Close()
	}
	return out
}

func TestRollingWindows(t *testing.T) {
	l, clk, _ := newTest(t)
	l.SetLimits([]Limit{
		{Scope: "global", Window: WindowMinute, Amount: 100},
		{Scope: "global", Window: WindowHour, Amount: 1000},
	})
	t0 := clk.Now()
	settle(t, reserve(t, l, nil, 100, Meta{}), 100)
	clk.Set(t0.Add(59 * time.Second))
	if _, err := l.Reserve(nil, 1, Meta{}); !errors.Is(err, ErrExceeded) {
		t.Fatalf("minute window should still hold: %v", err)
	}
	clk.Set(t0.Add(60 * time.Second))
	checkSpent(t, l, "global", WindowMinute, 0, 0)
	checkSpent(t, l, "global", WindowHour, 100, 0)
	settle(t, reserve(t, l, nil, 100, Meta{}), 100)
	clk.Set(t0.Add(time.Hour - time.Second))
	checkSpent(t, l, "global", WindowHour, 200, 0)
	clk.Set(t0.Add(time.Hour))
	checkSpent(t, l, "global", WindowHour, 100, 0)
	clk.Set(t0.Add(time.Hour + time.Minute))
	checkSpent(t, l, "global", WindowHour, 0, 0)
	// A clock stepping backwards never frees budget.
	settle(t, reserve(t, l, nil, 50, Meta{}), 50)
	clk.Set(t0)
	checkSpent(t, l, "global", WindowMinute, 50, 0)
}

func TestCalendarWindowsDST(t *testing.T) {
	ny := mustLoc(t, "America/New_York")
	cases := []struct {
		name        string
		first, last time.Time // same local day
		next        time.Time // next local day
	}{
		// Spring forward: 23-hour day.
		{"spring", time.Date(2026, 3, 8, 0, 30, 0, 0, ny), time.Date(2026, 3, 8, 23, 59, 59, 0, ny), time.Date(2026, 3, 9, 0, 0, 0, 0, ny)},
		// Fall back: 25-hour day.
		{"fall", time.Date(2026, 11, 1, 0, 30, 0, 0, ny), time.Date(2026, 11, 1, 23, 59, 59, 0, ny), time.Date(2026, 11, 2, 0, 0, 0, 0, ny)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clk := &fakeClock{t: c.first}
			l := open(t, t.TempDir(), clk, ny)
			l.SetLimits([]Limit{{Scope: "global", Window: WindowDay, Amount: 100}})
			settle(t, reserve(t, l, nil, 100, Meta{}), 100)
			clk.Set(c.last)
			if _, err := l.Reserve(nil, 1, Meta{}); !errors.Is(err, ErrExceeded) {
				t.Fatalf("same local day should be full: %v", err)
			}
			clk.Set(c.next)
			checkSpent(t, l, "global", WindowDay, 0, 0)
			settle(t, reserve(t, l, nil, 100, Meta{}), 100)
		})
	}
	// In UTC terms, 2026-03-08 23:30 NY is already 03-09; the day must follow NY.
	clk := &fakeClock{t: time.Date(2026, 3, 8, 1, 0, 0, 0, ny)}
	l := open(t, t.TempDir(), clk, ny)
	l.SetLimits([]Limit{{Scope: "global", Window: WindowDay, Amount: 100}})
	settle(t, reserve(t, l, nil, 60, Meta{}), 60)
	clk.Set(time.Date(2026, 3, 8, 23, 30, 0, 0, ny))
	checkSpent(t, l, "global", WindowDay, 60, 0)
}

func TestMonthRolloverAndReplay(t *testing.T) {
	tokyo := mustLoc(t, "Asia/Tokyo")
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 1, 31, 23, 30, 0, 0, tokyo)}
	l, err := Open(Options{Dir: dir, Clock: clk, Location: tokyo})
	if err != nil {
		t.Fatal(err)
	}
	l.SetLimits([]Limit{{Scope: "global", Window: WindowMonth, Amount: 1000}})
	settle(t, reserve(t, l, nil, 400, Meta{}), 400)
	clk.Set(time.Date(2026, 1, 31, 23, 59, 59, 0, tokyo))
	checkSpent(t, l, "global", WindowMonth, 400, 0)
	clk.Set(time.Date(2026, 2, 1, 0, 0, 0, 0, tokyo))
	checkSpent(t, l, "global", WindowMonth, 0, 0)
	settle(t, reserve(t, l, nil, 300, Meta{}), 300)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ledger-2026-01.jsonl", "ledger-2026-02.jsonl"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("expected %s: %v", f, err)
		}
	}
	// Restart 10 minutes into February: month = 300 only, hour sees both.
	clk.Set(time.Date(2026, 2, 1, 0, 10, 0, 0, tokyo))
	l2 := open(t, dir, clk, tokyo)
	l2.SetLimits([]Limit{
		{Scope: "global", Window: WindowMonth, Amount: 1000},
		{Scope: "global", Window: WindowHour, Amount: 1000},
		{Scope: "global", Window: WindowSession, Amount: 1000},
	})
	checkSpent(t, l2, "global", WindowMonth, 300, 0)
	checkSpent(t, l2, "global", WindowHour, 700, 0)
	checkSpent(t, l2, "global", WindowSession, 0, 0) // replayed spend is not this session's
	if _, err := l2.Reserve(nil, 301, Meta{}); !errors.Is(err, ErrExceeded) {
		t.Fatalf("hour window must include previous month's tail: %v", err)
	}
}

func TestReplayReproducesTotals(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)}
	l, err := Open(Options{Dir: dir, Clock: clk, Location: time.UTC, FlushInterval: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	scopes := [][]string{{"pass:a", "provider:x"}, {"pass:b", "provider:x"}, {"pass:a", "provider:y"}}
	for i := range 60 {
		sc := scopes[i%3]
		settle(t, reserve(t, l, sc, 1000, Meta{Model: "m" + string(rune('a'+i%2))}), money.Micros(i*7))
		clk.Add(37 * time.Second)
	}
	queries := []Limit{
		{Scope: "global", Window: WindowDay}, {Scope: "global", Window: WindowHour},
		{Scope: "global", Window: WindowMinute}, {Scope: "pass:a", Window: WindowMonth},
		{Scope: "provider:x", Window: WindowHour}, {Scope: "model:ma", Window: WindowDay},
	}
	before := map[Limit]money.Micros{}
	for _, q := range queries {
		before[q], _ = l.Spent(q.Scope, q.Window)
	}
	time.Sleep(50 * time.Millisecond) // background flusher writes without Close
	if n := len(readRecords(t, dir)); n != 60 {
		t.Fatalf("flusher wrote %d records", n)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l2 := open(t, dir, clk, time.UTC)
	for _, q := range queries {
		if got, _ := l2.Spent(q.Scope, q.Window); got != before[q] {
			t.Errorf("%s/%s after replay = %s, want %s", q.Scope, q.Window, got, before[q])
		}
	}
	l2.SetLimits([]Limit{{Scope: "pass:a", Window: WindowMonth, Amount: before[Limit{Scope: "pass:a", Window: WindowMonth}]}})
	if _, err := l2.Reserve([]string{"pass:a"}, 1, Meta{}); !errors.Is(err, ErrExceeded) {
		t.Fatalf("replayed spend not enforced: %v", err)
	}
}

func TestTruncatedLastLine(t *testing.T) {
	l, clk, dir := newTest(t)
	settle(t, reserve(t, l, nil, 10, Meta{}), 10)
	settle(t, reserve(t, l, nil, 20, Meta{}), 20)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "ledger-2026-06.jsonl")
	good, _ := os.ReadFile(p)
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"ts":"2026-06-15T12:00:00Z","id":"x","scopes":["glo`)
	f.Close()

	l2 := open(t, dir, clk, time.UTC)
	checkSpent(t, l2, "global", WindowDay, 30, 0)
	if now, _ := os.ReadFile(p); string(now) != string(good) {
		t.Fatalf("torn line not cut:\n%q", now)
	}
	settle(t, reserve(t, l2, nil, 5, Meta{}), 5)
	if err := l2.Close(); err != nil {
		t.Fatal(err)
	}
	l3 := open(t, dir, clk, time.UTC)
	checkSpent(t, l3, "global", WindowDay, 35, 0)
}

func TestCompleteLineMissingNewline(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ledger-2026-06.jsonl")
	line := `{"ts":"2026-06-15T11:00:00Z","id":"a","scopes":["global"],"amount_micros":42,"reserved_micros":50}`
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)}
	l := open(t, dir, clk, time.UTC)
	checkSpent(t, l, "global", WindowDay, 42, 0)
	settle(t, reserve(t, l, nil, 1, Meta{}), 1)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if n := len(readRecords(t, dir)); n != 2 {
		t.Fatalf("records = %d", n)
	}
}

func TestCorruptionRejected(t *testing.T) {
	ok := `{"ts":"2026-06-15T11:00:00Z","id":"a","scopes":["global"],"amount_micros":1,"reserved_micros":1}`
	cases := map[string]string{
		"garbage mid-file":   ok + "\nnot json\n" + ok + "\n",
		"negative amount":    `{"ts":"2026-06-15T11:00:00Z","id":"a","scopes":["global"],"amount_micros":-5,"reserved_micros":1}` + "\n",
		"missing ts":         `{"id":"a","scopes":["global"],"amount_micros":5}` + "\n",
		"no scopes":          `{"ts":"2026-06-15T11:00:00Z","id":"a","amount_micros":5}` + "\n",
		"bad scope":          `{"ts":"2026-06-15T11:00:00Z","id":"a","scopes":["nope"],"amount_micros":5}` + "\n",
		"torn line mid-file": `{"ts":"2026-06-15T11:00` + "\n" + ok + "\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "ledger-2026-06.jsonl"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			clk := &fakeClock{t: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)}
			l, err := Open(Options{Dir: dir, Clock: clk, Location: time.UTC})
			if err == nil {
				l.Close()
				t.Fatal("corruption accepted")
			}
		})
	}
}

func TestSessionWindow(t *testing.T) {
	l, _, _ := newTest(t)
	l.SetLimits([]Limit{
		{Scope: "global", Window: WindowSession, Amount: 100},
		{Scope: "session:u1", Window: WindowSession, Amount: 50},
	})
	settle(t, reserve(t, l, []string{"session:u1"}, 50, Meta{}), 50)
	if _, err := l.Reserve([]string{"session:u1"}, 1, Meta{}); !errors.Is(err, ErrExceeded) {
		t.Fatal(err)
	}
	settle(t, reserve(t, l, nil, 50, Meta{}), 50)
	if _, err := l.Reserve(nil, 1, Meta{}); !errors.Is(err, ErrExceeded) {
		t.Fatal(err)
	}
	l.ResetSession("global")
	checkSpent(t, l, "global", WindowSession, 0, 0)
	checkSpent(t, l, "session:u1", WindowSession, 50, 0)
	settle(t, reserve(t, l, nil, 30, Meta{}), 30)
	// A session limit added later counts only spend since that scope's reset.
	l.SetLimits([]Limit{{Scope: "global", Window: WindowSession, Amount: 100}, {Scope: "pass:z", Window: WindowSession, Amount: 1}})
	checkSpent(t, l, "global", WindowSession, 30, 0)
	l.ResetSession("pass:z")
	l.SetLimits([]Limit{{Scope: "global", Window: WindowDay, Amount: 1000}})
	l.SetLimits([]Limit{{Scope: "global", Window: WindowSession, Amount: 100}})
	checkSpent(t, l, "global", WindowSession, 30, 0) // rebuilt from history since last reset
}

func TestTripwire(t *testing.T) {
	l, clk, _ := newTest(t)
	var fired atomic.Int32
	var amount atomic.Int64
	l.SetTripwire(5*time.Minute, money.Dollar, func(s money.Micros) { fired.Add(1); amount.Store(int64(s)) })
	for range 4 {
		settle(t, reserve(t, l, nil, 250_000, Meta{}), 250_000) // exactly $1 total: not over
		clk.Add(time.Second)
	}
	if l.Tripped() {
		t.Fatal("tripped at exactly the threshold")
	}
	if _, err := l.Reserve(nil, 1, Meta{}); !errors.Is(err, ErrTripped) {
		t.Fatalf("want ErrTripped, got %v", err)
	}
	for range 3 {
		if _, err := l.Reserve(nil, 1, Meta{}); !errors.Is(err, ErrTripped) {
			t.Fatal(err)
		}
	}
	if fired.Load() != 1 || amount.Load() != int64(money.Dollar)+1 || !l.Tripped() {
		t.Fatalf("fired %d amount %d", fired.Load(), amount.Load())
	}
	l.ResetTrip()
	if l.Tripped() {
		t.Fatal("still tripped")
	}
	settle(t, reserve(t, l, nil, 10, Meta{}), 10)

	// Trip via settle overrun, and via the window expiring old spend.
	r := reserve(t, l, nil, 10, Meta{})
	settle(t, r, 2*money.Dollar)
	if !l.Tripped() || fired.Load() != 2 {
		t.Fatalf("settle overrun should trip once more: %d", fired.Load())
	}
	l.ResetTrip()
	l.SetTripwire(time.Minute, 100, nil)
	clk.Add(2 * time.Minute)
	settle(t, reserve(t, l, nil, 100, Meta{}), 100)
	clk.Add(time.Minute)
	settle(t, reserve(t, l, nil, 100, Meta{}), 100)
	if l.Tripped() {
		t.Fatal("old spend should have left the tripwire window")
	}
}

func TestTripwireFiresOnceConcurrently(t *testing.T) {
	l, _, _ := newTest(t)
	var fired atomic.Int32
	l.SetTripwire(time.Hour, 1000, func(money.Micros) { fired.Add(1) })
	var wg sync.WaitGroup
	for range 200 {
		wg.Go(func() {
			if r, err := l.Reserve(nil, 10, Meta{}); err == nil {
				_ = r.Settle(10, false)
			}
		})
	}
	wg.Wait()
	if !l.Tripped() || fired.Load() != 1 {
		t.Fatalf("tripped=%v fired=%d", l.Tripped(), fired.Load())
	}
}

func TestStress(t *testing.T) {
	for _, c := range []int64{16, 0} {
		t.Run(fmt.Sprintf("conc=%d", c), func(t *testing.T) { stress(t, c) })
	}
}

func stress(t *testing.T, maxConc int64) {
	l, clk, dir := newTest(t)
	const limit = money.Dollar
	l.SetLimits([]Limit{
		{Scope: "global", Window: WindowDay, Amount: limit},
		{Scope: "pass:a", Window: WindowMinute, Amount: limit / 2},
	})
	l.SetConcurrency("global", int(maxConc))

	var inflight, peak atomic.Int64
	var settledSum atomic.Int64
	var settles atomic.Int64
	stop := make(chan struct{})
	var violations atomic.Int64
	var checker sync.WaitGroup
	checker.Go(func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if s, r := l.Spent("global", WindowDay); s+r > limit {
				violations.Add(1)
			}
			if s, r := l.Spent("pass:a", WindowMinute); s+r > limit/2 {
				violations.Add(1)
			}
		}
	})

	var wg sync.WaitGroup
	for g := range 500 {
		wg.Go(func() {
			rng := rand.New(rand.NewPCG(uint64(g), 42))
			for range 20 {
				amt := money.Micros(rng.IntN(20_000) + 1)
				sc := []string{"pass:b"}
				if rng.IntN(2) == 0 {
					sc = []string{"pass:a"}
				}
				r, err := l.Reserve(sc, amt, Meta{})
				if err != nil {
					if !errors.Is(err, ErrExceeded) && !errors.Is(err, ErrConcurrency) {
						t.Errorf("unexpected error %v", err)
					}
					continue
				}
				n := inflight.Add(1)
				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}
				// Hold the reservation for a while so many overlap.
				time.Sleep(time.Duration(rng.IntN(500)) * time.Microsecond)
				if rng.IntN(5) == 0 {
					inflight.Add(-1)
					r.Release()
					continue
				}
				actual := money.Micros(rng.IntN(int(amt) + 1))
				inflight.Add(-1)
				if err := r.Settle(actual, false); err != nil {
					t.Error(err)
				}
				settledSum.Add(int64(actual))
				settles.Add(1)
				if rng.IntN(50) == 0 {
					clk.Add(time.Millisecond)
				}
			}
		})
	}
	wg.Wait()
	close(stop)
	checker.Wait()
	if v := violations.Load(); v != 0 {
		t.Fatalf("limit exceeded at %d observed instants", v)
	}
	if maxConc > 0 && peak.Load() > maxConc {
		t.Fatalf("concurrency peak %d > %d", peak.Load(), maxConc)
	}
	s, r := l.Spent("global", WindowDay)
	if r != 0 || int64(s) != settledSum.Load() || s > limit {
		t.Fatalf("final settled %d reserved %d, want %d", s, r, settledSum.Load())
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	recs := readRecords(t, dir)
	var sum money.Micros
	for _, rec := range recs {
		sum += rec.Amount
	}
	if int64(len(recs)) != settles.Load() || sum != s {
		t.Fatalf("persisted %d records sum %d, want %d / %d", len(recs), sum, settles.Load(), s)
	}
	t.Logf("settles=%d settled=%s peak=%d", settles.Load(), s, peak.Load())
}

func TestPersistFailureFailsClosed(t *testing.T) {
	l, _, dir := newTest(t)
	settle(t, reserve(t, l, nil, 1, Meta{}), 1)
	// Make the ledger directory unwritable by replacing it with a file.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := l.Flush(); err == nil {
		t.Fatal("flush should fail")
	}
	if _, err := l.Reserve(nil, 1, Meta{}); !errors.Is(err, ErrPersist) {
		t.Fatalf("want ErrPersist, got %v", err)
	}
	// Recovery: once the directory is back, the next flush writes the
	// held-back record and reservations resume.
	_ = os.Remove(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	reserve(t, l, nil, 1, Meta{}).Release()
	if n := len(readRecords(t, dir)); n != 1 {
		t.Fatalf("records after recovery = %d", n)
	}
}

func TestClose(t *testing.T) {
	l, _, _ := newTest(t)
	r := reserve(t, l, nil, 5, Meta{})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := l.Reserve(nil, 1, Meta{}); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := r.Settle(5, false); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestErrorStringsCarryNoMeta(t *testing.T) {
	l, _, _ := newTest(t)
	l.SetLimits([]Limit{{Scope: "global", Window: WindowDay, Amount: 0}})
	_, err := l.Reserve(nil, 1, Meta{Client: "secret-ish-client", RequestID: "rid-123"})
	if err == nil || strings.Contains(err.Error(), "secret-ish") || strings.Contains(err.Error(), "rid-123") {
		t.Fatalf("error leaks meta: %v", err)
	}
}
