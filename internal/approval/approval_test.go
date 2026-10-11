package approval

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/h-a-forster/keyleash/internal/money"
)

// fakeClock hands out timers the test fires explicitly.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []chan time.Time
}

func newClock() *fakeClock { return &fakeClock{now: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeClock) After(time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.timers = append(c.timers, ch)
	return ch
}
func (c *fakeClock) fireAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range c.timers {
		t <- c.now
	}
	c.timers = nil
}

// blockingApprover blocks until released or cancelled.
type blockingApprover struct {
	calls     atomic.Int32
	cancelled atomic.Int32
	release   chan bool
}

func newBlocking() *blockingApprover { return &blockingApprover{release: make(chan bool, 1)} }

func (b *blockingApprover) Method() string { return "test" }
func (b *blockingApprover) Approve(ctx context.Context, _ Request) (bool, error) {
	b.calls.Add(1)
	select {
	case ok := <-b.release:
		return ok, nil
	case <-ctx.Done():
		b.cancelled.Add(1)
		return false, ctx.Err()
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not reached")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestCoalescing50Waiters(t *testing.T) {
	ap := newBlocking()
	q := NewQueue(ap, time.Minute, newClock())
	req := Request{Kind: "limit", Title: "over budget", PassID: "abcdefghjk", CoalesceKey: "abcdefghjk/limit"}
	const n = 50
	results := make(chan Decision, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := q.Request(context.Background(), req)
			results <- d
			errs <- err
		}()
	}
	waitFor(t, func() bool { p := q.Pending(); return len(p) == 1 && p[0].Waiters == n })
	ap.release <- true
	wg.Wait()
	close(results)
	close(errs)
	var id string
	for d := range results {
		if !d.Approved || d.Method != "test" {
			t.Fatalf("decision %+v", d)
		}
		if id == "" {
			id = d.ID
		} else if d.ID != id {
			t.Fatal("waiters got different decisions")
		}
	}
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if ap.calls.Load() != 1 {
		t.Fatalf("approver called %d times", ap.calls.Load())
	}
	if len(q.Pending()) != 0 {
		t.Fatal("pending not cleared")
	}
	// A new request with the same key after resolution prompts again.
	go func() { ap.release <- false }()
	d, err := q.Request(context.Background(), req)
	if err != nil || d.Approved || ap.calls.Load() != 2 {
		t.Fatalf("second round %+v %v", d, err)
	}
}

func TestNoCoalesceWithoutKey(t *testing.T) {
	ap := newBlocking()
	q := NewQueue(ap, time.Minute, newClock())
	done := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func() { _, _ = q.Request(context.Background(), Request{Title: "x"}); done <- struct{}{} }()
	}
	waitFor(t, func() bool { return len(q.Pending()) == 2 })
	ap.release <- true
	ap.release <- true
	<-done
	<-done
}

func TestTimeoutFakeClock(t *testing.T) {
	ap := newBlocking()
	clk := newClock()
	q := NewQueue(ap, time.Minute, clk)
	res := make(chan error, 1)
	go func() {
		d, err := q.Request(context.Background(), Request{Title: "x"})
		if d.Approved || d.Method != "timeout" {
			t.Errorf("decision %+v", d)
		}
		res <- err
	}()
	waitFor(t, func() bool { return len(q.Pending()) == 1 && ap.calls.Load() == 1 })
	p := q.Pending()[0]
	if !p.Deadline.Equal(clk.Now().Add(time.Minute)) {
		t.Fatalf("deadline %v", p.Deadline)
	}
	clk.fireAll()
	if err := <-res; !errors.Is(err, ErrTimeout) {
		t.Fatalf("err %v", err)
	}
	waitFor(t, func() bool { return ap.cancelled.Load() == 1 })
}

func TestTimeoutRealClock(t *testing.T) {
	q := NewQueue(newBlocking(), 20*time.Millisecond, nil)
	start := time.Now()
	d, err := q.Request(context.Background(), Request{Title: "x"})
	if !errors.Is(err, ErrTimeout) || d.Approved {
		t.Fatalf("%+v %v", d, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout too slow")
	}
}

func TestExternalDecideWins(t *testing.T) {
	ap := newBlocking()
	q := NewQueue(ap, time.Minute, newClock())
	res := make(chan Decision, 1)
	go func() {
		d, err := q.Request(context.Background(), Request{Title: "x"})
		if err != nil {
			t.Error(err)
		}
		res <- d
	}()
	waitFor(t, func() bool { return len(q.Pending()) == 1 })
	id := q.Pending()[0].ID
	if err := q.Decide("nope", true, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	grant := &Grant{Amount: 10 * money.Dollar, For: time.Hour}
	if err := q.Decide(id, true, grant); err != nil {
		t.Fatal(err)
	}
	grant.Amount = 1 // caller mutation must not leak in
	d := <-res
	if !d.Approved || d.Method != "external" || d.ID != id || d.Grant == nil || d.Grant.Amount != 10*money.Dollar {
		t.Fatalf("decision %+v", d)
	}
	waitFor(t, func() bool { return ap.cancelled.Load() == 1 })
	if err := q.Decide(id, false, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("second decide accepted")
	}
}

func TestDenyCarriesNoGrant(t *testing.T) {
	q := NewQueue(newBlocking(), time.Minute, newClock())
	res := make(chan Decision, 1)
	go func() { d, _ := q.Request(context.Background(), Request{}); res <- d }()
	waitFor(t, func() bool { return len(q.Pending()) == 1 })
	_ = q.Decide(q.Pending()[0].ID, false, &Grant{Amount: 5})
	if d := <-res; d.Approved || d.Grant != nil {
		t.Fatalf("%+v", d)
	}
}

func TestApproverWinsThenDecideFails(t *testing.T) {
	ap := newBlocking()
	ap.release <- true
	q := NewQueue(ap, time.Minute, newClock())
	d, err := q.Request(context.Background(), Request{})
	if err != nil || !d.Approved {
		t.Fatal(d, err)
	}
	if err := q.Decide(d.ID, false, nil); !errors.Is(err, ErrNotFound) {
		t.Fatal("decide after resolution accepted")
	}
}

func TestContextCancel(t *testing.T) {
	ap := newBlocking()
	q := NewQueue(ap, time.Minute, newClock())
	key := "k"
	ctx1, cancel1 := context.WithCancel(context.Background())
	r1 := make(chan error, 1)
	r2 := make(chan Decision, 1)
	go func() { _, err := q.Request(ctx1, Request{CoalesceKey: key}); r1 <- err }()
	waitFor(t, func() bool { return len(q.Pending()) == 1 })
	go func() { d, _ := q.Request(context.Background(), Request{CoalesceKey: key}); r2 <- d }()
	waitFor(t, func() bool { p := q.Pending(); return len(p) == 1 && p[0].Waiters == 2 })
	cancel1()
	if err := <-r1; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// The other waiter keeps the request alive.
	if len(q.Pending()) != 1 || ap.cancelled.Load() != 0 {
		t.Fatal("request cancelled while a waiter remains")
	}
	ap.release <- true
	if d := <-r2; !d.Approved {
		t.Fatal("remaining waiter not approved")
	}

	// Last waiter leaving cancels the approver.
	ctx3, cancel3 := context.WithCancel(context.Background())
	r3 := make(chan error, 1)
	go func() { _, err := q.Request(ctx3, Request{}); r3 <- err }()
	waitFor(t, func() bool { return len(q.Pending()) == 1 })
	cancel3()
	if err := <-r3; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return ap.cancelled.Load() == 1 && len(q.Pending()) == 0 })

	ctx4, cancel4 := context.WithCancel(context.Background())
	cancel4()
	if d, err := q.Request(ctx4, Request{}); err == nil || d.Approved {
		t.Fatal("cancelled ctx accepted")
	}
}

type errApprover struct{ panic bool }

func (e errApprover) Approve(context.Context, Request) (bool, error) {
	if e.panic {
		panic("boom")
	}
	return true, errors.New("device unavailable")
}

func TestApproverFailureDenies(t *testing.T) {
	for _, p := range []bool{false, true} {
		q := NewQueue(errApprover{panic: p}, time.Minute, newClock())
		d, err := q.Request(context.Background(), Request{})
		if !errors.Is(err, ErrApprover) || d.Approved {
			t.Fatalf("panic=%v: %+v %v", p, d, err)
		}
	}
}

func TestDenyAndNilApprover(t *testing.T) {
	for _, a := range []Approver{DenyApprover{}, nil} {
		q := NewQueue(a, 0, nil)
		d, err := q.Request(context.Background(), Request{Title: "x"})
		if err != nil || d.Approved || d.Method != "deny" {
			t.Fatalf("%+v %v", d, err)
		}
	}
}

type fakeConfirmer struct {
	err    error
	prompt string
}

func (f *fakeConfirmer) Confirm(_ context.Context, p string) error { f.prompt = p; return f.err }

func TestHelloApprover(t *testing.T) {
	c := &fakeConfirmer{}
	a := HelloApprover(c)
	ok, err := a.Approve(context.Background(), Request{Title: "Raise limit\r\n\x1b[31m", Amount: 10 * money.Dollar, PassID: "abcdefghjk"})
	if !ok || err != nil {
		t.Fatal(ok, err)
	}
	if c.prompt != "Raise limit [31m · $10.00 · pass abcdefghjk" {
		t.Fatalf("prompt %q", c.prompt)
	}
	c.err = errors.New("user cancelled")
	ok, err = a.Approve(context.Background(), Request{})
	if ok || err != nil {
		t.Fatal("failed confirmation must be a plain denial", ok, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Approve(ctx, Request{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if ok, err := HelloApprover(nil).Approve(context.Background(), Request{}); ok || err == nil {
		t.Fatal("nil confirmer approved")
	}
	if NewQueue(a, 0, nil) == nil || methodOf(a) != "hello" {
		t.Fatal("method name")
	}
}

func TestPromptText(t *testing.T) {
	cases := []struct {
		req  Request
		want string
	}{
		{Request{}, "keyleash approval"},
		{Request{Kind: "unlock"}, "unlock"},
		{Request{Title: "a\tb\n\n c", Detail: "  d  "}, "a b c · d"},
		{Request{Title: "evil‮gnp.exe​"}, "evilgnp.exe"},
		{Request{Title: "x", Model: "claude-opus-5", Amount: 1500 * money.Cent / 100}, "x · $0.15 · model claude-opus-5"},
		{Request{Title: "bad\xffutf8"}, "badutf8"},
	}
	for _, c := range cases {
		if got := PromptText(c.req); got != c.want {
			t.Errorf("PromptText(%+v) = %q, want %q", c.req, got, c.want)
		}
	}
	long := PromptText(Request{Title: strings.Repeat("é", 1000), Detail: strings.Repeat("d", 1000)})
	if n := utf8.RuneCountInString(long); n > maxPromptRunes {
		t.Fatalf("prompt %d runes", n)
	}
	if !strings.Contains(long, "…") {
		t.Fatal("truncation not marked")
	}
}

func TestConsoleApprover(t *testing.T) {
	for in, want := range map[string]bool{"y\n": true, "YES\r\n": true, "n\n": false, "\n": false, "yes please\n": false, "": false, "y": true} {
		var out bytes.Buffer
		ok, err := ConsoleApprover(strings.NewReader(in), &out).Approve(context.Background(), Request{Title: "Unlock vault"})
		if err != nil || ok != want {
			t.Errorf("input %q: %v %v", in, ok, err)
		}
		if !strings.Contains(out.String(), "Unlock vault") || !strings.Contains(out.String(), "[y/N]") {
			t.Errorf("prompt output %q", out.String())
		}
	}
}

func TestConsoleApproverCancelAndStaleInput(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	a := ConsoleApprover(pr, io.Discard).(*consoleApprover)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := a.Approve(ctx, Request{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline, got %v", err)
	}
	// A "y" typed while no prompt is showing must not approve the next one.
	go func() { _, _ = pw.Write([]byte("y\n")) }()
	waitFor(t, func() bool { return len(a.lines) == 1 })
	ctx2, cancel2 := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel2()
	ok, err := a.Approve(ctx2, Request{})
	if ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stale answer used: %v %v", ok, err)
	}
	go func() { _, _ = pw.Write([]byte("y\n")) }()
	ok, err = a.Approve(context.Background(), Request{})
	if !ok || err != nil {
		t.Fatalf("fresh answer: %v %v", ok, err)
	}
}

func TestConsoleApproverThroughQueueTimeout(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	q := NewQueue(ConsoleApprover(pr, io.Discard), 20*time.Millisecond, nil)
	if _, err := q.Request(context.Background(), Request{}); !errors.Is(err, ErrTimeout) {
		t.Fatal(err)
	}
}

// TestPassphraseApproverWaitsForDecideAs: the passphrase approver never
// decides by itself; DecideAs records who decided, Get exposes the pending
// request (with its requester) until then.
func TestPassphraseApproverWaitsForDecideAs(t *testing.T) {
	ap := PassphraseApprover()
	if methodOf(ap) != "passphrase" {
		t.Fatalf("method = %q", methodOf(ap))
	}
	clk := newClock()
	q := NewQueue(ap, time.Minute, clk)
	res := make(chan Decision, 1)
	go func() {
		d, _ := q.Request(context.Background(), Request{Kind: "resume", Requester: 4242})
		res <- d
	}()
	waitFor(t, func() bool { return len(q.Pending()) == 1 })
	id := q.Pending()[0].ID
	pi, ok := q.Get(id)
	if !ok || pi.Request.Requester != 4242 || pi.Request.Kind != "resume" {
		t.Fatalf("get = %+v %v", pi, ok)
	}
	if _, ok := q.Get("nope"); ok {
		t.Fatal("unknown id found")
	}
	select {
	case d := <-res:
		t.Fatalf("decided without anyone deciding: %+v", d)
	case <-time.After(50 * time.Millisecond):
	}
	if err := q.DecideAs(id, true, nil, "passphrase"); err != nil {
		t.Fatal(err)
	}
	if d := <-res; !d.Approved || d.Method != "passphrase" {
		t.Fatalf("decision %+v", d)
	}
	if _, ok := q.Get(id); ok {
		t.Fatal("decided request still pending")
	}
	// Timeout still applies.
	go func() { d, _ := q.Request(context.Background(), Request{}); res <- d }()
	waitFor(t, func() bool { return len(q.Pending()) == 1 })
	clk.fireAll()
	if d := <-res; d.Approved || d.Method != "timeout" {
		t.Fatalf("timeout decision %+v", d)
	}
}
