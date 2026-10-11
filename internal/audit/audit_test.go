package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }
func (c *fakeClock) Set(t time.Time)     { c.mu.Lock(); c.t = t; c.mu.Unlock() }

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
}

var anchorKey = bytes.Repeat([]byte{7}, 32)

// writeSample writes n request records, with an anchor after each 3, and
// closes the log.
func writeSample(t *testing.T, dir string, clk *fakeClock, n int) {
	t.Helper()
	l, err := Open(dir, clk)
	if err != nil {
		t.Fatal(err)
	}
	l.SetAnchorKey(anchorKey)
	for i := 0; i < n; i++ {
		clk.Add(time.Second)
		if err := l.Append("request", map[string]any{
			"pass": "abcdefghjk", "model": "claude-sonnet-5", "cost_micros": 1234 + i,
			"latency_ms": 12.5, "estimated": i%2 == 0, "tags": []string{"a", "<b>&"},
		}); err != nil {
			t.Fatal(err)
		}
		if i%3 == 2 {
			if err := l.Anchor(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitAfter(string(raw), "\n")[:strings.Count(string(raw), "\n")]
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAppendVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	writeSample(t, dir, clk, 9)
	rep, err := Verify(dir, anchorKey)
	if err != nil {
		t.Fatalf("verify: %v (%+v)", err, rep.FirstBad)
	}
	if rep.Records != 12 || rep.Files != 1 || rep.Anchors != 3 || rep.AnchorsVerified != 3 {
		t.Fatalf("report %+v", rep)
	}
	rep, err = Verify(dir, nil)
	if err != nil || rep.AnchorsVerified != 0 || rep.Anchors != 3 {
		t.Fatalf("keyless verify: %+v %v", rep, err)
	}
	// Lines are canonical: sorted keys, no HTML escaping, ends with newline.
	lines := readLines(t, filepath.Join(dir, "audit-2026-10.jsonl"))
	if !strings.HasPrefix(lines[0], `{"cost_micros":1234,"estimated":true,"hash":"`) {
		t.Fatalf("not canonical: %s", lines[0])
	}
	if !strings.Contains(lines[0], `"<b>&"`) {
		t.Fatalf("html escaped: %s", lines[0])
	}
}

func TestResumeAndMonthRollover(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	writeSample(t, dir, clk, 4)
	clk.Set(time.Date(2026, 11, 1, 0, 0, 1, 0, time.UTC))
	l, err := Open(dir, clk)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append("daemon_start", nil); err != nil {
		t.Fatal(err)
	}
	// Clock stepped back into October must not reopen the older file.
	clk.Set(time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC))
	if err := l.Append("lock", map[string]any{"reason": "sleep"}); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if n := len(readLines(t, filepath.Join(dir, "audit-2026-11.jsonl"))); n != 2 {
		t.Fatalf("november file has %d lines", n)
	}
	rep, err := Verify(dir, anchorKey)
	if err != nil || rep.Files != 2 || rep.Records != 7 {
		t.Fatalf("verify %+v %v", rep, err)
	}
	recs, err := (func() ([]Record, error) {
		l, _ := Open(dir, clk)
		defer l.Close()
		return l.Tail(3)
	})()
	if err != nil || len(recs) != 3 {
		t.Fatalf("tail %v %v", recs, err)
	}
	if recs[0].Seq != 5 || recs[1].Type != "daemon_start" || recs[2].Type != "lock" || recs[2].Fields["reason"] != "sleep" {
		t.Fatalf("tail content %+v", recs)
	}
	if recs[1].Prev != recs[0].Hash {
		t.Fatal("cross-file chain not linked")
	}
}

func TestTamperDetection(t *testing.T) {
	type mutate func(t *testing.T, dir string)
	file := func(dir string) string { return filepath.Join(dir, "audit-2026-10.jsonl") }
	cases := map[string]mutate{
		"edit field": func(t *testing.T, dir string) {
			ls := readLines(t, file(dir))
			ls[2] = strings.Replace(ls[2], `"cost_micros":1236`, `"cost_micros":1`, 1)
			writeLines(t, file(dir), ls)
		},
		"edit number format": func(t *testing.T, dir string) {
			ls := readLines(t, file(dir))
			ls[2] = strings.Replace(ls[2], `"cost_micros":1236`, `"cost_micros":1236.0`, 1)
			writeLines(t, file(dir), ls)
		},
		"delete middle": func(t *testing.T, dir string) {
			ls := readLines(t, file(dir))
			writeLines(t, file(dir), append(ls[:2:2], ls[3:]...))
		},
		"delete first": func(t *testing.T, dir string) {
			ls := readLines(t, file(dir))
			writeLines(t, file(dir), ls[1:])
		},
		"reorder": func(t *testing.T, dir string) {
			ls := readLines(t, file(dir))
			ls[1], ls[2] = ls[2], ls[1]
			writeLines(t, file(dir), ls)
		},
		"duplicate": func(t *testing.T, dir string) {
			ls := readLines(t, file(dir))
			writeLines(t, file(dir), append(ls[:3:3], ls[2:]...))
		},
		"insert blank": func(t *testing.T, dir string) {
			ls := readLines(t, file(dir))
			writeLines(t, file(dir), append(ls[:2:2], append([]string{"\n"}, ls[2:]...)...))
		},
		"truncate mid-record": func(t *testing.T, dir string) {
			ls := readLines(t, file(dir))
			ls[len(ls)-1] = ls[len(ls)-1][:20]
			writeLines(t, file(dir), ls)
		},
		"delete earlier file": func(t *testing.T, dir string) {
			clk := &fakeClock{t: time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)}
			l, _ := Open(dir, clk)
			_ = l.Append("present", nil)
			_ = l.Close()
			_ = os.Remove(file(dir))
		},
		"add field": func(t *testing.T, dir string) {
			ls := readLines(t, file(dir))
			ls[1] = strings.Replace(ls[1], `{`, `{"aaa":1,`, 1)
			writeLines(t, file(dir), ls)
		},
	}
	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeSample(t, dir, newClock(), 6)
			m(t, dir)
			rep, err := Verify(dir, anchorKey)
			if !errors.Is(err, ErrTampered) || rep.FirstBad == nil {
				t.Fatalf("not detected: %+v %v", rep, err)
			}
		})
	}
}

// TestForgedChainCaughtByAnchors: an attacker edits a record and recomputes
// every later hash. The plain chain verifies; the anchors do not.
func TestForgedChainCaughtByAnchors(t *testing.T) {
	dir := t.TempDir()
	writeSample(t, dir, newClock(), 6)
	path := filepath.Join(dir, "audit-2026-10.jsonl")
	ls := readLines(t, path)
	prev := ""
	for i, line := range ls {
		m, _, err := parseLine([]byte(strings.TrimSuffix(line, "\n")))
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 {
			m["cost_micros"] = json.Number("1")
		}
		m["prev"] = prev
		h, err := computeHash(prev, m)
		if err != nil {
			t.Fatal(err)
		}
		m["hash"] = h
		var buf bytes.Buffer
		_ = canonical(&buf, m)
		ls[i] = buf.String() + "\n"
		prev = h
	}
	writeLines(t, path, ls)
	if _, err := Verify(dir, nil); err != nil {
		t.Fatalf("forged chain should pass without key: %v", err)
	}
	rep, err := Verify(dir, anchorKey)
	if !errors.Is(err, ErrTampered) || !strings.Contains(rep.FirstBad.Reason, "anchor") {
		t.Fatalf("forgery not caught: %+v %v", rep, err)
	}
	if _, err := Verify(t.TempDir(), nil); err != nil {
		t.Fatalf("empty dir: %v", err)
	}
}

func TestWrongAnchorKey(t *testing.T) {
	dir := t.TempDir()
	writeSample(t, dir, newClock(), 3)
	if _, err := Verify(dir, bytes.Repeat([]byte{8}, 32)); !errors.Is(err, ErrTampered) {
		t.Fatalf("wrong key accepted: %v", err)
	}
}

func TestTornTailRecovery(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	writeSample(t, dir, clk, 4)
	path := filepath.Join(dir, "audit-2026-10.jsonl")
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(`{"cost_micros":99,"hash":"ab`)
	_ = f.Close()
	if _, err := Verify(dir, anchorKey); !errors.Is(err, ErrTampered) {
		t.Fatal("torn tail should fail verify before recovery")
	}
	l, err := Open(dir, clk)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Append("present", nil); err != nil {
		t.Fatal(err)
	}
	recs, _ := l.Tail(2)
	_ = l.Close()
	if len(recs) != 2 || recs[0].Type != TypeRecover || recs[0].Fields["dropped_bytes"] != json.Number("28") {
		t.Fatalf("recovery record: %+v", recs)
	}
	if rep, err := Verify(dir, anchorKey); err != nil {
		t.Fatalf("after recovery: %v %+v", err, rep.FirstBad)
	}
}

func TestResumeSkipsGarbageButVerifyFlagsIt(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	writeSample(t, dir, clk, 2)
	path := filepath.Join(dir, "audit-2026-10.jsonl")
	ls := readLines(t, path)
	writeLines(t, path, append(ls, "garbage\n"))
	l, err := Open(dir, clk)
	if err != nil {
		t.Fatal(err)
	}
	_ = l.Append("present", nil)
	_ = l.Close()
	rep, err := Verify(dir, anchorKey)
	if !errors.Is(err, ErrTampered) || rep.FirstBad.Line != len(ls)+1 {
		t.Fatalf("garbage not flagged at right line: %+v %v", rep.FirstBad, err)
	}
}

func TestSecretGuard(t *testing.T) {
	bad := []any{
		"sk-ant-api03-" + strings.Repeat("A1b2", 10),
		"sk-proj-abcdefghijklmnopqrstuvwxyz",
		"key=sk-abcdefghijklmnopqrstuvwxyz",
		"Authorization: Bearer sk-or-v1-0123456789abcdef0123",
		"AIzaSyD-abcdefghijklmnopqrstuvwxyz012",
		"klp_0123456789_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		"Xk9mP2vQ7rT4wY8zB3nC6fH1jL5sD0gA9eR2tU7iO4pK", // generic high-entropy
		[]any{"ok", "sk-ant-" + strings.Repeat("x", 30)},
		map[string]any{"inner": "AIza" + strings.Repeat("Q", 30)},
	}
	for i, v := range bad {
		dir := t.TempDir()
		l, _ := Open(dir, newClock())
		err := l.Append("request", map[string]any{"detail": v})
		_ = l.Close()
		if !errors.Is(err, ErrSecret) {
			t.Errorf("case %d: not rejected: %v", i, err)
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(dir, "audit-2026-10.jsonl"))
		if len(raw) != 0 {
			t.Errorf("case %d: something was written", i)
		}
		if strings.Contains(err.Error(), "sk-") || strings.Contains(err.Error(), "AIza") {
			t.Errorf("case %d: error echoes value", i)
		}
	}
	// A secret in a nested object key is caught too.
	l, _ := Open(t.TempDir(), newClock())
	if err := l.Append("request", map[string]any{"m": map[string]any{"sk-ant-" + strings.Repeat("z", 30): 1}}); !errors.Is(err, ErrSecret) {
		t.Errorf("secret key not rejected: %v", err)
	}
	good := []string{
		"sk-short",
		"claude-sonnet-5-20260101",
		strings.Repeat("ab12", 16), // hex digest
		"0f8fad5b-d9cb-469f-a165-70867728950e",
		"chatcmpl-B9MBs8CjcvOU2jLn4n570S5qMJKcTAbCdEf",
		`C:\Users\someone\AppData\Local\Programs\Python\python.exe`,
		"keyleash is locked — run keyleash unlock",
		"task-skeleton-disk-usage-statistics-report",
	}
	for _, v := range good {
		if err := l.Append("request", map[string]any{"detail": v}); err != nil {
			t.Errorf("false positive on %q: %v", v, err)
		}
	}
	_ = l.Close()
}

func TestAppendValidation(t *testing.T) {
	l, _ := Open(t.TempDir(), newClock())
	defer l.Close()
	cases := []struct {
		typ    string
		fields map[string]any
	}{
		{"", nil},
		{"Bad Type", nil},
		{"anchor", nil},
		{"audit_recover", nil},
		{"x", map[string]any{"hash": "x"}},
		{"x", map[string]any{"seq": 1}},
		{"x", map[string]any{"Bad-Name": 1}},
		{"x", map[string]any{"f": func() {}}},
		{"x", map[string]any{"big": strings.Repeat("a b ", MaxRecordSize/3)}},
	}
	for i, c := range cases {
		if err := l.Append(c.typ, c.fields); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if err := l.Anchor(); !errors.Is(err, ErrNoAnchorKey) {
		t.Errorf("anchor without key: %v", err)
	}
	l.SetAnchorKey(anchorKey)
	l.ClearAnchorKey()
	if err := l.Anchor(); !errors.Is(err, ErrNoAnchorKey) {
		t.Errorf("anchor after clear: %v", err)
	}
	_ = l.Close()
	if err := l.Append("x", nil); !errors.Is(err, ErrClosed) {
		t.Errorf("append after close: %v", err)
	}
}

func TestConcurrentAppend(t *testing.T) {
	dir := t.TempDir()
	clk := newClock()
	l, _ := Open(dir, clk)
	l.SetAnchorKey(anchorKey)
	var wg sync.WaitGroup
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				if err := l.Append("request", map[string]any{"g": g, "i": i}); err != nil {
					t.Error(err)
				}
				if i == 10 {
					_ = l.Anchor()
				}
			}
		}(g)
	}
	wg.Wait()
	_ = l.Close()
	rep, err := Verify(dir, anchorKey)
	if err != nil || rep.Records != 520 || rep.AnchorsVerified != 20 {
		t.Fatalf("%+v %v", rep, err)
	}
}

func TestCanonicalStable(t *testing.T) {
	v, err := normalize(map[string]any{"b": 1.5, "a": []any{int64(1) << 60, "é\u2028", nil, true}})
	if err != nil {
		t.Fatal(err)
	}
	var b1 bytes.Buffer
	_ = canonical(&b1, v)
	v2, err := decodeValue(b1.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	var b2 bytes.Buffer
	_ = canonical(&b2, v2)
	if b1.String() != b2.String() {
		t.Fatalf("not stable:\n%s\n%s", b1.String(), b2.String())
	}
	if b1.String() != `{"a":[1152921504606846976,"é\u2028",null,true],"b":1.5}` {
		t.Fatalf("unexpected canonical form %s", b1.String())
	}
}
