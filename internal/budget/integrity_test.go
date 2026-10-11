package budget

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

func TestModelGlobSlashAndCase(t *testing.T) {
	l, _, _ := newTest(t)
	l.SetLimits([]Limit{
		{Scope: "model:*opus*", Window: WindowDay, Amount: 100},
		{Scope: "model:openai/*", Window: WindowDay, Amount: 50},
	})
	for _, m := range []string{"anthropic/claude-opus-4", "Anthropic/Claude-OPUS-4", "claude-opus-5-5"} {
		if _, err := l.Reserve(nil, 101, Meta{Model: m}); !errors.Is(err, ErrExceeded) {
			t.Errorf("model %q escaped model:*opus*: %v", m, err)
		}
	}
	if _, err := l.Reserve(nil, 51, Meta{Model: "OpenAI/gpt-5"}); !errors.Is(err, ErrExceeded) {
		t.Errorf("model:openai/* not applied: %v", err)
	}
	settle(t, reserve(t, l, nil, 100, Meta{Model: "anthropic/claude-opus-4"}), 100)
	checkSpent(t, l, "model:*opus*", WindowDay, 100, 0)
	if _, err := l.Reserve(nil, 1, Meta{Model: "ANTHROPIC/CLAUDE-OPUS-4.1"}); !errors.Is(err, ErrExceeded) {
		t.Errorf("spent not shared across case variants: %v", err)
	}
	settle(t, reserve(t, l, nil, 500, Meta{Model: "anthropic/claude-sonnet-4"}), 500) // not limited

	for _, s := range []string{"model:anthropic/*", "model:*opus*", "model:GPT-5?"} {
		if err := ValidateScope(s); err != nil {
			t.Errorf("ValidateScope(%q) = %v", s, err)
		}
	}
	for _, s := range []string{"model:", "model:[a]", `model:a\b`} {
		if ValidateScope(s) == nil {
			t.Errorf("ValidateScope(%q) = nil", s)
		}
	}
}

func TestAwayAndGrantScopes(t *testing.T) {
	for _, s := range []string{"away", "away:p1", "grant:g1", "grant:abc-123"} {
		if err := ValidateScope(s); err != nil {
			t.Errorf("ValidateScope(%q) = %v", s, err)
		}
	}
	for _, s := range []string{"grant:", "away:", "awayx", "grants:x"} {
		if ValidateScope(s) == nil {
			t.Errorf("ValidateScope(%q) = nil", s)
		}
	}
	l, _, dir := newTest(t)
	l.SetLimits([]Limit{
		{Scope: "global", Window: WindowSession, Amount: 10_000},
		{Scope: ScopeAway, Window: WindowSession, Amount: 300},
		{Scope: "grant:g1", Window: WindowSession, Amount: 1000},
	})
	l.SetConcurrency(ScopeAway, 1)
	settle(t, reserve(t, l, []string{ScopeAway, "pass:p"}, 300, Meta{}), 300)
	if _, err := l.Reserve([]string{ScopeAway}, 1, Meta{}); !errors.Is(err, ErrExceeded) {
		t.Fatalf("away limit: %v", err)
	}
	reserve(t, l, nil, 1, Meta{}).Release() // non-away requests unaffected
	hold := reserve(t, l, []string{"grant:g1"}, 1000, Meta{})
	if _, err := l.Reserve([]string{"grant:g1"}, 1, Meta{}); !errors.Is(err, ErrExceeded) {
		t.Fatalf("grant limit: %v", err)
	}
	settle(t, hold, 1000)

	// Entering Away again resets only the away counters.
	l.ResetSession(ScopeAway)
	checkSpent(t, l, ScopeAway, WindowSession, 0, 0)
	checkSpent(t, l, "grant:g1", WindowSession, 1000, 0)
	checkSpent(t, l, "global", WindowSession, 1300, 0)
	a := reserve(t, l, []string{ScopeAway}, 300, Meta{})
	if _, err := l.Reserve([]string{ScopeAway}, 0, Meta{}); !errors.Is(err, ErrConcurrency) {
		t.Fatalf("away concurrency: %v", err)
	}
	settle(t, a, 300)
	l.ResetSession("grant:g1")
	checkSpent(t, l, "grant:g1", WindowSession, 0, 0)
	settle(t, reserve(t, l, []string{"grant:g1"}, 1000, Meta{}), 1000)

	// Records with the new scopes replay.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	clk := &fakeClock{t: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)}
	l2 := open(t, dir, clk, time.UTC)
	checkSpent(t, l2, ScopeAway, WindowDay, 600, 0)
	checkSpent(t, l2, "grant:g1", WindowDay, 2000, 0)
}

func TestInFlightAndExpire(t *testing.T) {
	l, clk, dir := newTest(t)
	r1 := reserve(t, l, []string{"pass:p1"}, 70, Meta{PassID: "p1", Model: "m", RequestID: "req-1"})
	clk.Add(10 * time.Second)
	r2 := reserve(t, l, []string{"pass:p2"}, 30, Meta{PassID: "p2", RequestID: "req-2"})
	clk.Add(time.Second)
	got := l.InFlight()
	if len(got) != 2 || got[0].ID != "req-1" || got[0].Age != 11*time.Second || got[0].Amount != 70 ||
		got[0].Meta.PassID != "p1" || !slices.Equal(got[0].Scopes, []string{"global", "pass:p1"}) ||
		got[1].ID != "req-2" || got[1].Age != time.Second {
		t.Fatalf("InFlight = %+v", got)
	}
	got[0].Scopes[0] = "mutated"
	if l.InFlight()[0].Scopes[0] != "global" {
		t.Fatal("InFlight exposes internal scopes")
	}
	n, err := l.ExpireInFlight(5 * time.Second)
	if err != nil || n != 1 {
		t.Fatalf("ExpireInFlight = %d, %v", n, err)
	}
	if err := r1.Settle(1, false); !errors.Is(err, ErrAlreadySettled) {
		t.Fatalf("holder settle after expiry: %v", err)
	}
	checkSpent(t, l, "global", WindowDay, 70, 30)
	if in := l.InFlight(); len(in) != 1 || in[0].ID != "req-2" {
		t.Fatalf("InFlight after expiry = %+v", in)
	}
	r2.Release()
	if len(l.InFlight()) != 0 {
		t.Fatal("released reservation still in flight")
	}
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	recs := readRecords(t, dir)
	if len(recs) != 1 || recs[0].ID != "req-1" || !recs[0].Estimated || recs[0].Amount != 70 {
		t.Fatalf("expiry record %+v", recs)
	}
}

var testKey = []byte("0123456789abcdef0123456789abcdef")

// ledgerAt opens a ledger with the clock at t and the MAC key set.
func ledgerAt(t *testing.T, dir string, at time.Time) (*Ledger, *fakeClock) {
	t.Helper()
	clk := &fakeClock{t: at}
	l := open(t, dir, clk, time.UTC)
	l.SetMACKey(testKey)
	return l, clk
}

// writeHistory writes three records in May and three in June 2026.
func writeHistory(t *testing.T, dir string) Checkpoint {
	t.Helper()
	l, clk := ledgerAt(t, dir, time.Date(2026, 5, 20, 12, 0, 0, 0, time.UTC))
	for i := range 6 {
		if i == 3 {
			clk.Set(time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
		}
		settle(t, reserve(t, l, []string{"pass:p"}, 1000, Meta{}), money.Micros(100*(i+1)))
	}
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	cp := l.Checkpoint()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return cp
}

func verify(t *testing.T, dir string, key []byte, cp *Checkpoint) Integrity {
	t.Helper()
	l := open(t, dir, &fakeClock{t: time.Date(2026, 6, 15, 13, 0, 0, 0, time.UTC)}, time.UTC)
	in, err := l.VerifyIntegrity(key, VerifyOptions{Checkpoint: cp})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

func fileLines(t *testing.T, p string) []string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.SplitAfter(string(b), "\n")
}

func TestHashChainAndCheckpoint(t *testing.T) {
	dir := t.TempDir()
	cp := writeHistory(t, dir)
	may := fileLines(t, filepath.Join(dir, "ledger-2026-05.jsonl"))
	jun := fileLines(t, filepath.Join(dir, "ledger-2026-06.jsonl"))
	all := append(may[:3], jun[:3]...)
	prev := ""
	for i, ln := range all {
		var r record
		if err := parseLine([]byte(strings.TrimSuffix(ln, "\n")), &r); err != nil {
			t.Fatal(err)
		}
		if r.Prev != prev || len(r.MAC) != 64 {
			t.Fatalf("record %d prev %q mac %q, want prev %q", i, r.Prev, r.MAC, prev)
		}
		prev = lineHash([]byte(strings.TrimSuffix(ln, "\n")))
	}
	want := Checkpoint{Month: "2026-06", Records: 3, LastHash: prev, Settled: 400 + 500 + 600}
	if cp != want {
		t.Fatalf("Checkpoint = %+v, want %+v", cp, want)
	}
	in := verify(t, dir, testKey, &cp)
	if !in.OK() || in.Records != 6 || in.Files != 2 || len(in.Problems) != 0 {
		t.Fatalf("clean ledger: %+v", in)
	}
	// A ledger reopened later keeps chaining and still verifies.
	l, _ := ledgerAt(t, dir, time.Date(2026, 6, 16, 0, 0, 0, 0, time.UTC))
	settle(t, reserve(t, l, nil, 5, Meta{}), 5)
	in, err := l.VerifyIntegrity(testKey, VerifyOptions{Checkpoint: &cp})
	if err != nil || !in.OK() || in.Records != 7 {
		t.Fatalf("after append: %+v %v", in, err)
	}
	if got := l.Checkpoint(); got.Records != 4 || got.Settled != cp.Settled+5 {
		t.Fatalf("checkpoint after append %+v", got)
	}
}

func TestIntegrityDetectsTampering(t *testing.T) {
	type tc struct {
		tamper func(t *testing.T, dir string)
		check  func(in Integrity) bool
		noKey  bool // also detected without the MAC key
	}
	may := func(dir string) string { return filepath.Join(dir, "ledger-2026-05.jsonl") }
	jun := func(dir string) string { return filepath.Join(dir, "ledger-2026-06.jsonl") }
	rewrite := func(t *testing.T, p string, f func([]string) []string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(strings.Join(f(fileLines(t, p)), "")), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]tc{
		"edit amount mid-file": {
			tamper: func(t *testing.T, dir string) {
				rewrite(t, may(dir), func(ls []string) []string {
					ls[1] = strings.Replace(ls[1], `"amount_micros":200`, `"amount_micros":1`, 1)
					return ls
				})
			},
			check: func(in Integrity) bool { return in.ChainBreaks == 1 && in.MACFailures == 1 },
			noKey: true,
		},
		"edit last record": {
			tamper: func(t *testing.T, dir string) {
				rewrite(t, jun(dir), func(ls []string) []string {
					ls[2] = strings.Replace(ls[2], `"amount_micros":600`, `"amount_micros":6`, 1)
					return ls
				})
			},
			check: func(in Integrity) bool { return in.MACFailures == 1 && in.CheckpointMismatch },
		},
		"delete a record": {
			tamper: func(t *testing.T, dir string) {
				rewrite(t, may(dir), func(ls []string) []string { return slices.Delete(ls, 1, 2) })
			},
			check: func(in Integrity) bool { return in.ChainBreaks == 1 },
			noKey: true,
		},
		"truncate tail": {
			tamper: func(t *testing.T, dir string) {
				rewrite(t, jun(dir), func(ls []string) []string { return ls[:2] })
			},
			check: func(in Integrity) bool { return in.CheckpointMismatch && in.ChainBreaks == 0 },
		},
		"delete earlier month": {
			tamper: func(t *testing.T, dir string) { _ = os.Remove(may(dir)) },
			check: func(in Integrity) bool {
				return in.MissingHistory && in.Records == 3
			},
			noKey: true,
		},
		"delete current month": {
			tamper: func(t *testing.T, dir string) { _ = os.Remove(jun(dir)) },
			check: func(in Integrity) bool {
				return in.CheckpointMismatch && slices.Equal(in.MissingMonths, []string{"2026-06"})
			},
		},
		"strip macs and re-chain": {
			tamper: func(t *testing.T, dir string) {
				prev := ""
				for _, p := range []string{may(dir), jun(dir)} {
					rewrite(t, p, func(ls []string) []string {
						for i, ln := range ls {
							if strings.TrimSpace(ln) == "" {
								continue
							}
							var r record
							_ = parseLine([]byte(strings.TrimSpace(ln)), &r)
							r.Prev, r.MAC, r.Amount = prev, "", 0
							b, _ := json.Marshal(r)
							prev = lineHash(b)
							ls[i] = string(b) + "\n"
						}
						return ls
					})
				}
			},
			check: func(in Integrity) bool {
				return in.Unauthenticated == 6 && in.ChainBreaks == 0 && in.CheckpointMismatch
			},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			cp := writeHistory(t, dir)
			c.tamper(t, dir)
			in := verify(t, dir, testKey, &cp)
			if in.OK() || !c.check(in) {
				t.Fatalf("not detected: %+v", in)
			}
			for _, p := range in.Problems {
				if strings.Contains(p, "pass:p") || strings.Contains(p, "amount") {
					t.Fatalf("problem leaks record content: %q", p)
				}
			}
			if c.noKey {
				if in := verify(t, dir, nil, nil); in.OK() {
					t.Fatalf("not detected without key: %+v", in)
				}
			}
		})
	}
}

func TestIntegrityMissingMiddleMonth(t *testing.T) {
	dir := t.TempDir()
	l, clk := ledgerAt(t, dir, time.Date(2026, 4, 10, 0, 0, 0, 0, time.UTC))
	for _, m := range []time.Month{4, 5, 6} {
		clk.Set(time.Date(2026, m, 10, 0, 0, 0, 0, time.UTC))
		settle(t, reserve(t, l, nil, 1, Meta{}), 1)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if in := verify(t, dir, testKey, nil); !in.OK() {
		t.Fatalf("clean: %+v", in)
	}
	if err := os.Remove(filepath.Join(dir, "ledger-2026-05.jsonl")); err != nil {
		t.Fatal(err)
	}
	in := verify(t, dir, testKey, nil)
	if in.OK() || in.ChainBreaks != 1 || !slices.Equal(in.MissingMonths, []string{"2026-05"}) {
		t.Fatalf("missing month not reported: %+v", in)
	}
}

func TestIntegrityMACKeyHandling(t *testing.T) {
	dir := t.TempDir()
	cp := writeHistory(t, dir)
	if in := verify(t, dir, []byte("wrong key wrong key wrong key!!"), &cp); in.MACFailures != 6 || in.OK() {
		t.Fatalf("wrong key: %+v", in)
	}
	// Records written without a key are unauthenticated when a key is given.
	dir2 := t.TempDir()
	l, _, _ := func() (*Ledger, *fakeClock, string) {
		clk := &fakeClock{t: time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)}
		return open(t, dir2, clk, time.UTC), clk, dir2
	}()
	settle(t, reserve(t, l, nil, 1, Meta{}), 1)
	l.SetMACKey(testKey)
	settle(t, reserve(t, l, nil, 2, Meta{}), 2)
	in, err := l.VerifyIntegrity(testKey)
	if err != nil || in.Unauthenticated != 1 || in.MACFailures != 0 || in.OK() {
		t.Fatalf("unauthenticated: %+v %v", in, err)
	}
	if in, _ := l.VerifyIntegrity(nil); !in.OK() {
		t.Fatalf("chain-only check: %+v", in)
	}
}

func TestIntegrityTornLineTolerated(t *testing.T) {
	dir := t.TempDir()
	writeHistory(t, dir)
	p := filepath.Join(dir, "ledger-2026-06.jsonl")
	f, _ := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString(`{"ts":"2026-06-15T12:00:00Z","id":"x","sco`)
	f.Close()
	in := verify(t, dir, testKey, nil)
	if !in.OK() || in.TornLines != 1 || in.Records != 6 {
		t.Fatalf("torn line: %+v", in)
	}
}

func TestIntegrityDetectsTamperWhileRunning(t *testing.T) {
	dir := t.TempDir()
	l, _ := ledgerAt(t, dir, time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC))
	for range 3 {
		settle(t, reserve(t, l, nil, 10, Meta{}), 10)
	}
	if in, err := l.VerifyIntegrity(testKey); err != nil || !in.OK() {
		t.Fatalf("clean: %+v %v", in, err)
	}
	p := filepath.Join(dir, "ledger-2026-06.jsonl")
	ls := fileLines(t, p)
	cut := []byte(strings.Join(ls[:2], "") + `{"torn`)
	if err := os.WriteFile(p, cut, 0o600); err != nil {
		t.Fatal(err)
	}
	in, err := l.VerifyIntegrity(testKey)
	if err != nil || in.OK() || !in.CheckpointMismatch || in.TornLines != 1 {
		t.Fatalf("truncation while running not detected: %+v %v", in, err)
	}
	// Verification never repairs or rewrites the files.
	if after, _ := os.ReadFile(p); !bytes.Equal(after, cut) {
		t.Fatal("VerifyIntegrity modified the ledger file")
	}
}

// A failed write of a multi-file batch must not rewrite lines that did reach
// disk: a duplicate would break the hash chain.
func TestPartialBatchFailureKeepsChain(t *testing.T) {
	dir := t.TempDir()
	l, clk := ledgerAt(t, dir, time.Date(2026, 6, 30, 23, 0, 0, 0, time.UTC))
	settle(t, reserve(t, l, nil, 1, Meta{}), 1)
	clk.Set(time.Date(2026, 7, 1, 1, 0, 0, 0, time.UTC))
	settle(t, reserve(t, l, nil, 2, Meta{}), 2)
	blocker := filepath.Join(dir, "ledger-2026-07.jsonl")
	if err := os.Mkdir(blocker, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := l.Flush(); err == nil {
		t.Fatal("flush into a directory should fail")
	}
	if _, err := l.Reserve(nil, 1, Meta{}); !errors.Is(err, ErrPersist) {
		t.Fatalf("want ErrPersist, got %v", err)
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	if err := l.Flush(); err != nil {
		t.Fatal(err)
	}
	in, err := l.VerifyIntegrity(testKey)
	if err != nil || !in.OK() || in.Records != 2 {
		t.Fatalf("after recovery: %+v %v", in, err)
	}
	reserve(t, l, nil, 1, Meta{}).Release()
}

func TestVerifyIntegrityEmptyLedger(t *testing.T) {
	l, _, _ := newTest(t)
	if cp := l.Checkpoint(); cp != (Checkpoint{}) {
		t.Fatalf("empty checkpoint %+v", cp)
	}
	in, err := l.VerifyIntegrity(testKey, VerifyOptions{Checkpoint: &Checkpoint{}})
	if err != nil || !in.OK() || in.Files != 0 {
		t.Fatalf("empty: %+v %v", in, err)
	}
	// A checkpoint for records that no longer exist is a mismatch.
	in, _ = l.VerifyIntegrity(nil, VerifyOptions{Checkpoint: &Checkpoint{Month: "2026-05", Records: 2, LastHash: "ab"}})
	if in.OK() || !slices.Equal(in.MissingMonths, []string{"2026-05"}) {
		t.Fatalf("missing checkpoint month: %+v", in)
	}
}
