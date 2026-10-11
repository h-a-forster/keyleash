package pass

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

var testMACKey = bytes.Repeat([]byte{7}, 32)

// authStore opens a store with a MAC key and a hook that records the
// baseline the way the daemon keeps it in the vault.
func authStore(t *testing.T, path string, clk Clock, base **Baseline) *Store {
	t.Helper()
	s, err := OpenStore(path, clk)
	if err != nil {
		t.Fatal(err)
	}
	s.SetCommitHook(func(b Baseline) { c := b; *base = &c })
	s.SetMACKey(testMACKey)
	return s
}

func editDoc(t *testing.T, path string, fn func(doc map[string]any, body map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	b := doc["body"].(map[string]any)
	fn(doc, b)
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestStoreTamperDetected replays finding B: forging, un-revoking,
// unbinding or raising a pass's limits in passes.json, or rolling the file
// back, is detected after a restart (with the diff), while the store's own
// writes verify.
func TestStoreTamperDetected(t *testing.T) {
	clk := newClock()
	_, path := openTemp(t, clk)
	var base *Baseline
	s := authStore(t, path, clk, &base)
	p := basePass(clk)
	p.Limits = []LimitSpec{{Window: "day", Amount: money.Dollar}}
	p.Bind = &Binding{PID: 42, StartTime: 7}
	_, bound, err := s.Issue(p)
	if err != nil {
		t.Fatal(err)
	}
	_, revoked, err := s.Issue(basePass(clk))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Revoke(revoked.ID); err != nil {
		t.Fatal(err)
	}
	if base == nil || base.Counter != 3 || len(base.Digests) != 2 {
		t.Fatalf("baseline %+v", base)
	}
	good, _ := os.ReadFile(path)
	reopen := func() Diff {
		t.Helper()
		s2, err := OpenStore(path, clk)
		if err != nil {
			t.Fatal(err)
		}
		s2.SetMACKey(testMACKey)
		d, err := s2.VerifyAgainst(base)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := reopen(); !d.OK || !d.MACOK {
		t.Fatalf("untouched store: %+v", d)
	}

	// A forged unbound, unlimited pass.
	editDoc(t, path, func(_, b map[string]any) {
		ps := b["passes"].([]any)
		forged := map[string]any{"id": "zzzzzzzzzz", "name": "x", "kind": "named", "created": clk.Now(),
			"expires": clk.Now().Add(1000 * time.Hour), "providers": []string{"*"}, "secret_sha256": strings.Repeat("ab", 32)}
		b["passes"] = append(ps, forged)
	})
	if d := reopen(); d.OK || d.MACOK || len(d.Added) != 1 || d.Added[0] != "zzzzzzzzzz" {
		t.Fatalf("forged pass accepted: %+v", d)
	}
	// Un-revoke, unbind, raise a limit: each shows as changed.
	for name, edit := range map[string]func(r map[string]any){
		"unrevoke": func(r map[string]any) { delete(r, "revoked") },
		"unbind":   func(r map[string]any) { delete(r, "bind") },
		"raise":    func(r map[string]any) { r["limits"] = []any{map[string]any{"window": "day", "amount_micros": 1 << 40}} },
	} {
		_ = os.WriteFile(path, good, 0o600)
		target := bound.ID
		if name == "unrevoke" {
			target = revoked.ID
		}
		editDoc(t, path, func(_, b map[string]any) {
			for _, r := range b["passes"].([]any) {
				if rec := r.(map[string]any); rec["id"] == target {
					edit(rec)
				}
			}
		})
		if d := reopen(); d.OK || len(d.Changed) != 1 || d.Changed[0] != target {
			t.Errorf("%s accepted: %+v", name, d)
		}
	}
	// Re-MACing without the key is impossible; an old authentic file is a
	// rollback (counter below the baseline).
	_ = os.WriteFile(path, good, 0o600)
	s3 := authStore(t, path, clk, &base)
	old, _ := os.ReadFile(path)
	if _, _, err := s3.Issue(basePass(clk)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s3.Issue(basePass(clk)); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(path, old, 0o600)
	if d := reopen(); d.OK || !d.MACOK || d.Counter >= d.Baseline {
		t.Fatalf("rollback accepted: %+v", d)
	}
}

// TestStoreOneAheadAndLockedRevocations covers the tolerated crash window
// and revocations made while locked.
func TestStoreOneAheadAndLockedRevocations(t *testing.T) {
	clk := newClock()
	_, path := openTemp(t, clk)
	var base *Baseline
	s := authStore(t, path, clk, &base)
	_, p1, _ := s.Issue(basePass(clk))
	prev := *base
	if _, _, err := s.Issue(basePass(clk)); err != nil {
		t.Fatal(err)
	}
	s2, _ := OpenStore(path, clk)
	s2.SetMACKey(testMACKey)
	if d, _ := s2.VerifyAgainst(&prev); !d.OK {
		t.Fatalf("one write ahead rejected: %+v", d)
	}

	// Locked: revocation is kept outside the authenticated body, survives
	// a restart, still verifies, and is folded in by Commit.
	s.SetMACKey(nil)
	if _, _, err := s.Issue(basePass(clk)); !errors.Is(err, ErrNoKey) {
		t.Fatalf("issue without key: %v", err)
	}
	before := *base
	if err := s.Revoke(p1.ID); err != nil {
		t.Fatal(err)
	}
	if base.Counter != before.Counter {
		t.Fatal("locked revocation changed the baseline")
	}
	s3, err := OpenStore(path, clk)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := s3.Get(p1.ID); !got.Revoked {
		t.Fatal("locked revocation lost on reload")
	}
	s3.SetCommitHook(func(b Baseline) { c := b; base = &c })
	s3.SetMACKey(testMACKey)
	if d, _ := s3.VerifyAgainst(base); !d.OK {
		t.Fatalf("store with locked revocation: %+v", d)
	}
	if err := s3.Commit(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("revoked_while_locked")) || base.Counter != before.Counter+1 {
		t.Fatalf("commit did not fold the revocation in: %s", raw)
	}
}
