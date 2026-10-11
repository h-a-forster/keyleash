package pass

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)}
}

func openTemp(t *testing.T, clk Clock) (*Store, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "passes.json")
	s, err := OpenStore(p, clk)
	if err != nil {
		t.Fatal(err)
	}
	return s, p
}

func basePass(clk Clock) Pass {
	return Pass{
		Name:      "editor",
		Kind:      KindNamed,
		Expires:   clk.Now().Add(24 * time.Hour),
		Providers: []string{"anthropic"},
	}
}

func TestTokenFormat(t *testing.T) {
	clk := newClock()
	s, _ := openTemp(t, clk)
	tok, p, err := s.Issue(basePass(clk))
	if err != nil {
		t.Fatal(err)
	}
	if TokenLen != 58 || len(tok) != TokenLen {
		t.Fatalf("token length %d", len(tok))
	}
	if !strings.HasPrefix(tok, "klp_"+p.ID+"_") {
		t.Fatalf("token does not embed id")
	}
	for _, c := range p.ID {
		if !strings.ContainsRune(crockford, c) {
			t.Fatalf("id char %q not lowercase crockford", c)
		}
	}
	id, ok := Parse(tok)
	if !ok || id != p.ID {
		t.Fatalf("Parse = %q %v", id, ok)
	}
	if !LooksLikePass(tok) {
		t.Fatal("LooksLikePass false for real token")
	}
}

func TestParseRejects(t *testing.T) {
	good := formatToken("0123456789", make([]byte, 32))
	if _, ok := Parse(good); !ok {
		t.Fatal("good token rejected")
	}
	cases := map[string]string{
		"empty":         "",
		"wrong prefix":  "klx_" + good[4:],
		"uppercase id":  "klp_ABCDEFGHJK" + good[14:],
		"id has i":      "klp_012345678i" + good[14:],
		"missing sep":   good[:14] + "-" + good[15:],
		"short":         good[:len(good)-1],
		"long":          good + "A",
		"bad base64":    good[:len(good)-1] + "*",
		"padding":       good[:len(good)-1] + "=",
		"noncanonical":  good[:len(good)-1] + "B", // stray trailing bits
		"provider key":  "sk-ant-api03-" + strings.Repeat(`ab`, 45),
		"spaces around": " " + good,
	}
	for name, tok := range cases {
		if _, ok := Parse(tok); ok {
			t.Errorf("%s: accepted", name)
		}
		if LooksLikePass(tok) {
			t.Errorf("%s: LooksLikePass true", name)
		}
	}
}

func TestVerify(t *testing.T) {
	clk := newClock()
	s, _ := openTemp(t, clk)
	tok, issued, err := s.Issue(basePass(clk))
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Verify(tok)
	if err != nil || got.ID != issued.ID {
		t.Fatalf("Verify = %+v, %v", got, err)
	}

	id, _ := Parse(tok)
	otherSecret := formatToken(id, make([]byte, 32))
	unknownID := formatToken("zzzzzzzzzz", make([]byte, 32))
	cases := []struct {
		name string
		tok  string
		want error
	}{
		{"garbage", "hello", ErrInvalid},
		{"wrong secret", otherSecret, ErrInvalid},
		{"unknown id", unknownID, ErrInvalid},
		{"right secret wrong id", "klp_zzzzzzzzzz" + tok[14:], ErrInvalid},
	}
	for _, c := range cases {
		_, err := s.Verify(c.tok)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: err = %v, want %v", c.name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), tok[15:]) {
			t.Errorf("%s: error leaks secret", c.name)
		}
	}
}

// TestVerifyUnknownIDDoesComparableWork checks the functional side of the
// timing defence: unknown ids hash and compare against a dummy, and the
// dummy can never be matched by any token (it is not the hash of a secret we
// know), and the error is indistinguishable from a wrong secret.
func TestVerifyUnknownIDDoesComparableWork(t *testing.T) {
	clk := newClock()
	s, _ := openTemp(t, clk)
	var zero [sha256.Size]byte
	if s.dummy == zero {
		t.Fatal("dummy hash not initialised")
	}
	s2, _ := openTemp(t, clk)
	if s.dummy == s2.dummy {
		t.Fatal("dummy hash is not random per store")
	}
	for i := 0; i < 50; i++ {
		sec, _ := newSecret()
		_, errUnknown := s.Verify(formatToken("abcdefghjk", sec))
		if errUnknown != ErrInvalid {
			t.Fatalf("unknown id: %v", errUnknown)
		}
	}
	tok, _, _ := s.Issue(basePass(clk))
	id, _ := Parse(tok)
	sec, _ := newSecret()
	_, errWrong := s.Verify(formatToken(id, sec))
	if errWrong != ErrInvalid {
		t.Fatalf("wrong secret: %v", errWrong)
	}
}

func TestExpiryAndRevocation(t *testing.T) {
	clk := newClock()
	s, _ := openTemp(t, clk)
	p := basePass(clk)
	p.Expires = clk.Now().Add(time.Hour)
	tok, issued, err := s.Issue(p)
	if err != nil {
		t.Fatal(err)
	}
	clk.Add(time.Hour)
	if _, err := s.Verify(tok); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}

	tok2, issued2, _ := s.Issue(basePass(clk))
	if err := s.Revoke(issued2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Verify(tok2); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked: %v", err)
	}
	if err := s.Revoke(issued2.ID); err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if err := s.Revoke("nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke unknown: %v", err)
	}
	// A wrong secret on a revoked pass must still say invalid, not revoked.
	id2, _ := Parse(tok2)
	if _, err := s.Verify(formatToken(id2, make([]byte, 32))); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong secret on revoked pass: %v", err)
	}
	_ = issued
}

func TestRevokeKindAndAll(t *testing.T) {
	clk := newClock()
	s, _ := openTemp(t, clk)
	named := basePass(clk)
	run := basePass(clk)
	run.Kind = KindRun
	tn, _, _ := s.Issue(named)
	tr1, _, _ := s.Issue(run)
	tr2, _, _ := s.Issue(run)
	n, err := s.RevokeKind(KindRun)
	if err != nil || n != 2 {
		t.Fatalf("RevokeKind = %d, %v", n, err)
	}
	for _, tok := range []string{tr1, tr2} {
		if _, err := s.Verify(tok); !errors.Is(err, ErrRevoked) {
			t.Fatalf("run pass not revoked: %v", err)
		}
	}
	if _, err := s.Verify(tn); err != nil {
		t.Fatalf("named pass affected: %v", err)
	}
	n, err = s.RevokeAll()
	if err != nil || n != 1 {
		t.Fatalf("RevokeAll = %d, %v", n, err)
	}
	if _, err := s.Verify(tn); !errors.Is(err, ErrRevoked) {
		t.Fatal("named pass not revoked")
	}
}

func TestIssueValidation(t *testing.T) {
	clk := newClock()
	s, _ := openTemp(t, clk)
	mod := func(f func(*Pass)) Pass { p := basePass(clk); f(&p); return p }
	cases := map[string]Pass{
		"no expiry":        mod(func(p *Pass) { p.Expires = time.Time{} }),
		"past expiry":      mod(func(p *Pass) { p.Expires = clk.Now().Add(-time.Second) }),
		"run no expiry":    mod(func(p *Pass) { p.Kind = KindRun; p.Expires = time.Time{} }),
		"bad kind":         mod(func(p *Pass) { p.Kind = "admin" }),
		"no providers":     mod(func(p *Pass) { p.Providers = nil }),
		"unknown provider": mod(func(p *Pass) { p.Providers = []string{"evilcorp"} }),
		"bad allow glob":   mod(func(p *Pass) { p.ModelAllow = []string{"claude-["} }),
		"bad deny glob":    mod(func(p *Pass) { p.ModelDeny = []string{"[x"} }),
		"backslash glob":   mod(func(p *Pass) { p.ModelDeny = []string{`a\b`} }),
		"empty glob":       mod(func(p *Pass) { p.ModelAllow = []string{""} }),
		"neg concurrency":  mod(func(p *Pass) { p.MaxConcurrency = -1 }),
		"bad window":       mod(func(p *Pass) { p.Limits = []LimitSpec{{Window: "week", Amount: money.Dollar}} }),
		"zero limit":       mod(func(p *Pass) { p.Limits = []LimitSpec{{Window: "day"}} }),
		"control in name":  mod(func(p *Pass) { p.Name = "a\x1b[2Jb" }),
		"bad bind":         mod(func(p *Pass) { p.Bind = &Binding{PID: 0} }),
		"dup provider":     mod(func(p *Pass) { p.Providers = []string{"anthropic", "Anthropic"} }),
		"star and other":   mod(func(p *Pass) { p.Providers = []string{"*", "openai"} }),
		"dup model":        mod(func(p *Pass) { p.ModelAllow = []string{"claude-*", "CLAUDE-*"} }),
		"too many models": mod(func(p *Pass) {
			for i := 0; i < MaxListLen+1; i++ {
				p.ModelDeny = append(p.ModelDeny, fmt.Sprintf("m%d", i))
			}
		}),
		"too many providers": mod(func(p *Pass) {
			for i := 0; i < MaxListLen+1; i++ {
				p.Providers = append(p.Providers, "openai")
			}
		}),
	}
	for name, p := range cases {
		if _, _, err := s.Issue(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(s.List()) != 0 {
		t.Fatal("rejected passes were stored")
	}
	// Caller-supplied identity/state fields are ignored.
	p := mod(func(p *Pass) {
		p.ID = "0000000000"
		p.Revoked = true
		p.Providers = []string{"Anthropic", "openai"}
	})
	_, got, err := s.Issue(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "0000000000" || got.Revoked || !got.Created.Equal(clk.Now()) {
		t.Fatalf("store did not own identity fields: %+v", got)
	}
	if got.Providers[0] != "anthropic" {
		t.Fatalf("provider not normalised: %v", got.Providers)
	}
}

func TestPersistenceNeverStoresSecret(t *testing.T) {
	clk := newClock()
	s, path := openTemp(t, clk)
	p := basePass(clk)
	p.ModelAllow = []string{"claude-*"}
	p.Limits = []LimitSpec{{Window: "day", Amount: 5 * money.Dollar}}
	p.Bind = &Binding{PID: 42, StartTime: 7, Image: `C:\x.exe`}
	tok, issued, err := s.Issue(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	secretText := tok[15:]
	if strings.Contains(string(raw), secretText) || strings.Contains(string(raw), tok) {
		t.Fatal("secret written to disk")
	}
	_, sec, _ := parse(tok)
	h := sha256.Sum256(sec)
	if !strings.Contains(string(raw), hex.EncodeToString(h[:])) {
		t.Fatal("hash not stored")
	}

	s2, err := OpenStore(path, clk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != issued.ID || got.Bind == nil || got.Bind.PID != 42 || len(got.Limits) != 1 || got.ModelAllow[0] != "claude-*" {
		t.Fatalf("round trip lost data: %+v", got)
	}
	if err := s2.Revoke(issued.ID); err != nil {
		t.Fatal(err)
	}
	s3, _ := OpenStore(path, clk)
	if _, err := s3.Verify(tok); !errors.Is(err, ErrRevoked) {
		t.Fatalf("revocation not persisted: %v", err)
	}
}

func TestOpenStoreRejectsCorruption(t *testing.T) {
	clk := newClock()
	dir := t.TempDir()
	good := `{"format":"keyleash-passes","version":1,"passes":[]}`
	rec := func(id, hash string) string {
		return `{"format":"keyleash-passes","version":1,"passes":[{"id":"` + id +
			`","name":"","kind":"named","created":"2026-01-01T00:00:00Z","expires":"2027-01-01T00:00:00Z","providers":["*"],"secret_sha256":"` + hash + `"}]}`
	}
	h := strings.Repeat("ab", 32)
	cases := map[string]string{
		"not json":     "{",
		"wrong format": `{"format":"x","version":1,"passes":[]}`,
		"wrong vers":   `{"format":"keyleash-passes","version":3,"passes":[]}`,
		"unknown fld":  `{"format":"keyleash-passes","version":1,"passes":[],"x":1}`,
		"bad id":       rec("BAD", h),
		"bad hash":     rec("0123456789", "abcd"),
		"dup":          strings.Replace(rec("0123456789", h), `]}`, `,`+rec("0123456789", h)[strings.Index(rec("0123456789", h), "[{")+1:], 1),
	}
	for name, content := range cases {
		p := filepath.Join(dir, name+".json")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenStore(p, clk); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p := filepath.Join(dir, "good.json")
	_ = os.WriteFile(p, []byte(good), 0o600)
	if _, err := OpenStore(p, clk); err != nil {
		t.Fatal(err)
	}
	p = filepath.Join(dir, "rec.json")
	_ = os.WriteFile(p, []byte(rec("0123456789", h)), 0o600)
	if s, err := OpenStore(p, clk); err != nil || len(s.List()) != 1 {
		t.Fatalf("valid record: %v", err)
	}
}

func TestAllowsModel(t *testing.T) {
	cases := []struct {
		allow, deny []string
		model       string
		want        bool
	}{
		{nil, nil, "anything", true},
		{nil, []string{"*opus*"}, "claude-opus-5", false},
		{nil, []string{"*opus*"}, "CLAUDE-OPUS-5", false},
		{[]string{"claude-*"}, nil, "claude-sonnet-5", true},
		{[]string{"CLAUDE-*"}, nil, "claude-sonnet-5", true},
		{[]string{"claude-*"}, nil, "gpt-5", false},
		{[]string{"claude-*"}, []string{"claude-opus*"}, "claude-opus-5", false}, // deny wins
		{[]string{"claude-*"}, nil, "", false},
		{[]string{"*"}, nil, "openai/gpt-5", true}, // * crosses /
		{[]string{"openai/*"}, nil, "openai/gpt-5", true},
		{[]string{"openai/*"}, nil, "anthropic/claude-opus-4", false},
		{nil, []string{"*opus*"}, "anthropic/claude-opus-4", false}, // slashed OpenRouter id denied
		{[]string{"claude-*"}, nil, "anthropic/claude-sonnet-5", false},
		{[]string{"*claude-*"}, []string{"*OPUS*"}, "Anthropic/Claude-Opus-4", false},
		{[]string{"*claude-*"}, nil, "anthropic/claude-sonnet-5", true},
		{nil, []string{"[bad"}, "x", false}, // malformed deny fails closed
		{[]string{"[bad"}, nil, "x", false},
		{nil, []string{`a\b`}, "x", false},
	}
	for i, c := range cases {
		p := Pass{ModelAllow: c.allow, ModelDeny: c.deny}
		if got := p.AllowsModel(c.model); got != c.want {
			t.Errorf("case %d: AllowsModel(%q) = %v", i, c.model, got)
		}
	}
}

func TestAllowsProvider(t *testing.T) {
	p := Pass{Providers: []string{"anthropic"}}
	if !p.AllowsProvider("anthropic") || !p.AllowsProvider("Anthropic") || p.AllowsProvider("openai") || p.AllowsProvider("") {
		t.Fatal("explicit list")
	}
	if (Pass{}).AllowsProvider("anthropic") {
		t.Fatal("empty list must allow nothing")
	}
	if !(Pass{Providers: []string{"*"}}).AllowsProvider("gemini") {
		t.Fatal("* must allow all")
	}
}

func TestTouchThrottle(t *testing.T) {
	clk := newClock()
	s, path := openTemp(t, clk)
	_, p, _ := s.Issue(basePass(clk))
	mtime := func() string {
		raw, _ := os.ReadFile(path)
		return string(raw)
	}
	t0 := clk.Now().Add(time.Second)
	if err := s.Touch(p.ID, t0); err != nil {
		t.Fatal(err)
	}
	afterFirst := mtime()
	if !strings.Contains(afterFirst, "last_used") {
		t.Fatal("first touch not persisted")
	}
	if err := s.Touch(p.ID, t0.Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	if mtime() != afterFirst {
		t.Fatal("touch within interval wrote to disk")
	}
	got, _ := s.Get(p.ID)
	if !got.LastUsed.Equal(t0.Add(10 * time.Second)) {
		t.Fatal("in-memory LastUsed not updated")
	}
	if err := s.Touch(p.ID, t0.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if mtime() == afterFirst {
		t.Fatal("touch after interval not persisted")
	}
	if err := s.Touch("nope", t0); err != nil {
		t.Fatal(err)
	}
}

func TestPruneExpired(t *testing.T) {
	clk := newClock()
	s, _ := openTemp(t, clk)
	short := basePass(clk)
	short.Expires = clk.Now().Add(time.Hour)
	_, ps, _ := s.Issue(short)
	_, pl, _ := s.Issue(basePass(clk))
	_, pr, _ := s.Issue(basePass(clk))
	_ = s.Revoke(pr.ID)
	clk.Add(3 * time.Hour)
	n, err := s.PruneExpired(time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("prune = %d, %v", n, err)
	}
	if _, ok := s.Get(ps.ID); ok {
		t.Fatal("expired pass kept")
	}
	if _, ok := s.Get(pr.ID); ok {
		t.Fatal("revoked pass kept")
	}
	if _, ok := s.Get(pl.ID); !ok {
		t.Fatal("live pass pruned")
	}
}

func TestConcurrentIssueVerify(t *testing.T) {
	clk := newClock()
	s, path := openTemp(t, clk)
	var wg sync.WaitGroup
	toks := make(chan string, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, p, err := s.Issue(basePass(clk))
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := s.Verify(tok); err != nil {
				t.Error(err)
			}
			_ = s.Touch(p.ID, clk.Now().Add(time.Minute))
			toks <- tok
		}()
	}
	wg.Wait()
	close(toks)
	s2, err := OpenStore(path, clk)
	if err != nil {
		t.Fatal(err)
	}
	for tok := range toks {
		if _, err := s2.Verify(tok); err != nil {
			t.Fatal(err)
		}
	}
}

func TestReturnedPassIsACopy(t *testing.T) {
	clk := newClock()
	s, _ := openTemp(t, clk)
	_, p, _ := s.Issue(basePass(clk))
	p.Providers[0] = "openai"
	got, _ := s.Get(p.ID)
	if got.Providers[0] != "anthropic" {
		t.Fatal("caller mutated store state")
	}
}

func TestEntriesMappingPersistsAndValidates(t *testing.T) {
	clk := newClock()
	s, path := openTemp(t, clk)
	p := basePass(clk)
	p.Entries = map[string]string{"anthropic": "e_1"}
	_, issued, err := s.Issue(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Entries["anthropic"] = "mutated"
	if issued.Entries["anthropic"] != "e_1" {
		t.Fatal("caller mutation leaked into the issued pass")
	}
	s2, err := OpenStore(path, clk)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := s2.Get(issued.ID)
	if !ok || got.Entries["anthropic"] != "e_1" {
		t.Fatalf("mapping not persisted: %+v", got.Entries)
	}
	for _, bad := range []map[string]string{{"nope": "e_1"}, {"anthropic": ""}, {"Anthropic": "e_1"}} {
		q := basePass(clk)
		q.Entries = bad
		if _, _, err := s.Issue(q); err == nil {
			t.Errorf("Issue accepted entries %v", bad)
		}
	}
}
