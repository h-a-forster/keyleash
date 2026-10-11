package vault

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// Small Argon2id costs for tests only; production defaults are
	// untouched outside this binary.
	kdfDefaults = kdfParams{Time: 1, MemoryKiB: 64, Threads: 1}
	kdfTarget = 0
	os.Exit(m.Run())
}

var (
	testPass   = []byte("correct horse battery staple")
	testSecret = []byte("sk-ant-api03-THIS-IS-A-TEST-SECRET-0123456789")
)

func newTestVault(t *testing.T) (*Vault, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.json")
	v, code, err := Create(path, SlotSpec{Type: SlotPassphrase, Label: "main", Passphrase: testPass})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return v, path, code
}

func mustSecret(t *testing.T, v *Vault, id string) []byte {
	t.Helper()
	var got []byte
	if err := v.WithSecret(id, func(s []byte) error {
		got = bytes.Clone(s)
		return nil
	}); err != nil {
		t.Fatalf("WithSecret: %v", err)
	}
	return got
}

// fakeHello is an in-memory HelloKey backed by a real RSA key.
type fakeHello struct {
	name  string
	key   *rsa.PrivateKey
	err   error
	calls atomic.Int32
}

func newFakeHello(t *testing.T, name string, bits int) *fakeHello {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeHello{name: name, key: k}
}

func (f *fakeHello) KeyName() string                    { return f.name }
func (f *fakeHello) PublicKey() (*rsa.PublicKey, error) { return &f.key.PublicKey, nil }
func (f *fakeHello) Decrypt(ctx context.Context, ct []byte, prompt string) ([]byte, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), nil, f.key, ct, nil)
}

func TestPassphraseRoundTripAndPersistence(t *testing.T) {
	v, path, _ := newTestVault(t)
	if !v.IsUnlocked() {
		t.Fatal("new vault should be unlocked")
	}
	if v.Seq() != 1 {
		t.Fatalf("seq = %d, want 1", v.Seq())
	}
	info, err := v.AddEntry("anthropic", KindAPIKey, "work key", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := v.Fingerprint(testSecret)
	if err != nil || fp != info.Fingerprint || len(fp) != 16 {
		t.Fatalf("fingerprint %q vs %q (%v)", fp, info.Fingerprint, err)
	}
	if v.Seq() != 2 {
		t.Fatalf("seq = %d, want 2", v.Seq())
	}
	v.Lock()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, testSecret) || bytes.Contains(raw, testPass) {
		t.Fatal("plaintext secret or passphrase on disk")
	}
	prev, err := readFile(PrevPath(path))
	if err != nil || prev.Seq != 1 {
		t.Fatalf("prev copy: seq %v err %v", prev, err)
	}

	v2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if v2.IsUnlocked() || v2.ID() != v.ID() || v2.Seq() != 2 {
		t.Fatal("reopened vault state wrong")
	}
	if err := v2.WithSecret(info.ID, func([]byte) error { return nil }); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked WithSecret err = %v", err)
	}
	if err := v2.UnlockPassphrase(testPass); err != nil {
		t.Fatal(err)
	}
	if got := mustSecret(t, v2, info.ID); !bytes.Equal(got, testSecret) {
		t.Fatal("secret mismatch")
	}
	es := v2.Entries()
	if len(es) != 1 || es[0] != info {
		t.Fatalf("entries = %+v, want %+v", es, info)
	}
	if fp2, _ := v2.Fingerprint(testSecret); fp2 != fp {
		t.Fatal("fingerprint not stable across open")
	}
}

func TestWrongPassphrase(t *testing.T) {
	v, path, _ := newTestVault(t)
	v.Lock()
	v2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range [][]byte{nil, []byte(""), []byte("correct horse battery stapl"), []byte("wrong passphrase!!")} {
		err := v2.UnlockPassphrase(p)
		if !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("UnlockPassphrase(%q) = %v", p, err)
		}
		if strings.Contains(err.Error(), string(testPass)) || (len(p) > 0 && strings.Contains(err.Error(), string(p))) {
			t.Fatal("error leaks secret")
		}
	}
	if v2.IsUnlocked() {
		t.Fatal("unlocked after wrong passphrase")
	}
	// Re-unlock of an unlocked vault still checks the secret.
	if err := v.UnlockPassphrase(testPass); err != nil {
		t.Fatal(err)
	}
	if err := v.UnlockPassphrase([]byte("nope nope nope")); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("re-unlock wrong = %v", err)
	}
	if !v.IsUnlocked() {
		t.Fatal("failed re-unlock should not lock")
	}
}

func TestRecoveryRoundTrip(t *testing.T) {
	v, path, code := newTestVault(t)
	e, err := v.AddEntry("openai", KindAdminKey, "", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()
	groups := strings.Split(code, "-")
	if len(groups) != 8 {
		t.Fatalf("code %d groups", len(groups))
	}
	variants := []string{
		code,
		strings.ToLower(code),
		strings.ReplaceAll(code, "-", ""),
		strings.ReplaceAll(code, "-", " "),
		" " + strings.ReplaceAll(strings.ReplaceAll(code, "0", "o"), "1", "l") + " ",
	}
	for _, c := range variants {
		v2, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := v2.UnlockRecovery(c); err != nil {
			t.Fatalf("UnlockRecovery(%q): %v", c, err)
		}
		if !bytes.Equal(mustSecret(t, v2, e.ID), testSecret) {
			t.Fatal("secret mismatch")
		}
	}

	// A well-formed code for a different vault: checksum ok, wrong secret.
	_, _, other := newTestVault(t)
	v3, _ := Open(path)
	if err := v3.UnlockRecovery(other); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("other code = %v", err)
	}
}

func TestRecoveryCodeParse(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5A}, 16)
	good := formatRecoveryCode(secret)
	flip := []byte(good)
	if flip[0] == 'A' {
		flip[0] = 'B'
	} else {
		flip[0] = 'A'
	}
	tests := []struct {
		name string
		code string
		ok   bool
	}{
		{"good", good, true},
		{"empty", "", false},
		{"short", good[:len(good)-1], false},
		{"long", good + "0", false},
		{"bad char U", strings.Replace(good, good[:1], "U", 1), false},
		{"symbol", strings.Replace(good, "-", "*", 1), false},
		{"checksum flipped", string(flip), false},
		{"last group changed", good[:len(good)-4] + "0000", good[len(good)-4:] == "0000"},
		{"unicode", good[:len(good)-1] + "é", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf, err := parseRecoveryCode(tc.code)
			if tc.ok {
				if err != nil {
					t.Fatalf("err = %v", err)
				}
				if !bytes.Equal(buf.Bytes(), secret) {
					t.Fatal("decoded secret mismatch")
				}
				buf.Destroy()
				return
			}
			if !errors.Is(err, ErrBadRecoveryCode) {
				t.Fatalf("err = %v, want ErrBadRecoveryCode", err)
			}
		})
	}
}

func TestBadRecoveryCodeBeforeKDF(t *testing.T) {
	v, path, _ := newTestVault(t)
	v.Lock()
	v2, _ := Open(path)
	// Make any KDF call fail loudly: if the checksum check were skipped,
	// argon2KEK would reject this slot param and return ErrCorrupt instead.
	v2.f = v2.f.clone()
	for i := range v2.f.Slots {
		if v2.f.Slots[i].KDF != nil {
			v2.f.Slots[i].KDF.Alg = "broken"
		}
	}
	if err := v2.UnlockRecovery("0000-0000-0000-0000-0000-0000-0000-0000"); !errors.Is(err, ErrBadRecoveryCode) {
		t.Fatalf("err = %v", err)
	}
}

func TestHelloSlot(t *testing.T) {
	v, path, _ := newTestVault(t)
	h := newFakeHello(t, "keyleash-test-key", 2048)
	si, err := v.AddSlot(SlotSpec{Type: SlotHello, Label: "hello", Hello: h})
	if err != nil {
		t.Fatal(err)
	}
	if si.HelloKey != h.name || si.Type != SlotHello || si.Convenience {
		t.Fatalf("slot info %+v", si)
	}
	e, err := v.AddEntry("gemini", KindAPIKey, "g", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()

	v2, _ := Open(path)
	if err := v2.UnlockHello(context.Background(), h, "Unlock keyleash"); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustSecret(t, v2, e.ID), testSecret) {
		t.Fatal("secret mismatch")
	}

	// Different key with the same name: OAEP decrypt fails → error from h.
	v3, _ := Open(path)
	imposter := newFakeHello(t, h.name, 2048)
	if err := v3.UnlockHello(context.Background(), imposter, ""); err == nil || v3.IsUnlocked() {
		t.Fatalf("imposter unlock err = %v", err)
	}
	// Unknown key name: no slot → ErrWrongSecret, Decrypt never called.
	other := newFakeHello(t, "other", 2048)
	if err := v3.UnlockHello(context.Background(), other, ""); !errors.Is(err, ErrWrongSecret) || other.calls.Load() != 0 {
		t.Fatalf("unknown key err = %v calls=%d", err, other.calls.Load())
	}
	// Cancellation propagates.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v3.UnlockHello(ctx, h, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled err = %v", err)
	}
	if err := v3.UnlockHello(context.Background(), nil, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil hello err = %v", err)
	}

	// Weak RSA keys are refused.
	weak := newFakeHello(t, "weak", 1024)
	if _, err := v.AddSlot(SlotSpec{Type: SlotHello, Hello: weak}); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked AddSlot = %v", err)
	}
	if _, err := v2.AddSlot(SlotSpec{Type: SlotHello, Hello: weak}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("weak key AddSlot = %v", err)
	}
}

func TestDPAPISlot(t *testing.T) {
	v, path, _ := newTestVault(t)
	_, err := v.AddSlot(SlotSpec{Type: SlotDPAPI, Label: "logon"})
	if runtime.GOOS != "windows" {
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("AddSlot dpapi = %v, want ErrUnsupported", err)
		}
		if err := v.UnlockDPAPI(); !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("UnlockDPAPI = %v", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	e, err := v.AddEntry("openai", KindAPIKey, "", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()
	v2, _ := Open(path)
	if err := v2.UnlockDPAPI(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustSecret(t, v2, e.ID), testSecret) {
		t.Fatal("secret mismatch")
	}
	// The DPAPI blob is bound to the vault id via entropy: a corrupted blob
	// fails as a wrong secret.
	v3, _ := Open(path)
	v3.f = v3.f.clone()
	for i := range v3.f.Slots {
		if v3.f.Slots[i].Type == SlotDPAPI {
			v3.f.Slots[i].KEKBlob[len(v3.f.Slots[i].KEKBlob)-1] ^= 1
		}
	}
	if err := v3.UnlockDPAPI(); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("damaged dpapi = %v", err)
	}
	// With only dpapi + recovery left, removing recovery is refused.
	if err := v2.RemoveSlot(slotOfType(t, v2, SlotPassphrase)); err != nil {
		t.Fatal(err)
	}
	if err := v2.RemoveSlot(slotOfType(t, v2, SlotRecovery)); !errors.Is(err, ErrLastSlot) {
		t.Fatalf("remove last strong slot = %v", err)
	}
	// Removing the convenience slot is fine.
	if err := v2.RemoveSlot(slotOfType(t, v2, SlotDPAPI)); err != nil {
		t.Fatal(err)
	}
}

func slotOfType(t *testing.T, v *Vault, typ string) string {
	t.Helper()
	for _, s := range v.Slots() {
		if s.Type == typ {
			return s.ID
		}
	}
	t.Fatalf("no %s slot", typ)
	return ""
}

func TestSlotManagement(t *testing.T) {
	v, path, code := newTestVault(t)
	if got := len(v.Slots()); got != 2 {
		t.Fatalf("slots = %d", got)
	}
	if _, err := v.AddSlot(SlotSpec{Type: SlotPassphrase, Passphrase: []byte("short")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short passphrase = %v", err)
	}
	if _, err := v.AddSlot(SlotSpec{Type: SlotRecovery}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("recovery via AddSlot = %v", err)
	}
	if _, err := v.AddSlot(SlotSpec{Type: "fido2"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown type = %v", err)
	}
	if _, err := v.AddSlot(SlotSpec{Type: SlotPassphrase, Label: "bad\nlabel", Passphrase: testPass}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("control char label = %v", err)
	}
	second := []byte("second passphrase here")
	if _, err := v.AddSlot(SlotSpec{Type: SlotPassphrase, Label: "second", Passphrase: second}); err != nil {
		t.Fatal(err)
	}

	newCode, err := v.RotateRecovery()
	if err != nil || newCode == code {
		t.Fatalf("RotateRecovery: %v", err)
	}
	n := 0
	for _, s := range v.Slots() {
		if s.Type == SlotRecovery {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("recovery slots = %d", n)
	}
	if err := v.RemoveSlot("slot_0000000000000000"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove unknown = %v", err)
	}
	if err := v.RemoveSlot(v.Slots()[0].ID); err != nil { // first passphrase
		t.Fatal(err)
	}
	v.Lock()

	v2, _ := Open(path)
	if err := v2.UnlockRecovery(code); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("old recovery code = %v", err)
	}
	if err := v2.UnlockPassphrase(testPass); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("removed passphrase = %v", err)
	}
	if err := v2.UnlockPassphrase(second); err != nil {
		t.Fatal(err)
	}
	if err := v2.UnlockRecovery(newCode); err != nil {
		t.Fatal(err)
	}
	for _, s := range v2.Slots() {
		if s.Type == SlotRecovery {
			if err := v2.RemoveSlot(s.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := v2.RemoveSlot(v2.Slots()[0].ID); !errors.Is(err, ErrLastSlot) {
		t.Fatalf("remove last slot = %v", err)
	}
}

func TestEntryOperations(t *testing.T) {
	v, path, _ := newTestVault(t)
	bad := []struct {
		name, provider, kind, label string
		secret                      []byte
	}{
		{"empty provider", "", KindAPIKey, "", testSecret},
		{"upper provider", "OpenAI", KindAPIKey, "", testSecret},
		{"nul provider", "open\x00ai", KindAPIKey, "", testSecret},
		{"bad kind", "openai", "token", "", testSecret},
		{"long label", "openai", KindAPIKey, strings.Repeat("x", maxLabelLen+1), testSecret},
		{"empty secret", "openai", KindAPIKey, "", nil},
		{"huge secret", "openai", KindAPIKey, "", make([]byte, MaxSecretSize+1)},
	}
	for _, tc := range bad {
		if _, err := v.AddEntry(tc.provider, tc.kind, tc.label, tc.secret); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
	a, err := v.AddEntry("anthropic", KindAPIKey, "a", []byte("secret-a"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.AddEntry("openai", KindAPIKey, "b", []byte("secret-b"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // rotated timestamps have 1s resolution
	if err := v.ReplaceEntrySecret(a.ID, []byte("secret-a2")); err != nil {
		t.Fatal(err)
	}
	if err := v.ReplaceEntrySecret("ent_0000000000000000", []byte("x")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replace unknown = %v", err)
	}
	if err := v.ReplaceEntrySecret(a.ID, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replace empty = %v", err)
	}
	if got := mustSecret(t, v, a.ID); string(got) != "secret-a2" {
		t.Fatal("replaced secret mismatch")
	}
	na := v.Entries()[0]
	if na.Fingerprint == a.Fingerprint || !na.Rotated.After(na.Created) || !na.Created.Equal(a.Created) {
		t.Fatalf("rotation metadata %+v", na)
	}
	if err := v.RemoveEntry(b.ID); err != nil {
		t.Fatal(err)
	}
	if err := v.RemoveEntry(b.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double remove = %v", err)
	}
	if err := v.WithSecret(b.ID, func([]byte) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed WithSecret = %v", err)
	}
	sentinel := errors.New("fn error")
	if err := v.WithSecret(a.ID, func([]byte) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("fn error not returned: %v", err)
	}
	v.Lock()
	v2, _ := Open(path)
	if err := v2.UnlockPassphrase(testPass); err != nil {
		t.Fatal(err)
	}
	if len(v2.Entries()) != 1 || string(mustSecret(t, v2, a.ID)) != "secret-a2" {
		t.Fatal("state not persisted")
	}
}

func TestLockWipes(t *testing.T) {
	v, _, _ := newTestVault(t)
	e, err := v.AddEntry("anthropic", KindAPIKey, "", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	dek := v.dek
	var leaked []byte
	_ = v.WithSecret(e.ID, func(s []byte) error { leaked = s; return nil })
	v.Lock()
	v.Lock() // idempotent
	if v.IsUnlocked() || v.dek != nil || dek.Bytes() != nil {
		t.Fatal("DEK not destroyed on Lock")
	}
	_ = leaked // the secret buffer was unmapped after fn; not readable here
	if err := v.WithSecret(e.ID, func([]byte) error { return nil }); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	if _, err := v.AddEntry("openai", KindAPIKey, "", testSecret); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	if err := v.RemoveEntry(e.ID); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	if err := v.ReplaceEntrySecret(e.ID, testSecret); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	if _, err := v.Fingerprint(testSecret); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	if _, err := v.DeriveKey(InfoAuditAnchor); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	if _, err := v.RotateRecovery(); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	if err := v.RemoveSlot(v.Slots()[0].ID); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	if _, err := v.AddSlot(SlotSpec{Type: SlotPassphrase, Passphrase: testPass}); !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
}

func TestDeriveKey(t *testing.T) {
	v, _, _ := newTestVault(t)
	tests := []struct {
		info string
		ok   bool
	}{
		{InfoAuditAnchor, true},
		{"keyleash/v1/pass-store", true},
		{"keyleash/v1/", false},
		{"keyleash/v1/entry", false},
		{"keyleash/v1/header-mac", false},
		{"keyleash/v2/audit-anchor", false},
		{"audit-anchor", false},
		{"", false},
		{"KEYLEASH/v1/x", false},
		{"keyleash/v1/x\x00", false},
	}
	for _, tc := range tests {
		k, err := v.DeriveKey(tc.info)
		if tc.ok {
			if err != nil || len(k) != 32 {
				t.Errorf("DeriveKey(%q) = %d bytes, %v", tc.info, len(k), err)
			}
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("DeriveKey(%q) err = %v", tc.info, err)
		}
	}
	a1, _ := v.DeriveKey("keyleash/v1/a")
	a2, _ := v.DeriveKey("keyleash/v1/a")
	b, _ := v.DeriveKey("keyleash/v1/b")
	if !bytes.Equal(a1, a2) || bytes.Equal(a1, b) {
		t.Fatal("DeriveKey not deterministic/domain-separated")
	}
	// Derived keys must not equal the internal subkeys.
	for _, info := range []string{infoEntry, infoHeaderMAC} {
		k, _ := deriveSubkey(v.dek.Bytes(), info)
		if bytes.Equal(k.Bytes(), a1) {
			t.Fatal("collision with internal key")
		}
		k.Destroy()
	}
}

// tamper rewrites the vault file at path after applying mut to its parsed
// form (without recomputing the MAC).
func tamper(t *testing.T, path string, mut func(f *fileV1)) {
	t.Helper()
	f, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	mut(f)
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func idx(f *fileV1, typ string) int {
	for i, s := range f.Slots {
		if s.Type == typ {
			return i
		}
	}
	panic("no slot " + typ)
}

func TestTamperDetection(t *testing.T) {
	type tc struct {
		name string
		mut  func(f *fileV1)
		want error
	}
	pp := func(f *fileV1) *slotV1 { return &f.Slots[idx(f, SlotPassphrase)] }
	rec := func(f *fileV1) *slotV1 { return &f.Slots[idx(f, SlotRecovery)] }
	tests := []tc{
		// Changes to the slot being used make its KEK or AEAD fail.
		{"used slot salt", func(f *fileV1) { pp(f).KDF.Salt[0] ^= 1 }, ErrWrongSecret},
		{"used slot time", func(f *fileV1) { pp(f).KDF.Time++ }, ErrWrongSecret},
		{"used slot memory", func(f *fileV1) { pp(f).KDF.MemoryKiB += 8 }, ErrWrongSecret},
		{"used slot wrapped", func(f *fileV1) { pp(f).Wrapped[3] ^= 1 }, ErrWrongSecret},
		{"used slot nonce", func(f *fileV1) { pp(f).Nonce[0] ^= 1 }, ErrWrongSecret},
		{"used slot id", func(f *fileV1) { pp(f).ID = "slot_00000000000000ff" }, ErrWrongSecret},
		{"used slot removed", func(f *fileV1) { f.Slots = f.Slots[idx(f, SlotRecovery):][:1] }, ErrWrongSecret},
		{"used slot retyped", func(f *fileV1) {
			s := pp(f)
			s.Type = SlotRecovery
		}, ErrWrongSecret},
		{"vault id", func(f *fileV1) { f.VaultID = strings.Repeat("ab", 16) }, ErrWrongSecret},
		// Changes to anything else are caught by the header MAC.
		{"other slot salt", func(f *fileV1) { rec(f).KDF.Salt[0] ^= 1 }, ErrTampered},
		{"other slot params", func(f *fileV1) { rec(f).KDF.Time++ }, ErrTampered},
		{"other slot wrapped", func(f *fileV1) { rec(f).Wrapped[0] ^= 1 }, ErrTampered},
		{"slot label", func(f *fileV1) { pp(f).Label = "evil" }, ErrTampered},
		{"slot created", func(f *fileV1) { pp(f).Created = "2001-01-01T00:00:00Z" }, ErrTampered},
		{"other slot removed", func(f *fileV1) { f.Slots = f.Slots[:idx(f, SlotRecovery)] }, ErrTampered},
		{"slots reordered", func(f *fileV1) { f.Slots[0], f.Slots[1] = f.Slots[1], f.Slots[0] }, ErrTampered},
		{"slot added", func(f *fileV1) {
			s := *rec(f)
			s.ID = "slot_00000000000000aa"
			f.Slots = append(f.Slots, s)
		}, ErrTampered},
		{"entry ciphertext", func(f *fileV1) { f.Entries[0].Ciphertext[0] ^= 1 }, ErrTampered},
		{"entry nonce", func(f *fileV1) { f.Entries[0].Nonce[0] ^= 1 }, ErrTampered},
		{"entry label", func(f *fileV1) { f.Entries[0].Label = "x" }, ErrTampered},
		{"entry provider", func(f *fileV1) { f.Entries[0].Provider = "openai" }, ErrTampered},
		{"entry kind", func(f *fileV1) { f.Entries[0].Kind = KindAdminKey }, ErrTampered},
		{"entry fingerprint", func(f *fileV1) { f.Entries[0].Fingerprint = strings.Repeat("0", 16) }, ErrTampered},
		{"entry rotated", func(f *fileV1) { f.Entries[0].Rotated = "2001-01-01T00:00:00Z" }, ErrTampered},
		{"entry id", func(f *fileV1) { f.Entries[0].ID = "ent_00000000000000ff" }, ErrTampered},
		{"entry removed", func(f *fileV1) { f.Entries = f.Entries[1:] }, ErrTampered},
		{"entries reordered", func(f *fileV1) { f.Entries[0], f.Entries[1] = f.Entries[1], f.Entries[0] }, ErrTampered},
		{"entry duplicated", func(f *fileV1) {
			e := f.Entries[0]
			e.ID = "ent_00000000000000aa"
			f.Entries = append(f.Entries, e)
		}, ErrTampered},
		{"ciphertext swapped", func(f *fileV1) {
			a, b := &f.Entries[0], &f.Entries[1]
			a.Nonce, b.Nonce = b.Nonce, a.Nonce
			a.Ciphertext, b.Ciphertext = b.Ciphertext, a.Ciphertext
		}, ErrTampered},
		{"seq rolled back", func(f *fileV1) { f.Seq-- }, ErrTampered},
		{"seq bumped", func(f *fileV1) { f.Seq += 10 }, ErrTampered},
		{"vault created", func(f *fileV1) { f.Created = "2001-01-01T00:00:00Z" }, ErrTampered},
		{"mac", func(f *fileV1) { f.MAC[0] ^= 1 }, ErrTampered},
	}
	for _, c := range tests {
		t.Run(c.name, func(t *testing.T) {
			v, path, _ := newTestVault(t)
			if _, err := v.AddEntry("anthropic", KindAPIKey, "a", []byte("secret-a")); err != nil {
				t.Fatal(err)
			}
			if _, err := v.AddEntry("openai", KindAPIKey, "b", []byte("secret-b")); err != nil {
				t.Fatal(err)
			}
			v.Lock()
			tamper(t, path, c.mut)
			v2, err := Open(path)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			err = v2.UnlockPassphrase(testPass)
			if !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
			if v2.IsUnlocked() {
				t.Fatal("unlocked despite tampering")
			}
		})
	}
}

// TestEntryAADBinding re-MACs a tampered file with the real DEK, simulating
// a bug or an attacker who can forge the header, and checks that the entry
// AEAD alone still refuses moved or relabelled ciphertexts.
func TestEntryAADBinding(t *testing.T) {
	cases := []struct {
		name string
		mut  func(f *fileV1)
	}{
		{"swap ciphertexts", func(f *fileV1) {
			a, b := &f.Entries[0], &f.Entries[1]
			a.Nonce, b.Nonce = b.Nonce, a.Nonce
			a.Ciphertext, b.Ciphertext = b.Ciphertext, a.Ciphertext
		}},
		{"relabel provider", func(f *fileV1) { f.Entries[0].Provider = "openrouter" }},
		{"change kind", func(f *fileV1) { f.Entries[0].Kind = KindAdminKey }},
		{"change id", func(f *fileV1) { f.Entries[0].ID = "ent_00000000000000ff" }},
		{"flip ciphertext", func(f *fileV1) { f.Entries[0].Ciphertext[5] ^= 1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, path, _ := newTestVault(t)
			if _, err := v.AddEntry("anthropic", KindAPIKey, "a", []byte("secret-a")); err != nil {
				t.Fatal(err)
			}
			if _, err := v.AddEntry("openai", KindAPIKey, "b", []byte("secret-b")); err != nil {
				t.Fatal(err)
			}
			dek := bytes.Clone(v.dek.Bytes())
			v.Lock()
			tamper(t, path, func(f *fileV1) {
				c.mut(f)
				mac, err := headerMAC(dek, f)
				if err != nil {
					t.Fatal(err)
				}
				f.MAC = mac
			})
			v2, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := v2.UnlockPassphrase(testPass); err != nil {
				t.Fatalf("unlock after re-MAC: %v", err)
			}
			id := v2.Entries()[0].ID
			called := false
			err = v2.WithSecret(id, func([]byte) error { called = true; return nil })
			if !errors.Is(err, ErrTampered) || called {
				t.Fatalf("WithSecret err = %v called=%v", err, called)
			}
		})
	}
}

func TestStructuralValidation(t *testing.T) {
	tests := []struct {
		name string
		mut  func(m map[string]any)
	}{
		{"version 2", func(m map[string]any) { m["version"] = 2 }},
		{"format", func(m map[string]any) { m["format"] = "other" }},
		{"unknown field", func(m map[string]any) { m["extra"] = true }},
		{"seq zero", func(m map[string]any) { m["seq"] = 0 }},
		{"no slots", func(m map[string]any) { m["slots"] = []any{} }},
		{"bad mac b64", func(m map[string]any) { m["mac"] = "!!!" }},
		{"padded b64", func(m map[string]any) { m["mac"] = m["mac"].(string) + "=" }},
		{"short mac", func(m map[string]any) { m["mac"] = "AAAA" }},
		{"bad vault id", func(m map[string]any) { m["vault_id"] = "ABC" }},
		{"slot bad nonce", func(m map[string]any) { slot0(m)["nonce"] = "AAAA" }},
		{"slot unknown type", func(m map[string]any) { slot0(m)["type"] = "fido2" }},
		{"slot huge memory", func(m map[string]any) { kdf0(m)["m_kib"] = float64(maxKDFMemoryKiB + 1) }},
		{"slot huge time", func(m map[string]any) { kdf0(m)["t"] = float64(maxKDFTime + 1) }},
		{"slot zero threads", func(m map[string]any) { kdf0(m)["p"] = 0 }},
		{"slot threads overflow", func(m map[string]any) { kdf0(m)["p"] = 300 }},
		{"slot unknown kdf", func(m map[string]any) { kdf0(m)["alg"] = "scrypt" }},
		{"duplicate slot id", func(m map[string]any) {
			s := m["slots"].([]any)
			s[1].(map[string]any)["id"] = s[0].(map[string]any)["id"]
		}},
		{"bad time", func(m map[string]any) { m["created"] = "yesterday" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, path, _ := newTestVault(t)
			v.Lock()
			raw, _ := os.ReadFile(path)
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			tc.mut(m)
			data, _ := json.Marshal(m)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			// Remove the .prev copy (there is none after Create) so the
			// corrupt main file is not silently replaced by a fallback.
			_, err := Open(path)
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Open err = %v, want ErrCorrupt", err)
			}
		})
	}
}

func slot0(m map[string]any) map[string]any { return m["slots"].([]any)[0].(map[string]any) }
func kdf0(m map[string]any) map[string]any  { return slot0(m)["kdf"].(map[string]any) }

func TestCrashRecovery(t *testing.T) {
	v, path, _ := newTestVault(t)
	a, err := v.AddEntry("anthropic", KindAPIKey, "a", []byte("secret-a")) // seq 2, prev = seq 1
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.AddEntry("openai", KindAPIKey, "b", []byte("secret-b")) // seq 3, prev = seq 2
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()

	t.Run("truncated main", func(t *testing.T) {
		raw, _ := os.ReadFile(path)
		if err := os.WriteFile(path, raw[:len(raw)/2], 0o600); err != nil {
			t.Fatal(err)
		}
		v2, err := Open(path)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		if !v2.RecoveredFromPrev() || v2.Seq() != 2 {
			t.Fatalf("recovered=%v seq=%d", v2.RecoveredFromPrev(), v2.Seq())
		}
		if err := v2.UnlockPassphrase(testPass); err != nil {
			t.Fatal(err)
		}
		if string(mustSecret(t, v2, a.ID)) != "secret-a" {
			t.Fatal("secret mismatch")
		}
		if err := v2.WithSecret(b.ID, func([]byte) error { return nil }); !errors.Is(err, ErrNotFound) {
			t.Fatalf("entry from lost write = %v", err)
		}
		// A write repairs main and keeps the good .prev (not the corrupt main).
		if _, err := v2.AddEntry("gemini", KindAPIKey, "c", []byte("secret-c")); err != nil {
			t.Fatal(err)
		}
		if v2.RecoveredFromPrev() || v2.Seq() != 3 {
			t.Fatal("state after repair")
		}
		if f, err := readFile(path); err != nil || f.Seq != 3 {
			t.Fatalf("main after repair: %v", err)
		}
		if f, err := readFile(PrevPath(path)); err != nil || f.Seq != 2 {
			t.Fatalf("prev after repair: %v", err)
		}
	})

	t.Run("main missing", func(t *testing.T) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		v3, err := Open(path)
		if err != nil || !v3.RecoveredFromPrev() {
			t.Fatalf("Open: %v", err)
		}
		if err := v3.UnlockPassphrase(testPass); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("both corrupt", func(t *testing.T) {
		_ = os.WriteFile(path, []byte("{"), 0o600)
		_ = os.WriteFile(PrevPath(path), []byte("garbage"), 0o600)
		if _, err := Open(path); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Open = %v", err)
		}
	})

	t.Run("tampered main does not fall back", func(t *testing.T) {
		v, path, _ := newTestVault(t)
		if _, err := v.AddEntry("anthropic", KindAPIKey, "a", []byte("x")); err != nil {
			t.Fatal(err)
		}
		v.Lock()
		tamper(t, path, func(f *fileV1) { f.Seq += 5 })
		v2, err := Open(path)
		if err != nil || v2.RecoveredFromPrev() {
			t.Fatalf("Open: %v", err)
		}
		if err := v2.UnlockPassphrase(testPass); !errors.Is(err, ErrTampered) {
			t.Fatalf("unlock = %v", err)
		}
	})
}

func TestCreateErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.json")
	if _, _, err := Create(path, SlotSpec{Type: SlotPassphrase, Passphrase: []byte("short")}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("short = %v", err)
	}
	if _, _, err := Create(path, SlotSpec{Type: SlotRecovery}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("recovery first = %v", err)
	}
	if _, _, err := Create(filepath.Join(dir, "vault.prev"), SlotSpec{Type: SlotPassphrase, Passphrase: testPass}); !errors.Is(err, ErrInvalid) {
		t.Fatalf(".prev path = %v", err)
	}
	if _, _, err := Create(path, SlotSpec{Type: SlotPassphrase, Passphrase: testPass}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Create(path, SlotSpec{Type: SlotPassphrase, Passphrase: testPass}); !errors.Is(err, ErrExists) {
		t.Fatalf("existing = %v", err)
	}
	if _, err := Open(filepath.Join(dir, "missing.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing = %v", err)
	}
	// Create in a new nested directory secures it.
	nested := filepath.Join(dir, "a", "b", "vault.json")
	if _, _, err := Create(nested, SlotSpec{Type: SlotPassphrase, Passphrase: testPass}); err != nil {
		t.Fatal(err)
	}
	checkOwnerOnly(t, filepath.Dir(nested), true)
	checkOwnerOnly(t, nested, false)
	// No temp files left behind.
	ents, _ := os.ReadDir(filepath.Dir(nested))
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	v, _, _ := newTestVault(t)
	want := map[string]string{}
	for i := 0; i < 4; i++ {
		s := strings.Repeat(string(rune('a'+i)), 40)
		e, err := v.AddEntry("anthropic", KindAPIKey, "", []byte(s))
		if err != nil {
			t.Fatal(err)
		}
		want[e.ID] = s
	}
	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var bad atomic.Int32
	var reads atomic.Int64
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				id := ids[(g+i)%len(ids)]
				err := v.WithSecret(id, func(s []byte) error {
					if string(s) != want[id] {
						bad.Add(1)
					}
					return nil
				})
				if err != nil && !errors.Is(err, ErrLocked) {
					bad.Add(1)
				}
				reads.Add(1)
				_, _ = v.Fingerprint([]byte("x"))
				_ = v.Entries()
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			v.Lock()
			if err := v.UnlockPassphrase(testPass); err != nil {
				bad.Add(1)
			}
			if _, err := v.AddEntry("openai", KindAPIKey, "", []byte("churn")); err != nil {
				bad.Add(1)
			}
		}
	}()
	time.Sleep(300 * time.Millisecond)
	// Let the lock/unlock goroutine finish before stopping readers.
	for v.Seq() < 1+4+20 {
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d bad results under concurrency", bad.Load())
	}
	if reads.Load() == 0 {
		t.Fatal("no concurrent reads happened")
	}
}

func TestSlotInfoHasNoSecrets(t *testing.T) {
	v, _, code := newTestVault(t)
	for _, s := range v.Slots() {
		str := strings.ToLower(strings.Join([]string{s.ID, s.Type, s.Label, s.HelloKey}, " "))
		if strings.Contains(str, strings.ToLower(code)) {
			t.Fatal("recovery code in slot info")
		}
	}
}
