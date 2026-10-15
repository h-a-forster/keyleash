package vault

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// copyAsVault writes data as vault.json in a fresh directory (no sidecar,
// no .prev) and returns the path: an attacker's or a backup's copy.
func copyAsVault(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "vault.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dekOf(v *Vault) []byte {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return bytes.Clone(v.dek.Bytes())
}

func openCopy(t *testing.T, data []byte) *Vault {
	t.Helper()
	v, err := Open(copyAsVault(t, data))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// removedSlot adds a slot that will later be removed and returns an unlock
// function for it: DPAPI on Windows (the review's scenario), a second
// passphrase elsewhere.
func removedSlot(t *testing.T, v *Vault) (id string, unlock func(*Vault) error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		si, err := v.AddSlot(SlotSpec{Type: SlotDPAPI, Label: "logon"})
		if err != nil {
			t.Fatal(err)
		}
		return si.ID, func(x *Vault) error { return x.UnlockDPAPI() }
	}
	p := []byte("to be removed passphrase")
	si, err := v.AddSlot(SlotSpec{Type: SlotPassphrase, Label: "old", Passphrase: p})
	if err != nil {
		t.Fatal(err)
	}
	return si.ID, func(x *Vault) error { return x.UnlockPassphrase(p) }
}

// TestRemoveSlotRekeys replicates the review finding: a removed slot must
// not open the live vault or .prev, and old copies it still opens must not
// share the live DEK.
func TestRemoveSlotRekeys(t *testing.T) {
	v, path, _ := newTestVault(t)
	e, err := v.AddEntry("anthropic", KindAPIKey, "a", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	id, unlockRemoved := removedSlot(t, v)
	oldCopy := readBytes(t, path)
	oldDEK := dekOf(v)

	if err := v.RemoveSlot(id); err != nil {
		t.Fatal(err)
	}
	newDEK := dekOf(v)
	if bytes.Equal(oldDEK, newDEK) {
		t.Fatal("RemoveSlot did not rotate the DEK")
	}
	// Entries survive the re-key, with fingerprints under the new DEK.
	if got := mustSecret(t, v, e.ID); !bytes.Equal(got, testSecret) {
		t.Fatal("secret lost in re-key")
	}
	fp, _ := v.Fingerprint(testSecret)
	if v.Entries()[0].Fingerprint != fp || fp == e.Fingerprint {
		t.Fatal("fingerprint not recomputed under the new DEK")
	}
	v.Lock()

	// The old copy still opens with the removed slot (unavoidable), but its
	// DEK is not the live one.
	old := openCopy(t, oldCopy)
	if err := unlockRemoved(old); err != nil {
		t.Fatalf("old copy with removed slot: %v", err)
	}
	if d := dekOf(old); !bytes.Equal(d, oldDEK) || bytes.Equal(d, newDEK) {
		t.Fatal("old copy DEK equals the live DEK")
	}
	// Nothing in the old copy authenticates the new file.
	nf, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := verifyHeaderMAC(oldDEK, nf); ok {
		t.Fatal("new file authenticates under the old DEK")
	}

	// The removed slot opens neither the live file nor .prev.
	for _, p := range []string{path, PrevPath(path)} {
		x := openCopy(t, readBytes(t, p))
		if err := unlockRemoved(x); !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("%s: removed slot unlock = %v", filepath.Base(p), err)
		}
		// .prev was replaced with the new state: it holds the new DEK.
		if err := x.UnlockPassphrase(testPass); err != nil {
			t.Fatalf("%s: %v", filepath.Base(p), err)
		}
		if !bytes.Equal(dekOf(x), newDEK) {
			t.Fatalf("%s holds the old DEK", filepath.Base(p))
		}
	}

	// The live vault reopens normally (sidecar matches).
	v2, _ := Open(path)
	if err := v2.UnlockPassphrase(testPass); err != nil {
		t.Fatal(err)
	}
	if got := mustSecret(t, v2, e.ID); !bytes.Equal(got, testSecret) {
		t.Fatal("secret mismatch after reopen")
	}
}

func TestRotateRecoveryKillsOldCode(t *testing.T) {
	v, path, code := newTestVault(t)
	if _, err := v.AddEntry("openai", KindAPIKey, "", testSecret); err != nil {
		t.Fatal(err)
	}
	oldDEK := dekOf(v)
	newCode, err := v.RotateRecovery()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dekOf(v), oldDEK) {
		t.Fatal("RotateRecovery did not rotate the DEK")
	}
	v.Lock()
	for _, p := range []string{path, PrevPath(path)} {
		x := openCopy(t, readBytes(t, p))
		if err := x.UnlockRecovery(code); !errors.Is(err, ErrWrongSecret) {
			t.Fatalf("%s: old code = %v", filepath.Base(p), err)
		}
		if err := x.UnlockRecovery(newCode); err != nil {
			t.Fatalf("%s: new code = %v", filepath.Base(p), err)
		}
	}
}

// TestRotateRecoveryKeepsOtherSlots: after a rotation the passphrase and
// hello slots still open the live file and .prev, entries survive with
// recomputed fingerprints, and exactly one recovery slot remains.
func TestRotateRecoveryKeepsOtherSlots(t *testing.T) {
	v, path, code := newTestVault(t)
	h := newFakeHello(t, "keyleash-test-key", 2048)
	if _, err := v.AddSlot(SlotSpec{Type: SlotHello, Label: "hello", Hello: h}); err != nil {
		t.Fatal(err)
	}
	e, err := v.AddEntry("anthropic", KindAPIKey, "a", testSecret)
	if err != nil {
		t.Fatal(err)
	}
	slotsBefore := len(v.Slots())
	newCode, err := v.RotateRecovery()
	if err != nil || newCode == code {
		t.Fatalf("RotateRecovery: %v", err)
	}
	if _, err := parseRecoveryCode(newCode); err != nil {
		t.Fatalf("new code does not parse: %v", err)
	}
	if strings.Contains(string(readBytes(t, path)), newCode) {
		t.Fatal("vault file contains the recovery code")
	}
	recovery := 0
	for _, s := range v.Slots() {
		if s.Type == SlotRecovery {
			recovery++
		}
	}
	if recovery != 1 || len(v.Slots()) != slotsBefore {
		t.Fatalf("slots after rotation: %d recovery of %d (before %d)", recovery, len(v.Slots()), slotsBefore)
	}
	fp, _ := v.Fingerprint(testSecret)
	if v.Entries()[0].Fingerprint != fp || fp == e.Fingerprint {
		t.Fatal("fingerprint not recomputed under the new DEK")
	}
	live := dekOf(v)
	v.Lock()
	for _, p := range []string{path, PrevPath(path)} {
		unlocks := map[string]func(x *Vault) error{
			"passphrase": func(x *Vault) error { return x.UnlockPassphrase(testPass) },
			"hello":      func(x *Vault) error { return x.UnlockHello(context.Background(), h, "") },
			"new code":   func(x *Vault) error { return x.UnlockRecovery(newCode) },
		}
		for name, unlock := range unlocks {
			x := openCopy(t, readBytes(t, p))
			if err := unlock(x); err != nil {
				t.Fatalf("%s with %s: %v", filepath.Base(p), name, err)
			}
			if !bytes.Equal(dekOf(x), live) {
				t.Fatalf("%s with %s: not the live DEK", filepath.Base(p), name)
			}
			if got := mustSecret(t, x, e.ID); !bytes.Equal(got, testSecret) {
				t.Fatalf("%s with %s: secret mismatch", filepath.Base(p), name)
			}
		}
	}
	// The live vault reopens normally (sidecar matches the new state).
	v2, _ := Open(path)
	if err := v2.UnlockPassphrase(testPass); err != nil {
		t.Fatal(err)
	}
	// Verifying (step-up) uses the new code, never the old one.
	if err := v2.VerifyRecovery(newCode); err != nil {
		t.Fatalf("verify new code: %v", err)
	}
	if err := v2.VerifyRecovery(code); !errors.Is(err, ErrWrongSecret) {
		t.Fatalf("verify old code: %v", err)
	}
}

// TestRotateRecoveryCrashAndRollback covers the states a crash or a restore
// can leave around a rotation (writeAtomic in writeRekey mode).
func TestRotateRecoveryCrashAndRollback(t *testing.T) {
	type files struct{ main, prev, seq []byte }
	snapshot := func(t *testing.T, path string) files {
		return files{readBytes(t, path), readBytes(t, PrevPath(path)), readBytes(t, SeqPath(path))}
	}
	put := func(t *testing.T, path string, f files) {
		t.Helper()
		for p, b := range map[string][]byte{path: f.main, PrevPath(path): f.prev, SeqPath(path): f.seq} {
			if b == nil {
				if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
				continue
			}
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	// rotated returns a vault path with one entry, rotated once, plus the
	// files before and after the rotation and both codes.
	rotated := func(t *testing.T) (path string, before, after files, oldCode, newCode string) {
		v, path, oldCode := newTestVault(t)
		if _, err := v.AddEntry("anthropic", KindAPIKey, "a", testSecret); err != nil {
			t.Fatal(err)
		}
		before = snapshot(t, path)
		newCode, err := v.RotateRecovery()
		if err != nil {
			t.Fatal(err)
		}
		v.Lock()
		return path, before, snapshot(t, path), oldCode, newCode
	}
	unlockRecovery := func(t *testing.T, path, code string) error {
		t.Helper()
		x, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return x.UnlockRecovery(code)
	}

	withSidecarModes(t, func(t *testing.T) {
		t.Run("crash before the main rename", func(t *testing.T) {
			// Nothing was committed: the old state (and code) stands, and
			// the new code (never shown) does not open it.
			path, before, _, oldCode, newCode := rotated(t)
			put(t, path, before)
			if err := unlockRecovery(t, path, newCode); !errors.Is(err, ErrWrongSecret) {
				t.Fatalf("new code = %v", err)
			}
			if err := unlockRecovery(t, path, oldCode); err != nil {
				t.Fatalf("old code = %v", err)
			}
		})
		t.Run("crash after the main rename", func(t *testing.T) {
			// Main is new; .prev and the sidecar are still the old ones.
			path, before, after, oldCode, newCode := rotated(t)
			put(t, path, files{after.main, before.prev, before.seq})
			if err := unlockRecovery(t, path, oldCode); !errors.Is(err, ErrWrongSecret) {
				t.Fatalf("old code on main = %v", err)
			}
			x, _ := Open(path)
			if err := x.UnlockRecovery(newCode); err != nil {
				t.Fatalf("new code = %v", err)
			}
			if got := mustSecret(t, x, x.Entries()[0].ID); !bytes.Equal(got, testSecret) {
				t.Fatal("secret mismatch")
			}
			// That unlock replaced the stale .prev (old DEK, old code) with
			// a copy of the live state, and reports it once.
			if found, err := x.TakeStalePrev(); !found || err != nil {
				t.Fatalf("stale .prev not scrubbed: found=%v err=%v", found, err)
			}
			if found, _ := x.TakeStalePrev(); found {
				t.Fatal("stale .prev reported twice")
			}
			prev := readBytes(t, PrevPath(path))
			if bytes.Equal(prev, before.prev) {
				t.Fatal(".prev still holds the pre-rotation state")
			}
			if err := openCopy(t, prev).UnlockRecovery(oldCode); !errors.Is(err, ErrWrongSecret) {
				t.Fatalf("old code on .prev = %v", err)
			}
			if err := openCopy(t, prev).UnlockRecovery(newCode); err != nil {
				t.Fatalf("new code on .prev = %v", err)
			}
			// A .prev under the live DEK is left alone.
			x.Lock()
			if err := x.UnlockRecovery(newCode); err != nil {
				t.Fatal(err)
			}
			if found, _ := x.TakeStalePrev(); found {
				t.Fatal("current .prev reported as stale")
			}
		})
		t.Run("main lost after the rotation", func(t *testing.T) {
			// .prev was replaced with the new state: falling back to it is
			// not a rollback and the old code does not open it.
			path, _, after, oldCode, newCode := rotated(t)
			put(t, path, files{nil, after.prev, after.seq})
			if err := unlockRecovery(t, path, oldCode); !errors.Is(err, ErrWrongSecret) {
				t.Fatalf("old code on .prev = %v", err)
			}
			x, _ := Open(path)
			if !x.RecoveredFromPrev() {
				t.Fatal("not recovered from .prev")
			}
			if err := x.UnlockRecovery(newCode); err != nil {
				t.Fatalf("new code on .prev = %v", err)
			}
		})
		t.Run("pre-rotation copy restored", func(t *testing.T) {
			// Restoring the old vault file next to the current sidecar is a
			// rollback even with the old code; the old code opens it only
			// with the owner's explicit override.
			path, before, after, oldCode, newCode := rotated(t)
			put(t, path, files{before.main, before.prev, after.seq})
			if err := unlockRecovery(t, path, oldCode); !errors.Is(err, ErrRollback) {
				t.Fatalf("old code on a restored copy = %v", err)
			}
			if err := unlockRecovery(t, path, newCode); !errors.Is(err, ErrWrongSecret) {
				t.Fatalf("new code on a restored copy = %v", err)
			}
		})
	})
}

// withSidecarModes runs f with the native sidecar encoding and, on
// Windows, also with the portable (HMAC) one.
func withSidecarModes(t *testing.T, f func(t *testing.T)) {
	t.Run("native", f)
	if sidecarUseDPAPI {
		t.Run("portable", func(t *testing.T) {
			sidecarUseDPAPI = false
			defer func() { sidecarUseDPAPI = dpapiSupported }()
			f(t)
		})
	}
}

func TestRollbackDetection(t *testing.T) {
	withSidecarModes(t, func(t *testing.T) {
		t.Run("older copy", func(t *testing.T) {
			v, path, _ := newTestVault(t)
			win := runtime.GOOS == "windows"
			if win {
				if _, err := v.AddSlot(SlotSpec{Type: SlotDPAPI}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := v.AddEntry("anthropic", KindAPIKey, "a", []byte("a")); err != nil {
				t.Fatal(err)
			}
			old := readBytes(t, path)
			if _, err := v.AddEntry("openai", KindAPIKey, "b", []byte("b")); err != nil {
				t.Fatal(err)
			}
			v.Lock()
			if err := os.WriteFile(path, old, 0o600); err != nil {
				t.Fatal(err)
			}
			v2, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			// No oracle: a wrong secret still gets ErrWrongSecret.
			if err := v2.UnlockPassphrase([]byte("wrong passphrase")); !errors.Is(err, ErrWrongSecret) {
				t.Fatalf("wrong secret = %v", err)
			}
			if err := v2.UnlockPassphrase(testPass); !errors.Is(err, ErrRollback) || v2.IsUnlocked() {
				t.Fatalf("rollback unlock = %v unlocked=%v", err, v2.IsUnlocked())
			}
			v2.AcceptRollback()
			if win {
				// DPAPI (no user presence) neither honours nor consumes it.
				if err := v2.UnlockDPAPI(); !errors.Is(err, ErrRollback) {
					t.Fatalf("dpapi with override = %v", err)
				}
			}
			if err := v2.UnlockPassphrase(testPass); err != nil {
				t.Fatalf("accepted unlock = %v", err)
			}
			if v2.Seq() != v.Seq()+1 || len(v2.Entries()) != 1 {
				t.Fatalf("after accept seq=%d entries=%d", v2.Seq(), len(v2.Entries()))
			}
			v2.Lock()
			v3, _ := Open(path)
			if err := v3.UnlockPassphrase(testPass); err != nil {
				t.Fatalf("reopen after accept = %v", err)
			}
			// The override was consumed.
			if err := os.WriteFile(path, old, 0o600); err != nil {
				t.Fatal(err)
			}
			v4, _ := Open(path)
			if err := v4.UnlockPassphrase(testPass); !errors.Is(err, ErrRollback) {
				t.Fatalf("second rollback = %v", err)
			}
		})

		t.Run("pre-rekey copy", func(t *testing.T) {
			v, path, _ := newTestVault(t)
			old := readBytes(t, path)
			id, _ := removedSlot(t, v)
			if err := v.RemoveSlot(id); err != nil {
				t.Fatal(err)
			}
			v.Lock()
			if err := os.WriteFile(path, old, 0o600); err != nil {
				t.Fatal(err)
			}
			v2, _ := Open(path)
			if err := v2.UnlockPassphrase(testPass); !errors.Is(err, ErrRollback) {
				t.Fatalf("pre-rekey rollback = %v", err)
			}
		})

		t.Run("sidecar states", func(t *testing.T) {
			v, path, _ := newTestVault(t)
			v.Lock()
			unlock := func() error {
				x, err := Open(path)
				if err != nil {
					t.Fatal(err)
				}
				return x.UnlockPassphrase(testPass)
			}
			// Missing sidecar: accepted and rewritten.
			if err := os.Remove(SeqPath(path)); err != nil {
				t.Fatal(err)
			}
			if err := unlock(); err != nil {
				t.Fatalf("missing sidecar = %v", err)
			}
			if _, err := os.Stat(SeqPath(path)); err != nil {
				t.Fatalf("sidecar not rewritten: %v", err)
			}
			// Garbage fails closed.
			if err := os.WriteFile(SeqPath(path), []byte("garbage"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := unlock(); !errors.Is(err, ErrRollback) {
				t.Fatalf("garbage sidecar = %v", err)
			}
			// A record for another vault fails closed.
			other, _, _ := newTestVault(t)
			data, err := encodeSidecar(other.ID(), 1, dekOf(other))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(SeqPath(path), data, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := unlock(); !errors.Is(err, ErrRollback) {
				t.Fatalf("foreign sidecar = %v", err)
			}
		})
	})
}

// pkcs1OnlyHello models a KSP without OAEP support.
type pkcs1OnlyHello struct {
	*fakeHello
	pkcsCalls int
}

func (k *pkcs1OnlyHello) Decrypt(context.Context, []byte, string) ([]byte, error) {
	k.calls.Add(1)
	return nil, fmt.Errorf("ksp: NTE_NOT_SUPPORTED: %w", ErrOAEPUnsupported)
}

func (k *pkcs1OnlyHello) DecryptPKCS1v15(_ context.Context, ct []byte, _ string) ([]byte, error) {
	k.pkcsCalls++
	return rsa.DecryptPKCS1v15(nil, k.key, ct) //nolint:staticcheck // test of the spec fallback
}

// noOAEPHello rejects OAEP and offers no fallback.
type noOAEPHello struct{ *fakeHello }

func (k *noOAEPHello) Decrypt(context.Context, []byte, string) ([]byte, error) {
	return nil, ErrOAEPUnsupported
}

// cancelHello has the PKCS#1 fallback but fails OAEP for another reason.
type cancelHello struct{ *pkcs1OnlyHello }

func (k *cancelHello) Decrypt(context.Context, []byte, string) ([]byte, error) {
	return nil, context.Canceled
}

// liarHello decrypts to the wrong value.
type liarHello struct{ *fakeHello }

func (k *liarHello) Decrypt(context.Context, []byte, string) ([]byte, error) {
	return make([]byte, 32), nil
}

func TestHelloPadding(t *testing.T) {
	t.Run("oaep test unwrap", func(t *testing.T) {
		v, _, _ := newTestVault(t)
		h := newFakeHello(t, "oaep", 2048)
		si, err := v.AddSlot(SlotSpec{Type: SlotHello, Hello: h, HelloPrompt: "Enable Hello"})
		if err != nil {
			t.Fatal(err)
		}
		if si.Padding != PaddingOAEPSHA256 || h.calls.Load() != 1 {
			t.Fatalf("padding=%q calls=%d", si.Padding, h.calls.Load())
		}
	})

	t.Run("pkcs1 fallback", func(t *testing.T) {
		v, path, _ := newTestVault(t)
		e, err := v.AddEntry("openai", KindAPIKey, "", testSecret)
		if err != nil {
			t.Fatal(err)
		}
		h := &pkcs1OnlyHello{fakeHello: newFakeHello(t, "pkcs", 2048)}
		si, err := v.AddSlot(SlotSpec{Type: SlotHello, Hello: h})
		if err != nil {
			t.Fatal(err)
		}
		if si.Padding != PaddingPKCS1v15 || h.pkcsCalls != 1 {
			t.Fatalf("padding=%q pkcsCalls=%d", si.Padding, h.pkcsCalls)
		}
		// Re-key re-wraps the hello slot with its recorded padding, no prompt.
		if err := v.RemoveSlot(slotOfType(t, v, SlotPassphrase)); err != nil {
			t.Fatal(err)
		}
		if h.pkcsCalls != 1 {
			t.Fatal("re-key prompted")
		}
		v.Lock()
		v2, _ := Open(path)
		if err := v2.UnlockHello(context.Background(), h, ""); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(mustSecret(t, v2, e.ID), testSecret) {
			t.Fatal("secret mismatch")
		}
		// A key without the fallback cannot open a PKCS#1 slot.
		v3, _ := Open(path)
		if err := v3.UnlockHello(context.Background(), h.fakeHello, ""); !errors.Is(err, ErrInvalid) {
			t.Fatalf("oaep-only key on pkcs1 slot = %v", err)
		}
	})

	t.Run("padding field authenticated", func(t *testing.T) {
		v, path, _ := newTestVault(t)
		h := &pkcs1OnlyHello{fakeHello: newFakeHello(t, "pkcs", 2048)}
		if _, err := v.AddSlot(SlotSpec{Type: SlotHello, Hello: h}); err != nil {
			t.Fatal(err)
		}
		v.Lock()
		tamper(t, path, func(f *fileV1) { f.Slots[idx(f, SlotHello)].Padding = PaddingOAEPSHA256 })
		v2, _ := Open(path)
		if err := v2.UnlockPassphrase(testPass); !errors.Is(err, ErrTampered) {
			t.Fatalf("padding tamper = %v", err)
		}
	})

	t.Run("no fallback available", func(t *testing.T) {
		v, _, _ := newTestVault(t)
		_, err := v.AddSlot(SlotSpec{Type: SlotHello, Hello: &noOAEPHello{newFakeHello(t, "n", 2048)}})
		if !errors.Is(err, ErrOAEPUnsupported) {
			t.Fatalf("err = %v", err)
		}
		if len(v.Slots()) != 2 {
			t.Fatal("slot added despite failure")
		}
	})

	t.Run("other errors do not fall back", func(t *testing.T) {
		v, _, _ := newTestVault(t)
		h := &cancelHello{&pkcs1OnlyHello{fakeHello: newFakeHello(t, "c", 2048)}}
		_, err := v.AddSlot(SlotSpec{Type: SlotHello, Hello: h})
		if !errors.Is(err, context.Canceled) || h.pkcsCalls != 0 || len(v.Slots()) != 2 {
			t.Fatalf("err = %v pkcsCalls=%d", err, h.pkcsCalls)
		}
	})

	t.Run("wrong round trip", func(t *testing.T) {
		v, _, _ := newTestVault(t)
		_, err := v.AddSlot(SlotSpec{Type: SlotHello, Hello: &liarHello{newFakeHello(t, "l", 2048)}})
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("err = %v", err)
		}
	})
}
