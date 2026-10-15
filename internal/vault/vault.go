// Package vault implements keyleash's encrypted key store (spec §5).
//
// A vault file holds provider secrets sealed with XChaCha20-Poly1305 under a
// random 256-bit data encryption key (DEK). The DEK is wrapped independently
// by each key slot (passphrase, recovery code, Windows Hello, DPAPI); any one
// slot unlocks the vault. All metadata is authenticated with an HMAC keyed
// from the DEK and verified on every unlock.
//
// While unlocked the DEK lives in a secmem.Buffer; Lock wipes it. Secrets are
// decrypted per call by WithSecret into a short-lived locked buffer.
//
// Before a successful unlock, the metadata returned by Slots and Entries is
// unauthenticated and must be treated as untrusted display data.
package vault

import (
	"context"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/h-a-forster/keyleash/internal/secmem"
)

// Errors returned by the vault. Callers match them with errors.Is. Messages
// never contain secret material.
var (
	// ErrLocked: the operation needs the vault unlocked.
	ErrLocked = errors.New("vault: locked")
	// ErrWrongSecret: no slot of the requested type accepted the secret.
	// It is returned both for a wrong secret and for "no such slot".
	ErrWrongSecret = errors.New("vault: wrong secret")
	// ErrTampered: authenticated data (header MAC or an entry AEAD) failed
	// verification under the correct key.
	ErrTampered = errors.New("vault: integrity check failed")
	// ErrNotFound: no slot or entry with that id.
	ErrNotFound = errors.New("vault: not found")
	// ErrLastSlot: removing the slot would leave no non-convenience slot.
	ErrLastSlot = errors.New("vault: cannot remove the last non-convenience slot")
	// ErrBadRecoveryCode: the recovery code is malformed or its checksum
	// does not match. Returned before any key derivation.
	ErrBadRecoveryCode = errors.New("vault: malformed recovery code")
	// ErrCorrupt: the file is not a structurally valid vault.
	ErrCorrupt = errors.New("vault: corrupt vault file")
	// ErrExists: Create found an existing vault (or its .prev) at the path.
	ErrExists = errors.New("vault: vault already exists")
	// ErrInvalid: an argument failed validation.
	ErrInvalid = errors.New("vault: invalid argument")
	// ErrRollback: the secret was correct and the file authentic, but the
	// anti-rollback sidecar records a newer state than the file on disk (or
	// cannot be read, or names another vault). The vault stays locked. It is
	// only returned after the DEK has been recovered, so it reveals nothing
	// to someone without a slot secret. See AcceptRollback.
	ErrRollback = errors.New("vault: vault file is older than the last recorded state (possible rollback)")
	// ErrChanged: the vault was re-keyed by a concurrent operation while an
	// unlock of the already-unlocked vault was in progress. Retry.
	ErrChanged = errors.New("vault: vault changed during unlock")
	// ErrOAEPUnsupported is the error a HelloKey's Decrypt must return (or
	// wrap, matched with errors.Is) when the key storage provider cannot do
	// RSA-OAEP-SHA256. internal/winhello has its own sentinel
	// (winhello.ErrOAEPUnsupported); the daemon's adapter must map it to
	// this one, or hello slot creation fails instead of falling back.
	ErrOAEPUnsupported = errors.New("vault: hello key does not support RSA-OAEP-SHA256")
	// ErrPrevNotScrubbed: a re-keying change (RemoveSlot, RotateRecovery) IS
	// committed and the vault holds the new DEK, but the .prev copy, which
	// still holds the old DEK, could neither be replaced nor removed. The
	// caller should tell the user to delete it.
	ErrPrevNotScrubbed = errPrevNotScrubbed
)

// MinPassphraseLen is the shortest passphrase accepted for a new slot.
const MinPassphraseLen = 8

// minRSABits is the smallest Hello public key accepted.
const minRSABits = 2048

// HelloKey is a Windows Hello (Microsoft Passport KSP) RSA key, normally an
// adapter around internal/winhello. Decrypt must perform RSA-OAEP with
// SHA-256 (MGF1-SHA-256, empty label), prompting the user, and must return
// an error matching ErrOAEPUnsupported when the provider cannot do OAEP.
type HelloKey interface {
	KeyName() string
	PublicKey() (*rsa.PublicKey, error)
	Decrypt(ctx context.Context, ciphertext []byte, prompt string) ([]byte, error)
}

// HelloKeyPKCS1 is optionally implemented by a HelloKey whose provider can
// decrypt RSA PKCS#1 v1.5. It is used only when Decrypt reports
// ErrOAEPUnsupported while a hello slot is being created, and afterwards
// for slots recorded with PaddingPKCS1v15 (spec §5.2).
type HelloKeyPKCS1 interface {
	DecryptPKCS1v15(ctx context.Context, ciphertext []byte, prompt string) ([]byte, error)
}

// SlotSpec describes a slot to create. Type is "passphrase", "hello" or
// "dpapi" (recovery slots are created by Create and RotateRecovery).
// Passphrase is read but not retained or modified; the caller wipes it.
//
// Creating a hello slot performs a test unwrap through Hello, which prompts
// the user (HelloPrompt is shown; Context cancels it, nil means
// context.Background). The test runs before the vault lock is taken.
type SlotSpec struct {
	Type        string
	Label       string
	Passphrase  []byte
	Hello       HelloKey
	HelloPrompt string
	Context     context.Context
}

// SlotInfo is public slot metadata.
type SlotInfo struct {
	ID      string
	Type    string
	Label   string
	Created time.Time
	// HelloKey is the KSP key name for hello slots.
	HelloKey string
	// Padding is PaddingOAEPSHA256 or PaddingPKCS1v15 for hello slots.
	Padding string
	// Convenience is true for slots any same-user process can open (dpapi).
	Convenience bool
}

// EntryInfo is public entry metadata. It never includes the secret.
type EntryInfo struct {
	ID          string
	Provider    string
	Kind        string
	Label       string
	Created     time.Time
	Rotated     time.Time
	Fingerprint string
}

// Vault is an open vault file. Its methods are safe for concurrent use.
type Vault struct {
	unlockMu sync.Mutex // serialises unlock attempts (KDF work)

	mu       sync.RWMutex
	path     string
	f        *fileV1        // current authenticated (or, while locked, parsed) state; never mutated in place
	dek      *secmem.Buffer // nil while locked
	fromPrev bool           // f was loaded from the .prev copy

	acceptRollback bool           // AcceptRollback armed for the next strong unlock
	accepted       *RollbackError // the rollback the last unlock accepted, if any
	seqFloor       uint64         // the next commit's seq must exceed this

	stalePrev    bool  // the last unlock found (and scrubbed) a .prev under another DEK
	stalePrevErr error // ErrPrevNotScrubbed if that .prev could not be scrubbed
}

// RollbackError is the ErrRollback an unlock returns: the vault file's seq
// is below the seq the anti-rollback sidecar recorded. errors.Is(err,
// ErrRollback) matches it.
type RollbackError struct {
	FileSeq, RecordedSeq uint64
}

func (e *RollbackError) Error() string {
	return fmt.Sprintf("%v (file seq %d, recorded seq %d)", ErrRollback, e.FileSeq, e.RecordedSeq)
}

// Is makes errors.Is(err, ErrRollback) true.
func (e *RollbackError) Is(target error) bool { return target == ErrRollback }

func nowString() string { return time.Now().UTC().Truncate(time.Second).Format(time.RFC3339) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func checkPath(path string) (string, error) {
	ext := filepath.Ext(path)
	if path == "" || strings.EqualFold(ext, ".prev") || strings.EqualFold(ext, ".seq") {
		return "", fmt.Errorf("%w: vault path", ErrInvalid)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("%w: vault path", ErrInvalid)
	}
	return abs, nil
}

// Create makes a new vault at path with the given first slot and a recovery
// slot, writes it, and returns it unlocked together with the recovery code,
// which is shown to the user once and never stored. It fails with ErrExists
// if a vault or its .prev copy already exists at path. If the parent
// directory does not exist it is created with owner-only permissions.
func Create(path string, first SlotSpec) (v *Vault, recoveryCode string, err error) {
	path, err = checkPath(path)
	if err != nil {
		return nil, "", err
	}
	if first.Type == SlotRecovery {
		return nil, "", fmt.Errorf("%w: first slot cannot be a recovery slot", ErrInvalid)
	}
	if err := checkSpec(first); err != nil {
		return nil, "", err
	}
	for _, p := range []string{path, PrevPath(path)} {
		if _, err := os.Lstat(p); err == nil {
			return nil, "", ErrExists
		} else if !errors.Is(err, fs.ErrNotExist) {
			return nil, "", fmt.Errorf("vault: stat: %w", err)
		}
	}
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := SecureDir(dir); err != nil {
			return nil, "", err
		}
	}

	// Secret-dependent and interactive work (Argon2id, Hello prompt) first.
	fp, err := prepareSlot(first)
	if err != nil {
		return nil, "", err
	}
	defer fp.destroy()
	rp, code, err := prepareRecovery()
	if err != nil {
		return nil, "", err
	}

	dek, err := secmem.New(dekSize)
	if err != nil {
		return nil, "", err
	}
	ok := false
	defer func() {
		if !ok {
			dek.Destroy()
		}
	}()
	if _, err := readRandInto(dek.Bytes()); err != nil {
		return nil, "", err
	}
	id, err := randHex(16)
	if err != nil {
		return nil, "", err
	}
	f := &fileV1{
		Format:  formatName,
		Version: formatVersion,
		VaultID: id,
		Created: nowString(),
	}
	s, err := fp.wrap(f.VaultID, dek.Bytes())
	if err != nil {
		return nil, "", err
	}
	rs, err := rp.wrap(f.VaultID, dek.Bytes())
	if err != nil {
		return nil, "", err
	}
	f.Slots = []slotV1{s, rs}
	// A leftover sidecar from an earlier vault at this path would make the
	// new vault look rolled back if the first sidecar write failed.
	if err := os.Remove(SeqPath(path)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, "", fmt.Errorf("vault: remove stale sidecar: %w", err)
	}
	v = &Vault{path: path, f: &fileV1{Seq: 0}, dek: dek}
	if err := v.commitLocked(f); err != nil {
		return nil, "", err
	}
	ok = true
	return v, code, nil
}

// Open reads and structurally validates the vault at path and returns it
// locked. If the main file is missing or corrupt (an interrupted write), the
// .prev copy is used and RecoveredFromPrev reports true; callers should
// surface that to the user. If the anti-rollback sidecar shows that a newer
// state than .prev had been written, unlock fails with ErrRollback. The
// next write replaces the main file.
func Open(path string) (*Vault, error) {
	path, err := checkPath(path)
	if err != nil {
		return nil, err
	}
	f, fromPrev, err := loadWithFallback(path)
	if err != nil {
		return nil, err
	}
	return &Vault{path: path, f: f, fromPrev: fromPrev}, nil
}

// Path returns the vault file path.
func (v *Vault) Path() string { return v.path }

// RecoveredFromPrev reports whether the current state was loaded from the
// .prev copy because the main file was missing or corrupt, and no write has
// happened since.
func (v *Vault) RecoveredFromPrev() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.fromPrev
}

// TakeStalePrev reports whether the last successful unlock found a .prev
// that does not authenticate under the live DEK (left by a re-key that
// crashed between its two renames, or whose scrub failed) and replaced it
// with a copy of the live state. err is ErrPrevNotScrubbed when that .prev
// could be neither replaced nor removed. Reading the result clears it, so
// each finding is reported once.
func (v *Vault) TakeStalePrev() (found bool, err error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	found, err = v.stalePrev, v.stalePrevErr
	v.stalePrev, v.stalePrevErr = false, nil
	return found, err
}

// ID returns the vault id.
func (v *Vault) ID() string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.f.VaultID
}

// Seq returns the write sequence number of the current state.
func (v *Vault) Seq() uint64 {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.f.Seq
}

// Slots returns slot metadata in file order. Unauthenticated while locked.
func (v *Vault) Slots() []SlotInfo {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]SlotInfo, len(v.f.Slots))
	for i, s := range v.f.Slots {
		out[i] = slotInfo(&s)
	}
	return out
}

// Entries returns entry metadata in file order. Unauthenticated while locked.
func (v *Vault) Entries() []EntryInfo {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]EntryInfo, len(v.f.Entries))
	for i, e := range v.f.Entries {
		out[i] = entryInfo(&e)
	}
	return out
}

func slotInfo(s *slotV1) SlotInfo {
	return SlotInfo{
		ID:          s.ID,
		Type:        s.Type,
		Label:       s.Label,
		Created:     parseTime(s.Created),
		HelloKey:    s.HelloKey,
		Padding:     s.Padding,
		Convenience: s.Type == SlotDPAPI,
	}
}

func entryInfo(e *entryV1) EntryInfo {
	return EntryInfo{
		ID:          e.ID,
		Provider:    e.Provider,
		Kind:        e.Kind,
		Label:       e.Label,
		Created:     parseTime(e.Created),
		Rotated:     parseTime(e.Rotated),
		Fingerprint: e.Fingerprint,
	}
}

// IsUnlocked reports whether the DEK is loaded.
func (v *Vault) IsUnlocked() bool {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.dek != nil
}

// Lock wipes the DEK. It is idempotent.
func (v *Vault) Lock() {
	v.mu.Lock()
	dek := v.dek
	v.dek = nil
	v.mu.Unlock()
	dek.Destroy()
}

// errSkipSlot tells unlock to try the next slot.
var errSkipSlot = errors.New("skip slot")

// unlock tries every slot of slotType with kek, which returns the slot KEK
// (or errSkipSlot to move on, or another error to abort). On success it
// verifies the header MAC before installing the DEK. Calling it on an
// unlocked vault re-verifies the secret and keeps the vault unlocked.
func (v *Vault) unlock(slotType string, kek func(s *slotV1) (*secmem.Buffer, error)) error {
	v.unlockMu.Lock()
	defer v.unlockMu.Unlock()

	v.mu.RLock()
	f := v.f // immutable snapshot
	fromPrev := v.fromPrev
	v.mu.RUnlock()

	var dek *secmem.Buffer
	for i := range f.Slots {
		s := &f.Slots[i]
		if s.Type != slotType {
			continue
		}
		k, err := kek(s)
		if errors.Is(err, errSkipSlot) {
			continue
		}
		if err != nil {
			return err
		}
		if k.Len() != 32 {
			k.Destroy()
			continue
		}
		d, err := openToBuffer(k.Bytes(), s.Nonce, s.Wrapped, slotAAD(f.VaultID, s.ID, s.Type))
		k.Destroy()
		if err != nil {
			if errors.Is(err, errAuth) {
				continue
			}
			return err
		}
		if d.Len() != dekSize {
			d.Destroy()
			continue
		}
		dek = d
		break
	}
	if dek == nil {
		return ErrWrongSecret
	}
	ok, err := verifyHeaderMAC(dek.Bytes(), f)
	if err != nil || !ok {
		dek.Destroy()
		if err != nil {
			return err
		}
		return ErrTampered
	}
	// Anti-rollback, only now that the caller has proven a slot secret.
	sc, err := checkSidecar(v.path, f, dek.Bytes())
	if err != nil {
		dek.Destroy()
		return err
	}
	if !fromPrev {
		// A .prev of this vault with a higher seq than the main file means
		// the main file was rolled back (e.g. an old backup restored
		// without its sidecar). It is the same signal as a newer sidecar
		// record, and .prev is left untouched (spec §5.4).
		if pf, perr := readFile(PrevPath(v.path)); perr == nil && pf.VaultID == f.VaultID && pf.Seq > f.Seq {
			sc.rollback = true
			sc.seq = max(sc.seq, pf.Seq)
		}
	}

	v.mu.Lock()
	if v.f != f {
		// Only possible when the vault was already unlocked and was written
		// meanwhile. A plain write keeps the DEK; a re-key does not.
		if ok, err := verifyHeaderMAC(dek.Bytes(), v.f); err != nil || !ok {
			v.mu.Unlock()
			dek.Destroy()
			return ErrChanged
		}
	}
	accept := false
	if slotType != SlotDPAPI {
		accept = v.acceptRollback
		v.acceptRollback = false
	}
	old := v.dek
	if sc.rollback && !accept {
		v.dek = nil
		v.mu.Unlock()
		old.Destroy()
		dek.Destroy()
		return &RollbackError{FileSeq: f.Seq, RecordedSeq: sc.seq}
	}
	v.dek = dek
	if sc.rollback {
		v.accepted = &RollbackError{FileSeq: f.Seq, RecordedSeq: sc.seq}
		// Owner override: make the accepted state the newest one. This also
		// rewrites the main file and the sidecar.
		v.seqFloor = max(v.seqFloor, sc.seq)
		if err := v.commitLocked(v.f.clone()); err != nil {
			v.dek = nil
			v.mu.Unlock()
			old.Destroy()
			dek.Destroy()
			return err
		}
	} else if !sc.current {
		// Missing, stale or unauthentic record: refresh it (best effort).
		_ = writeSidecar(v.path, v.f.VaultID, v.f.Seq, dek.Bytes())
	}
	if !v.fromPrev {
		// A crash between a re-key's two renames leaves .prev under the
		// old DEK, openable by the slots that re-key removed (spec §5.4).
		v.stalePrev, v.stalePrevErr = scrubStalePrev(v.path, v.f, dek.Bytes())
	}
	v.mu.Unlock()
	old.Destroy()
	return nil
}

// AcceptRollback arms a one-shot owner override for ErrRollback: the next
// unlock with a passphrase, recovery code or Windows Hello (not DPAPI, which
// needs no user presence) accepts the on-disk state even though the sidecar
// records a newer one, and immediately rewrites it with a seq above the
// recorded one. The override is consumed by that next successful strong
// unlock whether or not a rollback is present. Callers must only arm it on
// an explicit user request; afterwards the user should review Slots, since a
// rolled-back file can contain slots that had been removed.
func (v *Vault) AcceptRollback() { v.SetAcceptRollback(true) }

// SetAcceptRollback arms (on) or disarms the one-shot rollback override, so
// a caller can scope it to exactly one unlock attempt.
func (v *Vault) SetAcceptRollback(on bool) {
	v.mu.Lock()
	v.acceptRollback = on
	if on {
		v.accepted = nil
	}
	v.mu.Unlock()
}

// AcceptedRollback reports the rollback the most recent successful unlock
// accepted under the override (nil when it accepted none).
func (v *Vault) AcceptedRollback() *RollbackError {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.accepted == nil {
		return nil
	}
	r := *v.accepted
	return &r
}

// VerifyPassphrase checks p against the passphrase slots of the unlocked
// vault without changing its state: it derives the slot key (the slow KDF
// runs without holding any lock that Lock needs) and then confirms that the
// slot yields the DEK currently loaded. It returns ErrLocked when the vault
// is (or became) locked, ErrWrongSecret for a wrong passphrase and
// ErrChanged when the vault was re-keyed meanwhile.
func (v *Vault) VerifyPassphrase(p []byte) error {
	if len(p) == 0 {
		return ErrWrongSecret
	}
	return v.verify(SlotPassphrase, func(s *slotV1) (*secmem.Buffer, error) {
		return passphraseKEK(p, s)
	})
}

// VerifyRecovery is VerifyPassphrase for the recovery code. A malformed
// code returns ErrBadRecoveryCode without any KDF work.
func (v *Vault) VerifyRecovery(code string) error {
	secret, err := parseRecoveryCode(code)
	if err != nil {
		return err
	}
	defer secret.Destroy()
	return v.verify(SlotRecovery, func(s *slotV1) (*secmem.Buffer, error) {
		return passphraseKEK(secret.Bytes(), s)
	})
}

func (v *Vault) verify(slotType string, kek func(s *slotV1) (*secmem.Buffer, error)) error {
	v.mu.RLock()
	f, unlocked := v.f, v.dek != nil
	v.mu.RUnlock()
	if !unlocked {
		return ErrLocked
	}
	var found *secmem.Buffer
	for i := range f.Slots {
		s := &f.Slots[i]
		if s.Type != slotType {
			continue
		}
		k, err := kek(s)
		if err != nil {
			return err
		}
		if k.Len() != 32 {
			k.Destroy()
			continue
		}
		d, err := openToBuffer(k.Bytes(), s.Nonce, s.Wrapped, slotAAD(f.VaultID, s.ID, s.Type))
		k.Destroy()
		if err != nil {
			if errors.Is(err, errAuth) {
				continue
			}
			return err
		}
		found = d
		break
	}
	if found == nil {
		return ErrWrongSecret
	}
	defer found.Destroy()
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.dek == nil {
		return ErrLocked
	}
	if subtle.ConstantTimeCompare(found.Bytes(), v.dek.Bytes()) != 1 {
		if v.f != f {
			return ErrChanged
		}
		return ErrWrongSecret
	}
	return nil
}

// UnlockPassphrase unlocks with a passphrase slot. p is not retained.
func (v *Vault) UnlockPassphrase(p []byte) error {
	if len(p) == 0 {
		return ErrWrongSecret
	}
	return v.unlock(SlotPassphrase, func(s *slotV1) (*secmem.Buffer, error) {
		return passphraseKEK(p, s)
	})
}

// UnlockRecovery unlocks with the recovery code. A malformed code or a
// checksum mismatch returns ErrBadRecoveryCode without any KDF work.
func (v *Vault) UnlockRecovery(code string) error {
	secret, err := parseRecoveryCode(code)
	if err != nil {
		return err
	}
	defer secret.Destroy()
	return v.unlock(SlotRecovery, func(s *slotV1) (*secmem.Buffer, error) {
		return passphraseKEK(secret.Bytes(), s)
	})
}

// UnlockHello unlocks with the hello slot bound to h.KeyName(), asking h to
// decrypt the slot's wrapped KEK (which prompts the user) with the padding
// recorded in the slot. Errors from h (cancellation, device failure) are
// returned wrapped; ErrWrongSecret means no hello slot for that key opened.
func (v *Vault) UnlockHello(ctx context.Context, h HelloKey, prompt string) error {
	if h == nil {
		return fmt.Errorf("%w: nil hello key", ErrInvalid)
	}
	name := h.KeyName()
	return v.unlock(SlotHello, func(s *slotV1) (*secmem.Buffer, error) {
		if s.HelloKey != name {
			return nil, errSkipSlot
		}
		var plain []byte
		var err error
		switch s.Padding {
		case PaddingOAEPSHA256:
			plain, err = h.Decrypt(ctx, s.KEKBlob, prompt)
		case PaddingPKCS1v15:
			p1, ok := h.(HelloKeyPKCS1)
			if !ok {
				return nil, fmt.Errorf("%w: hello slot needs PKCS#1 v1.5 decryption", ErrInvalid)
			}
			plain, err = p1.DecryptPKCS1v15(ctx, s.KEKBlob, prompt)
		default:
			return nil, errSkipSlot
		}
		if err != nil {
			return nil, fmt.Errorf("vault: hello decrypt: %w", err)
		}
		defer secmem.Wipe(plain)
		if len(plain) != 32 {
			return nil, errSkipSlot
		}
		buf, err := secmem.New(32)
		if err != nil {
			return nil, err
		}
		copy(buf.Bytes(), plain)
		return buf, nil
	})
}

// UnlockDPAPI unlocks with a DPAPI slot for the current Windows user. On
// other platforms it returns an error wrapping errors.ErrUnsupported.
func (v *Vault) UnlockDPAPI() error {
	if !dpapiSupported {
		_, err := dpapiUnprotect(nil, nil)
		return err
	}
	v.mu.RLock()
	entropy := []byte(v.f.VaultID)
	v.mu.RUnlock()
	return v.unlock(SlotDPAPI, func(s *slotV1) (*secmem.Buffer, error) {
		k, err := dpapiUnprotect(s.KEKBlob, entropy)
		if err != nil {
			// Wrong user, wrong entropy or a damaged blob: try the next.
			return nil, errSkipSlot
		}
		return k, nil
	})
}

// checkSpec validates a SlotSpec without doing any expensive work.
func checkSpec(spec SlotSpec) error {
	if !validLabel(spec.Label) {
		return fmt.Errorf("%w: slot label", ErrInvalid)
	}
	switch spec.Type {
	case SlotPassphrase:
		if len(spec.Passphrase) < MinPassphraseLen {
			return fmt.Errorf("%w: passphrase shorter than %d bytes", ErrInvalid, MinPassphraseLen)
		}
	case SlotHello:
		if spec.Hello == nil || !validKeyName(spec.Hello.KeyName()) {
			return fmt.Errorf("%w: hello key", ErrInvalid)
		}
	case SlotDPAPI:
		if !dpapiSupported {
			_, err := dpapiProtect(nil, nil)
			return err
		}
	case SlotRecovery:
		return fmt.Errorf("%w: use RotateRecovery for recovery slots", ErrInvalid)
	default:
		return fmt.Errorf("%w: slot type", ErrInvalid)
	}
	return nil
}

func randomKEK() (*secmem.Buffer, error) {
	k, err := secmem.New(32)
	if err != nil {
		return nil, err
	}
	if _, err := readRandInto(k.Bytes()); err != nil {
		k.Destroy()
		return nil, err
	}
	return k, nil
}

// commitLocked authenticates nf as the next version under v.dek and writes
// it. The caller holds v.mu for writing (or exclusively owns v) and v.dek is
// set. On failure the in-memory state is unchanged.
func (v *Vault) commitLocked(nf *fileV1) error {
	mode := writeKeepPrev
	if v.fromPrev {
		// The main file is corrupt; do not move it over the good .prev.
		mode = writeNoPrev
	}
	return v.commitWith(nf, v.dek.Bytes(), mode)
}

// commitWith authenticates nf under dek, writes it with mode and installs it
// as v.f. When only the .prev scrub of a re-key failed it installs the state
// and returns errPrevNotScrubbed. It then records the new seq in the
// anti-rollback sidecar (best effort: a failure only weakens detection, and
// the next unlock rewrites a stale record).
func (v *Vault) commitWith(nf *fileV1, dek []byte, mode writeMode) error {
	nf.Seq = max(v.f.Seq, v.seqFloor) + 1
	mac, err := headerMAC(dek, nf)
	if err != nil {
		return err
	}
	nf.MAC = mac
	if err := validateFile(nf); err != nil {
		return fmt.Errorf("vault: refusing to write invalid state: %w", err)
	}
	data, err := json.MarshalIndent(nf, "", "  ")
	if err != nil {
		return fmt.Errorf("vault: encode: %w", err)
	}
	werr := writeAtomic(v.path, append(data, '\n'), mode)
	if werr != nil && !errors.Is(werr, errPrevNotScrubbed) {
		return werr
	}
	v.f = nf
	v.fromPrev = false
	_ = writeSidecar(v.path, nf.VaultID, nf.Seq, dek)
	return werr
}

// rekeyLocked commits nf under a fresh random DEK. Every entry is re-sealed
// under the new entry key with a new nonce (fingerprint recomputed), every
// slot in nf is re-wrapped from its public material (no secret, no prompt),
// and .prev is replaced with a copy of the new state (writeRekey). Slots not
// in nf never see the new DEK, so a removed slot, or an old copy of the file
// opened with it, yields only the old DEK. The caller holds v.mu for writing
// and v.dek is set. If it fails before the main file is replaced, file, state
// and DEK are unchanged.
//
// Re-keying changes everything derived from the DEK: entry fingerprints and
// DeriveKey outputs (e.g. the audit-anchor key).
func (v *Vault) rekeyLocked(nf *fileV1) error {
	newDEK, err := secmem.New(dekSize)
	if err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			newDEK.Destroy()
		}
	}()
	if _, err := readRandInto(newDEK.Bytes()); err != nil {
		return err
	}
	oldKey, err := deriveSubkey(v.dek.Bytes(), infoEntry)
	if err != nil {
		return err
	}
	defer oldKey.Destroy()
	for i := range nf.Entries {
		e := &nf.Entries[i]
		pt, err := openToBuffer(oldKey.Bytes(), e.Nonce, e.Ciphertext, entryAAD(nf.VaultID, e.ID, e.Provider, e.Kind))
		if errors.Is(err, errAuth) {
			return ErrTampered
		}
		if err != nil {
			return err
		}
		err = sealEntry(newDEK.Bytes(), nf.VaultID, e, pt.Bytes())
		pt.Destroy()
		if err != nil {
			return err
		}
	}
	for i := range nf.Slots {
		if err := wrapSlot(nf.VaultID, &nf.Slots[i], newDEK.Bytes()); err != nil {
			return err
		}
	}
	// writeRekey also when recovered from .prev: .prev holds the old DEK.
	werr := v.commitWith(nf, newDEK.Bytes(), writeRekey)
	if werr != nil && !errors.Is(werr, errPrevNotScrubbed) {
		return werr
	}
	old := v.dek
	v.dek = newDEK
	installed = true
	old.Destroy()
	return werr
}

// AddSlot adds a passphrase, hello or dpapi slot. The vault must be
// unlocked; the caller is responsible for the step-up check (spec §5.2).
// Argon2id and the Hello test unwrap (one prompt) run before the vault lock
// is taken. Adding a slot does not re-key.
func (v *Vault) AddSlot(spec SlotSpec) (SlotInfo, error) {
	if err := checkSpec(spec); err != nil {
		return SlotInfo{}, err
	}
	if !v.IsUnlocked() {
		return SlotInfo{}, ErrLocked
	}
	p, err := prepareSlot(spec)
	if err != nil {
		return SlotInfo{}, err
	}
	defer p.destroy()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return SlotInfo{}, ErrLocked
	}
	if len(v.f.Slots) >= maxSlots {
		return SlotInfo{}, fmt.Errorf("%w: too many slots", ErrInvalid)
	}
	s, err := p.wrap(v.f.VaultID, v.dek.Bytes())
	if err != nil {
		return SlotInfo{}, err
	}
	nf := v.f.clone()
	nf.Slots = append(nf.Slots, s)
	if err := v.commitLocked(nf); err != nil {
		return SlotInfo{}, err
	}
	return slotInfo(&s), nil
}

// RotateRecovery replaces every recovery slot with a new one, re-keys the
// vault (see rekeyLocked) and returns the new code. Once it returns, the old
// code opens neither the live file nor .prev. If the process dies between
// the main rename and the .prev rename, .prev keeps the old DEK (and opens
// with the old code) until the next unlock, which replaces it with a copy of
// the live state (see TakeStalePrev). Copies of the vault file taken
// before the rotation (backups) still open with the old code and reveal the
// entries as they were then, but never the new DEK. ErrPrevNotScrubbed
// comes with the new code: the rotation is committed but a stale .prev
// remains.
func (v *Vault) RotateRecovery() (string, error) {
	if !v.IsUnlocked() {
		return "", ErrLocked
	}
	p, code, err := prepareRecovery()
	if err != nil {
		return "", err
	}
	defer p.destroy()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return "", ErrLocked
	}
	nf := v.f.clone()
	kept := nf.Slots[:0]
	for _, s := range nf.Slots {
		if s.Type != SlotRecovery {
			kept = append(kept, s)
		}
	}
	nf.Slots = append(kept, p.s)
	if err := v.rekeyLocked(nf); err != nil {
		if errors.Is(err, errPrevNotScrubbed) {
			return code, err
		}
		return "", err
	}
	return code, nil
}

// RemoveSlot removes a slot and re-keys the vault (see rekeyLocked), so the
// removed slot opens neither the live file nor .prev. Copies taken before
// the removal still open with it and reveal the entries as they were then,
// but never the new DEK. It returns ErrLastSlot if no non-convenience
// (non-dpapi) slot would remain. ErrPrevNotScrubbed means the removal is
// committed but a stale .prev remains. Re-wrapping a remaining dpapi slot
// needs DPAPI, so on other systems removing a slot from a vault that still
// has one fails with an error wrapping errors.ErrUnsupported.
func (v *Vault) RemoveSlot(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return ErrLocked
	}
	nf := v.f.clone()
	idx, strong := -1, 0
	for i, s := range nf.Slots {
		if s.ID == id {
			idx = i
		} else if s.Type != SlotDPAPI {
			strong++
		}
	}
	if idx < 0 {
		return ErrNotFound
	}
	if strong == 0 {
		return ErrLastSlot
	}
	nf.Slots = append(nf.Slots[:idx], nf.Slots[idx+1:]...)
	return v.rekeyLocked(nf)
}

func checkEntryArgs(provider, kind, label string, secret []byte) error {
	if !validProvider(provider) {
		return fmt.Errorf("%w: provider", ErrInvalid)
	}
	if !validKind(kind) {
		return fmt.Errorf("%w: kind", ErrInvalid)
	}
	if !validLabel(label) {
		return fmt.Errorf("%w: label", ErrInvalid)
	}
	return checkSecret(secret)
}

func checkSecret(secret []byte) error {
	if len(secret) == 0 || len(secret) > MaxSecretSize {
		return fmt.Errorf("%w: secret size", ErrInvalid)
	}
	return nil
}

// sealEntry fills e's fingerprint, nonce and ciphertext for secret.
func sealEntry(dek []byte, vaultID string, e *entryV1, secret []byte) error {
	fp, err := fingerprint(dek, secret)
	if err != nil {
		return err
	}
	key, err := deriveSubkey(dek, infoEntry)
	if err != nil {
		return err
	}
	defer key.Destroy()
	nonce, ct, err := seal(key.Bytes(), secret, entryAAD(vaultID, e.ID, e.Provider, e.Kind))
	if err != nil {
		return err
	}
	e.Fingerprint, e.Nonce, e.Ciphertext = fp, nonce, ct
	return nil
}

// AddEntry seals and stores a new secret. secret is not retained; the
// caller wipes it.
func (v *Vault) AddEntry(provider, kind, label string, secret []byte) (EntryInfo, error) {
	if err := checkEntryArgs(provider, kind, label, secret); err != nil {
		return EntryInfo{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return EntryInfo{}, ErrLocked
	}
	if len(v.f.Entries) >= maxEntries {
		return EntryInfo{}, fmt.Errorf("%w: too many entries", ErrInvalid)
	}
	id, err := randHex(idHexLen / 2)
	if err != nil {
		return EntryInfo{}, err
	}
	now := nowString()
	e := entryV1{ID: entryIDPrefix + id, Provider: provider, Kind: kind, Label: label, Created: now, Rotated: now}
	if err := sealEntry(v.dek.Bytes(), v.f.VaultID, &e, secret); err != nil {
		return EntryInfo{}, err
	}
	nf := v.f.clone()
	nf.Entries = append(nf.Entries, e)
	if err := v.commitLocked(nf); err != nil {
		return EntryInfo{}, err
	}
	return entryInfo(&e), nil
}

// RemoveEntry deletes an entry.
func (v *Vault) RemoveEntry(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return ErrLocked
	}
	nf := v.f.clone()
	for i := range nf.Entries {
		if nf.Entries[i].ID == id {
			nf.Entries = append(nf.Entries[:i], nf.Entries[i+1:]...)
			return v.commitLocked(nf)
		}
	}
	return ErrNotFound
}

// ReplaceEntrySecret re-seals an entry with a new secret (key rotation),
// updating its fingerprint and rotated time.
func (v *Vault) ReplaceEntrySecret(id string, secret []byte) error {
	if err := checkSecret(secret); err != nil {
		return err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return ErrLocked
	}
	nf := v.f.clone()
	for i := range nf.Entries {
		e := &nf.Entries[i]
		if e.ID != id {
			continue
		}
		e.Rotated = nowString()
		if err := sealEntry(v.dek.Bytes(), nf.VaultID, e, secret); err != nil {
			return err
		}
		return v.commitLocked(nf)
	}
	return ErrNotFound
}

// WithSecret decrypts entry id into a locked buffer, calls fn with it, and
// wipes the buffer when fn returns. fn must not retain the slice. The vault
// lock is not held while fn runs, so a concurrent Lock does not wait for fn.
// An authentication failure returns ErrTampered.
func (v *Vault) WithSecret(id string, fn func(secret []byte) error) error {
	if fn == nil {
		return fmt.Errorf("%w: nil func", ErrInvalid)
	}
	buf, err := v.openEntry(id)
	if err != nil {
		return err
	}
	defer buf.Destroy()
	return fn(buf.Bytes())
}

func (v *Vault) openEntry(id string) (*secmem.Buffer, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.dek == nil {
		return nil, ErrLocked
	}
	var e *entryV1
	for i := range v.f.Entries {
		if v.f.Entries[i].ID == id {
			e = &v.f.Entries[i]
			break
		}
	}
	if e == nil {
		return nil, ErrNotFound
	}
	key, err := deriveSubkey(v.dek.Bytes(), infoEntry)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()
	buf, err := openToBuffer(key.Bytes(), e.Nonce, e.Ciphertext, entryAAD(v.f.VaultID, e.ID, e.Provider, e.Kind))
	if errors.Is(err, errAuth) {
		return nil, ErrTampered
	}
	return buf, err
}

// Fingerprint returns the spec §5.3 fingerprint of secret for this vault:
// hex of the first 8 bytes of HMAC-SHA256(header-MAC key, secret).
func (v *Vault) Fingerprint(secret []byte) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.dek == nil {
		return "", ErrLocked
	}
	return fingerprint(v.dek.Bytes(), secret)
}

// DeriveKey returns a 32-byte HKDF-SHA256 subkey of the DEK for another
// component (e.g. InfoAuditAnchor). info must start with "keyleash/v1/",
// have something after the prefix, and must not be one of the vault's own
// infos (entry, header-mac, seq-sidecar, slot-kek*). The caller should
// wipe the result. The result changes when the vault is re-keyed
// (RemoveSlot, RotateRecovery).
func (v *Vault) DeriveKey(info string) ([]byte, error) {
	if !strings.HasPrefix(info, derivePrefix) || len(info) == len(derivePrefix) ||
		info == infoEntry || info == infoHeaderMAC || info == infoSidecar ||
		strings.HasPrefix(info, infoSlotKEK) || !validLabelNoLimit(info) || len(info) > 256 {
		return nil, fmt.Errorf("%w: derive info", ErrInvalid)
	}
	v.mu.RLock()
	defer v.mu.RUnlock()
	if v.dek == nil {
		return nil, ErrLocked
	}
	k, err := deriveSubkey(v.dek.Bytes(), info)
	if err != nil {
		return nil, err
	}
	defer k.Destroy()
	out := make([]byte, k.Len())
	copy(out, k.Bytes())
	return out, nil
}
