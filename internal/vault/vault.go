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
	"crypto/sha256"
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
)

// MinPassphraseLen is the shortest passphrase accepted for a new slot.
const MinPassphraseLen = 8

// minRSABits is the smallest Hello public key accepted.
const minRSABits = 2048

// HelloKey is a Windows Hello (Microsoft Passport KSP) RSA key. It is
// implemented by internal/winhello. Decrypt must perform RSA-OAEP with
// SHA-256 (MGF1-SHA-256, empty label), prompting the user.
type HelloKey interface {
	KeyName() string
	PublicKey() (*rsa.PublicKey, error)
	Decrypt(ctx context.Context, ciphertext []byte, prompt string) ([]byte, error)
}

// SlotSpec describes a slot to create. Type is "passphrase", "hello" or
// "dpapi" (recovery slots are created by Create and RotateRecovery).
// Passphrase is read but not retained or modified; the caller wipes it.
type SlotSpec struct {
	Type       string
	Label      string
	Passphrase []byte
	Hello      HelloKey
}

// SlotInfo is public slot metadata.
type SlotInfo struct {
	ID      string
	Type    string
	Label   string
	Created time.Time
	// HelloKey is the KSP key name for hello slots.
	HelloKey string
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
}

func nowString() string { return time.Now().UTC().Truncate(time.Second).Format(time.RFC3339) }

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func checkPath(path string) (string, error) {
	if path == "" || strings.EqualFold(filepath.Ext(path), ".prev") {
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
	s, err := buildSlot(f.VaultID, dek.Bytes(), first)
	if err != nil {
		return nil, "", err
	}
	rs, code, err := buildRecoverySlot(f.VaultID, dek.Bytes())
	if err != nil {
		return nil, "", err
	}
	f.Slots = []slotV1{s, rs}
	v = &Vault{path: path, f: &fileV1{Seq: 0}, dek: dek}
	if err := v.commitLocked(f); err != nil {
		return nil, "", err
	}
	ok = true
	return v, code, nil
}

// Open reads and structurally validates the vault at path and returns it
// locked. If the main file is missing or corrupt (an interrupted write), the
// .prev copy is used and RecoveredFromPrev reports true; the next write
// replaces the main file.
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

	v.mu.Lock()
	if v.f != f {
		// Only possible when the vault was already unlocked and was written
		// meanwhile; the DEK is the same, but fail closed and re-verify.
		if ok, err := verifyHeaderMAC(dek.Bytes(), v.f); err != nil || !ok {
			v.mu.Unlock()
			dek.Destroy()
			return ErrTampered
		}
	}
	old := v.dek
	v.dek = dek
	v.mu.Unlock()
	old.Destroy()
	return nil
}

// UnlockPassphrase unlocks with a passphrase slot. p is not retained.
func (v *Vault) UnlockPassphrase(p []byte) error {
	if len(p) == 0 {
		return ErrWrongSecret
	}
	return v.unlock(SlotPassphrase, func(s *slotV1) (*secmem.Buffer, error) {
		return argon2KEK(p, s.KDF)
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
		return argon2KEK(secret.Bytes(), s.KDF)
	})
}

// UnlockHello unlocks with the hello slot bound to h.KeyName(), asking h to
// decrypt the slot's wrapped KEK (which prompts the user). Errors from h
// (cancellation, device failure) are returned wrapped; ErrWrongSecret means
// no hello slot for that key opened.
func (v *Vault) UnlockHello(ctx context.Context, h HelloKey, prompt string) error {
	if h == nil {
		return fmt.Errorf("%w: nil hello key", ErrInvalid)
	}
	name := h.KeyName()
	return v.unlock(SlotHello, func(s *slotV1) (*secmem.Buffer, error) {
		if s.HelloKey != name {
			return nil, errSkipSlot
		}
		plain, err := h.Decrypt(ctx, s.KEKBlob, prompt)
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

// buildSlot creates a non-recovery slot wrapping dek.
func buildSlot(vaultID string, dek []byte, spec SlotSpec) (slotV1, error) {
	if err := checkSpec(spec); err != nil {
		return slotV1{}, err
	}
	id, err := randHex(idHexLen / 2)
	if err != nil {
		return slotV1{}, err
	}
	s := slotV1{ID: slotIDPrefix + id, Type: spec.Type, Label: spec.Label, Created: nowString()}
	var kek *secmem.Buffer
	switch spec.Type {
	case SlotPassphrase:
		s.KDF, kek, err = newKDF(spec.Passphrase)
		if err != nil {
			return slotV1{}, err
		}
	case SlotHello:
		pub, err := spec.Hello.PublicKey()
		if err != nil {
			return slotV1{}, fmt.Errorf("vault: hello public key: %w", err)
		}
		if pub == nil || pub.N == nil || pub.N.BitLen() < minRSABits {
			return slotV1{}, fmt.Errorf("%w: hello key must be RSA >= %d bits", ErrInvalid, minRSABits)
		}
		if kek, err = randomKEK(); err != nil {
			return slotV1{}, err
		}
		blob, err := rsa.EncryptOAEP(sha256.New(), randReader(), pub, kek.Bytes(), nil)
		if err != nil {
			kek.Destroy()
			return slotV1{}, fmt.Errorf("vault: hello wrap: %w", err)
		}
		s.HelloKey = spec.Hello.KeyName()
		s.KEKBlob = blob
	case SlotDPAPI:
		if kek, err = randomKEK(); err != nil {
			return slotV1{}, err
		}
		blob, err := dpapiProtect(kek.Bytes(), []byte(vaultID))
		if err != nil {
			kek.Destroy()
			return slotV1{}, fmt.Errorf("vault: dpapi wrap: %w", err)
		}
		s.KEKBlob = blob
	}
	defer kek.Destroy()
	s.Nonce, s.Wrapped, err = seal(kek.Bytes(), dek, slotAAD(vaultID, s.ID, s.Type))
	if err != nil {
		return slotV1{}, err
	}
	return s, nil
}

// buildRecoverySlot creates a recovery slot and returns its code.
func buildRecoverySlot(vaultID string, dek []byte) (slotV1, string, error) {
	secret, err := secmem.New(recoverySecretLen)
	if err != nil {
		return slotV1{}, "", err
	}
	defer secret.Destroy()
	if _, err := readRandInto(secret.Bytes()); err != nil {
		return slotV1{}, "", err
	}
	id, err := randHex(idHexLen / 2)
	if err != nil {
		return slotV1{}, "", err
	}
	s := slotV1{ID: slotIDPrefix + id, Type: SlotRecovery, Label: "recovery code", Created: nowString()}
	var kek *secmem.Buffer
	s.KDF, kek, err = newKDF(secret.Bytes())
	if err != nil {
		return slotV1{}, "", err
	}
	defer kek.Destroy()
	s.Nonce, s.Wrapped, err = seal(kek.Bytes(), dek, slotAAD(vaultID, s.ID, s.Type))
	if err != nil {
		return slotV1{}, "", err
	}
	return s, formatRecoveryCode(secret.Bytes()), nil
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

// commitLocked authenticates nf as the next version and writes it. The
// caller holds v.mu for writing (or exclusively owns v) and v.dek is set.
// On failure the in-memory state is unchanged.
func (v *Vault) commitLocked(nf *fileV1) error {
	nf.Seq = v.f.Seq + 1
	mac, err := headerMAC(v.dek.Bytes(), nf)
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
	if err := writeAtomic(v.path, append(data, '\n'), !v.fromPrev); err != nil {
		return err
	}
	v.f = nf
	v.fromPrev = false
	return nil
}

// AddSlot adds a passphrase, hello or dpapi slot. The vault must be
// unlocked; the caller is responsible for the step-up check (spec §5.2).
func (v *Vault) AddSlot(spec SlotSpec) (SlotInfo, error) {
	if err := checkSpec(spec); err != nil {
		return SlotInfo{}, err
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return SlotInfo{}, ErrLocked
	}
	if len(v.f.Slots) >= maxSlots {
		return SlotInfo{}, fmt.Errorf("%w: too many slots", ErrInvalid)
	}
	// KDF work happens under the write lock; slot changes are rare and
	// interactive, and this keeps the DEK from being wiped mid-wrap.
	s, err := buildSlot(v.f.VaultID, v.dek.Bytes(), spec)
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

// RotateRecovery replaces every recovery slot with a new one and returns the
// new code. The old code stops working once this returns.
func (v *Vault) RotateRecovery() (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return "", ErrLocked
	}
	rs, code, err := buildRecoverySlot(v.f.VaultID, v.dek.Bytes())
	if err != nil {
		return "", err
	}
	nf := v.f.clone()
	kept := nf.Slots[:0]
	for _, s := range nf.Slots {
		if s.Type != SlotRecovery {
			kept = append(kept, s)
		}
	}
	nf.Slots = append(kept, rs)
	if err := v.commitLocked(nf); err != nil {
		return "", err
	}
	return code, nil
}

// RemoveSlot removes a slot. It returns ErrLastSlot if no non-convenience
// (non-dpapi) slot would remain.
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
	return v.commitLocked(nf)
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
// infos (entry, header-mac). The caller should wipe the result.
func (v *Vault) DeriveKey(info string) ([]byte, error) {
	if !strings.HasPrefix(info, derivePrefix) || len(info) == len(derivePrefix) ||
		info == infoEntry || info == infoHeaderMAC || !validLabelNoLimit(info) || len(info) > 256 {
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
