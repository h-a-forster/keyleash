package vault

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20poly1305"
)

// On-disk format constants (spec §5.4).
const (
	formatName    = "keyleash-vault"
	formatVersion = 1

	// maxFileSize bounds how much Open will read.
	maxFileSize = 16 << 20
	maxSlots    = 64
	maxEntries  = 4096
	// MaxSecretSize is the largest secret AddEntry accepts.
	MaxSecretSize = 64 << 10
	maxLabelLen   = 128 // bytes
	maxKeyNameLen = 256 // bytes, hello key names

	dekSize  = 32
	saltSize = 16
	macSize  = 32
	tagSize  = chacha20poly1305.Overhead
	nonceLen = chacha20poly1305.NonceSizeX

	// KDF parameter bounds accepted from disk. They are wide on purpose so
	// `rekey` can raise parameters, but stop a crafted file from asking for
	// absurd memory or time during unlock.
	maxKDFMemoryKiB = 4 << 20 // 4 GiB
	maxKDFTime      = 64
)

// Slot types.
const (
	SlotPassphrase = "passphrase"
	SlotRecovery   = "recovery"
	SlotHello      = "hello"
	SlotDPAPI      = "dpapi"
)

// Entry kinds.
const (
	KindAPIKey   = "api_key"
	KindAdminKey = "admin_key"
)

// b64 is a byte slice encoded in JSON as unpadded base64url (spec §5.4).
type b64 []byte

// MarshalJSON implements json.Marshaler.
func (b b64) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON implements json.Unmarshaler. It rejects padding and the
// standard alphabet so each value has exactly one encoding.
func (b *b64) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	out, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return errors.New("invalid base64url")
	}
	*b = out
	return nil
}

// fileV1 is the vault file. Values of this type are treated as immutable
// once installed in a Vault: mutations clone, change and replace.
type fileV1 struct {
	Format  string    `json:"format"`
	Version int       `json:"version"`
	VaultID string    `json:"vault_id"`
	Seq     uint64    `json:"seq"`
	Created string    `json:"created"`
	Slots   []slotV1  `json:"slots"`
	Entries []entryV1 `json:"entries"`
	MAC     b64       `json:"mac"`
}

// kdfV1 holds per-slot Argon2id parameters (spec §5.2).
type kdfV1 struct {
	Alg       string `json:"alg"`
	Salt      b64    `json:"salt"`
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m_kib"`
	Threads   uint8  `json:"p"`
}

// slotV1 is one key slot. Every slot type seals the DEK with
// XChaCha20-Poly1305 under a slot KEK and the slot AAD; the types differ in
// how the KEK is obtained:
//   - passphrase, recovery: KEK = Argon2id(secret, KDF.Salt, ...)
//   - hello: KEK is random; KEKBlob = RSA-OAEP-SHA256(hello public key, KEK)
//   - dpapi: KEK is random; KEKBlob = CryptProtectData(KEK, entropy=vault_id)
type slotV1 struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Label    string `json:"label"`
	Created  string `json:"created"`
	KDF      *kdfV1 `json:"kdf,omitempty"`
	HelloKey string `json:"hello_key,omitempty"`
	KEKBlob  b64    `json:"kek_blob,omitempty"`
	Nonce    b64    `json:"nonce"`
	Wrapped  b64    `json:"wrapped"`
}

// entryV1 is one sealed secret (spec §5.3).
type entryV1 struct {
	ID          string `json:"id"`
	Provider    string `json:"provider"`
	Kind        string `json:"kind"`
	Label       string `json:"label"`
	Created     string `json:"created"`
	Rotated     string `json:"rotated"`
	Fingerprint string `json:"fingerprint"`
	Nonce       b64    `json:"nonce"`
	Ciphertext  b64    `json:"ciphertext"`
}

// clone returns a deep copy of f suitable for mutation.
func (f *fileV1) clone() *fileV1 {
	nf := *f
	nf.Slots = make([]slotV1, len(f.Slots))
	for i, s := range f.Slots {
		ns := s
		if s.KDF != nil {
			k := *s.KDF
			k.Salt = bytes.Clone(s.KDF.Salt)
			ns.KDF = &k
		}
		ns.KEKBlob = bytes.Clone(s.KEKBlob)
		ns.Nonce = bytes.Clone(s.Nonce)
		ns.Wrapped = bytes.Clone(s.Wrapped)
		nf.Slots[i] = ns
	}
	nf.Entries = make([]entryV1, len(f.Entries))
	for i, e := range f.Entries {
		ne := e
		ne.Nonce = bytes.Clone(e.Nonce)
		ne.Ciphertext = bytes.Clone(e.Ciphertext)
		nf.Entries[i] = ne
	}
	nf.MAC = nil
	return &nf
}

// headerMACInput returns the canonical encoding authenticated by the header
// MAC (spec §5.1). It covers every field of the file except "mac" itself.
//
// Encoding (all integers big-endian; str/bytes = uint32 length || data):
//
//	str("keyleash/v1/header\x00")
//	str(format) u32(version) str(vault_id) u64(seq) str(created)
//	u32(len(slots)), then per slot in file order:
//	  str(id) str(type) str(label) str(created)
//	  u8(0) if no kdf, else u8(1) str(alg) bytes(salt) u32(t) u32(m_kib) u32(p)
//	  str(hello_key) bytes(kek_blob) bytes(nonce) bytes(wrapped)
//	u32(len(entries)), then per entry in file order:
//	  str(id) str(provider) str(kind) str(label) str(created) str(rotated)
//	  str(fingerprint) bytes(nonce) bytes(ciphertext)
//
// Slices are encoded in their stored order, so reordering slots or entries
// changes the MAC. No maps are involved, so the encoding is deterministic.
func headerMACInput(f *fileV1) []byte {
	var w canonWriter
	w.str("keyleash/v1/header\x00")
	w.str(f.Format)
	w.u32(uint32(f.Version))
	w.str(f.VaultID)
	w.u64(f.Seq)
	w.str(f.Created)
	w.u32(uint32(len(f.Slots)))
	for _, s := range f.Slots {
		w.str(s.ID)
		w.str(s.Type)
		w.str(s.Label)
		w.str(s.Created)
		if s.KDF == nil {
			w.u8(0)
		} else {
			w.u8(1)
			w.str(s.KDF.Alg)
			w.bytes(s.KDF.Salt)
			w.u32(s.KDF.Time)
			w.u32(s.KDF.MemoryKiB)
			w.u32(uint32(s.KDF.Threads))
		}
		w.str(s.HelloKey)
		w.bytes(s.KEKBlob)
		w.bytes(s.Nonce)
		w.bytes(s.Wrapped)
	}
	w.u32(uint32(len(f.Entries)))
	for _, e := range f.Entries {
		w.str(e.ID)
		w.str(e.Provider)
		w.str(e.Kind)
		w.str(e.Label)
		w.str(e.Created)
		w.str(e.Rotated)
		w.str(e.Fingerprint)
		w.bytes(e.Nonce)
		w.bytes(e.Ciphertext)
	}
	return w.buf.Bytes()
}

type canonWriter struct{ buf bytes.Buffer }

func (w *canonWriter) u8(v uint8)   { w.buf.WriteByte(v) }
func (w *canonWriter) u32(v uint32) { w.buf.Write(binary.BigEndian.AppendUint32(nil, v)) }
func (w *canonWriter) u64(v uint64) { w.buf.Write(binary.BigEndian.AppendUint64(nil, v)) }
func (w *canonWriter) bytes(b []byte) {
	w.u32(uint32(len(b)))
	w.buf.Write(b)
}
func (w *canonWriter) str(s string) {
	w.u32(uint32(len(s)))
	w.buf.WriteString(s)
}

// decodeFile parses and structurally validates a vault file.
func decodeFile(data []byte) (*fileV1, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f fileV1
	if err := dec.Decode(&f); err != nil {
		// The decoder's message is not propagated: it can quote input.
		return nil, corrupt("malformed JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, corrupt("trailing data")
	}
	if err := validateFile(&f); err != nil {
		return nil, err
	}
	return &f, nil
}

// corrupt builds an ErrCorrupt error. Details never include field values,
// which could be secret-bearing.
func corrupt(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
}

// validateFile performs structural validation. It authenticates nothing;
// the header MAC is checked on unlock.
func validateFile(f *fileV1) error {
	if f.Format != formatName {
		return corrupt("unknown format")
	}
	if f.Version != formatVersion {
		return corrupt("unsupported version %d", f.Version)
	}
	if !validVaultID(f.VaultID) {
		return corrupt("bad vault_id")
	}
	if f.Seq == 0 {
		return corrupt("bad seq")
	}
	if !validTime(f.Created) {
		return corrupt("bad created time")
	}
	if len(f.Slots) == 0 || len(f.Slots) > maxSlots {
		return corrupt("bad slot count")
	}
	if len(f.Entries) > maxEntries {
		return corrupt("too many entries")
	}
	if len(f.MAC) != macSize {
		return corrupt("bad mac")
	}
	seen := make(map[string]bool, len(f.Slots)+len(f.Entries))
	strong := 0
	for i := range f.Slots {
		s := &f.Slots[i]
		if err := validateSlot(s); err != nil {
			return fmt.Errorf("%w (slot %d)", err, i)
		}
		if seen[s.ID] {
			return corrupt("duplicate slot id")
		}
		seen[s.ID] = true
		if s.Type != SlotDPAPI {
			strong++
		}
	}
	if strong == 0 {
		return corrupt("no non-convenience slot")
	}
	for i := range f.Entries {
		e := &f.Entries[i]
		if err := validateEntry(e); err != nil {
			return fmt.Errorf("%w (entry %d)", err, i)
		}
		if seen[e.ID] {
			return corrupt("duplicate entry id")
		}
		seen[e.ID] = true
	}
	return nil
}

func validateSlot(s *slotV1) error {
	if !validPrefixedID(s.ID, slotIDPrefix) {
		return corrupt("bad slot id")
	}
	if !validLabel(s.Label) {
		return corrupt("bad slot label")
	}
	if !validTime(s.Created) {
		return corrupt("bad slot created time")
	}
	if len(s.Nonce) != nonceLen || len(s.Wrapped) != dekSize+tagSize {
		return corrupt("bad wrapped key")
	}
	switch s.Type {
	case SlotPassphrase, SlotRecovery:
		if s.KDF == nil || s.HelloKey != "" || len(s.KEKBlob) != 0 {
			return corrupt("bad %s slot fields", s.Type)
		}
		if err := validateKDF(s.KDF); err != nil {
			return err
		}
	case SlotHello:
		if s.KDF != nil || len(s.KEKBlob) == 0 || len(s.KEKBlob) > 2048 {
			return corrupt("bad hello slot fields")
		}
		if !validKeyName(s.HelloKey) {
			return corrupt("bad hello key name")
		}
	case SlotDPAPI:
		if s.KDF != nil || s.HelloKey != "" || len(s.KEKBlob) == 0 || len(s.KEKBlob) > 4096 {
			return corrupt("bad dpapi slot fields")
		}
	default:
		return corrupt("unknown slot type")
	}
	return nil
}

func validateKDF(k *kdfV1) error {
	if k.Alg != "argon2id" {
		return corrupt("unknown kdf")
	}
	if len(k.Salt) < saltSize || len(k.Salt) > 64 {
		return corrupt("bad kdf salt")
	}
	if k.Threads == 0 || k.Time == 0 || k.Time > maxKDFTime {
		return corrupt("bad kdf cost")
	}
	if k.MemoryKiB < 8*uint32(k.Threads) || k.MemoryKiB > maxKDFMemoryKiB {
		return corrupt("bad kdf memory")
	}
	return nil
}

func validateEntry(e *entryV1) error {
	if !validPrefixedID(e.ID, entryIDPrefix) {
		return corrupt("bad entry id")
	}
	if !validProvider(e.Provider) || !validKind(e.Kind) || !validLabel(e.Label) {
		return corrupt("bad entry metadata")
	}
	if !validTime(e.Created) || !validTime(e.Rotated) {
		return corrupt("bad entry time")
	}
	if !validFingerprint(e.Fingerprint) {
		return corrupt("bad fingerprint")
	}
	if len(e.Nonce) != nonceLen || len(e.Ciphertext) <= tagSize || len(e.Ciphertext) > MaxSecretSize+tagSize {
		return corrupt("bad entry ciphertext")
	}
	return nil
}

const (
	slotIDPrefix  = "slot_"
	entryIDPrefix = "ent_"
	idHexLen      = 16
)

func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validVaultID(s string) bool { return len(s) == 32 && isLowerHex(s) }

func validPrefixedID(s, prefix string) bool {
	rest, ok := strings.CutPrefix(s, prefix)
	return ok && len(rest) == idHexLen && isLowerHex(rest)
}

func validFingerprint(s string) bool { return len(s) == 16 && isLowerHex(s) }

func validTime(s string) bool {
	t, err := time.Parse(time.RFC3339, s)
	return err == nil && t.Format(time.RFC3339) == s
}

// validLabel accepts short, printable UTF-8 (empty is allowed).
func validLabel(s string) bool {
	if len(s) > maxLabelLen || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validKeyName(s string) bool {
	return s != "" && len(s) <= maxKeyNameLen && validLabelNoLimit(s)
}

func validLabelNoLimit(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// validProvider accepts registry-style names: [a-z0-9][a-z0-9._-]{0,63}.
func validProvider(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case (c == '.' || c == '_' || c == '-') && i > 0:
		default:
			return false
		}
	}
	return true
}

func validKind(s string) bool { return s == KindAPIKey || s == KindAdminKey }
