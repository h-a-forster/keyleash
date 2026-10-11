package vault

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/h-a-forster/keyleash/internal/secmem"
)

// HKDF info strings (spec §5.1).
const (
	infoEntry       = "keyleash/v1/entry"
	infoHeaderMAC   = "keyleash/v1/header-mac"
	InfoAuditAnchor = "keyleash/v1/audit-anchor"
	derivePrefix    = "keyleash/v1/"
)

// kdfParams are Argon2id costs for new passphrase and recovery slots.
type kdfParams struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
}

// Production Argon2id defaults (spec §5.2). Tests replace kdfDefaults and
// kdfTarget in TestMain; nothing in non-test code changes them.
var (
	kdfDefaults = kdfParams{Time: 3, MemoryKiB: 256 * 1024, Threads: 4}
	// kdfTarget is the minimum creation-time cost; when the defaults run
	// faster on this machine, Time is raised (spec: "tuned to >= 0.5 s").
	kdfTarget = 500 * time.Millisecond
	// kdfMaxTunedTime caps the tuned iteration count.
	kdfMaxTunedTime uint32 = 16
)

// randBytes returns n bytes from crypto/rand.
func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("vault: random: %w", err)
	}
	return b, nil
}

func randHex(n int) (string, error) {
	b, err := randBytes(n)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// deriveSubkey derives a 32-byte HKDF-SHA256 subkey of the DEK into locked
// memory. The caller must Destroy it.
func deriveSubkey(dek []byte, info string) (*secmem.Buffer, error) {
	buf, err := secmem.New(32)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdf.New(sha256.New, dek, nil, []byte(info)), buf.Bytes()); err != nil {
		buf.Destroy()
		return nil, fmt.Errorf("vault: hkdf: %w", err)
	}
	return buf, nil
}

// entryAAD is "keyleash/v1/entry\x00" || vault_id || entry_id || provider || kind.
// The concatenation is unambiguous because vault and entry ids are fixed
// length and kind is one of a fixed set no member of which is a suffix of
// another (spec §5.1).
func entryAAD(vaultID, entryID, provider, kind string) []byte {
	return []byte("keyleash/v1/entry\x00" + vaultID + entryID + provider + kind)
}

// slotAAD is "keyleash/v1/slot\x00" || vault_id || slot_id || slot_type.
func slotAAD(vaultID, slotID, slotType string) []byte {
	return []byte("keyleash/v1/slot\x00" + vaultID + slotID + slotType)
}

// seal encrypts plaintext with XChaCha20-Poly1305 under key and a fresh
// random nonce.
func seal(key, plaintext, aad []byte) (nonce, ct []byte, err error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: aead: %w", err)
	}
	nonce, err = randBytes(nonceLen)
	if err != nil {
		return nil, nil, err
	}
	return nonce, aead.Seal(nil, nonce, plaintext, aad), nil
}

// errAuth reports an AEAD authentication failure.
var errAuth = errors.New("vault: authentication failed")

// openToBuffer decrypts ct into a new secmem buffer. On any failure the
// buffer is destroyed and errAuth is returned.
func openToBuffer(key, nonce, ct, aad []byte) (*secmem.Buffer, error) {
	if len(ct) <= tagSize || len(nonce) != nonceLen {
		return nil, errAuth
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("vault: aead: %w", err)
	}
	buf, err := secmem.New(len(ct) - tagSize)
	if err != nil {
		return nil, err
	}
	// Open writes into buf's memory because its capacity is exactly the
	// plaintext length; on failure it zeroes that memory itself.
	out, err := aead.Open(buf.Bytes()[:0], nonce, ct, aad)
	if err != nil || len(out) != buf.Len() || &out[0] != &buf.Bytes()[0] {
		buf.Destroy()
		return nil, errAuth
	}
	return buf, nil
}

// headerMAC computes HMAC-SHA256 under the header-MAC subkey.
func headerMAC(dek []byte, f *fileV1) ([]byte, error) {
	key, err := deriveSubkey(dek, infoHeaderMAC)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()
	m := hmac.New(sha256.New, key.Bytes())
	m.Write(headerMACInput(f))
	return m.Sum(nil), nil
}

// verifyHeaderMAC reports whether f.MAC is valid under dek.
func verifyHeaderMAC(dek []byte, f *fileV1) (bool, error) {
	want, err := headerMAC(dek, f)
	if err != nil {
		return false, err
	}
	return hmac.Equal(want, f.MAC), nil
}

// fingerprint is hex(HMAC-SHA256(header-MAC key, secret)[:8]) (spec §5.3).
func fingerprint(dek, secret []byte) (string, error) {
	key, err := deriveSubkey(dek, infoHeaderMAC)
	if err != nil {
		return "", err
	}
	defer key.Destroy()
	m := hmac.New(sha256.New, key.Bytes())
	m.Write(secret)
	return hex.EncodeToString(m.Sum(nil)[:8]), nil
}

// argon2KEK derives Argon2id(secret) with the slot's stored parameters: the
// X25519 private scalar of a passphrase or recovery slot (see slotV1).
func argon2KEK(secret []byte, k *kdfV1) (*secmem.Buffer, error) {
	if err := validateKDF(k); err != nil {
		return nil, err
	}
	buf, err := secmem.New(32)
	if err != nil {
		return nil, err
	}
	key := argon2.IDKey(secret, k.Salt, k.Time, k.MemoryKiB, k.Threads, 32)
	copy(buf.Bytes(), key)
	secmem.Wipe(key)
	return buf, nil
}

// newKDF picks parameters for a new slot and derives its Argon2id output. Starting from
// kdfDefaults, it raises Time when one derivation is faster than kdfTarget.
func newKDF(secret []byte) (*kdfV1, *secmem.Buffer, error) {
	salt, err := randBytes(saltSize)
	if err != nil {
		return nil, nil, err
	}
	k := &kdfV1{
		Alg:       "argon2id",
		Salt:      salt,
		Time:      kdfDefaults.Time,
		MemoryKiB: kdfDefaults.MemoryKiB,
		Threads:   kdfDefaults.Threads,
	}
	start := time.Now()
	kek, err := argon2KEK(secret, k)
	if err != nil {
		return nil, nil, err
	}
	elapsed := time.Since(start)
	if kdfTarget <= 0 || elapsed >= kdfTarget || k.Time >= kdfMaxTunedTime {
		return k, kek, nil
	}
	scaled := math.Ceil(float64(k.Time) * float64(kdfTarget) / float64(max(elapsed, time.Millisecond)))
	k.Time = uint32(min(scaled, float64(kdfMaxTunedTime)))
	kek.Destroy()
	kek, err = argon2KEK(secret, k)
	if err != nil {
		return nil, nil, err
	}
	return k, kek, nil
}

// readRandInto fills b from crypto/rand.
func readRandInto(b []byte) (int, error) {
	n, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return n, fmt.Errorf("vault: random: %w", err)
	}
	return n, nil
}

// randReader is the randomness source for RSA-OAEP wrapping.
func randReader() io.Reader { return rand.Reader }
