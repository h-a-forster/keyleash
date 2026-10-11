// Package winhello keeps an RSA key in the Microsoft Passport Key Storage
// Provider (Windows Hello / NGC, TPM-backed when a TPM is present) and uses
// it for the vault's hello slot (spec §5.2) and the hello step-up approver
// (spec §9).
//
// Every private-key operation (Decrypt, Confirm) shows a Windows Hello
// prompt: keys are created with the NGC cache type "auth mandatory", and an
// existing key without it is refused. Public-key operations never prompt.
//
// Keys are named "<user SID>//keyleash//<name>", following the Passport
// "<SID>//<domain>/<subdomain>/<key name>" convention with an empty
// sub-domain, so they are scoped to the current Windows user.
//
// On non-Windows platforms Available reports false and every other call
// returns ErrUnavailable.
package winhello

import (
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"unicode"
)

// Sentinel errors. Errors returned by this package wrap one of these where
// applicable (use errors.Is) and never contain key material.
var (
	// ErrUnavailable: Windows Hello / the Passport KSP is not usable here.
	ErrUnavailable = errors.New("winhello: Windows Hello is not available")
	// ErrNotFound: no key with that name exists for this user.
	ErrNotFound = errors.New("winhello: key not found")
	// ErrCancelled: the user dismissed or failed the Windows Hello prompt.
	ErrCancelled = errors.New("winhello: cancelled by user")
	// ErrOAEPUnsupported: the KSP rejected RSA-OAEP-SHA256 decryption. The
	// vault must then use the PKCS#1 v1.5 fallback (DecryptPKCS1v15).
	ErrOAEPUnsupported = errors.New("winhello: KSP does not support RSA-OAEP-SHA256")
	// ErrUnsupported: the KSP does not support a requested operation.
	ErrUnsupported = errors.New("winhello: operation not supported by KSP")
	// ErrWeakKey: an existing key is not an RSA key of at least MinKeyBits,
	// or was not created with mandatory per-use authentication.
	ErrWeakKey = errors.New("winhello: existing key does not meet policy")
	// ErrInvalidName: the key name is empty, too long or has bad characters.
	ErrInvalidName = errors.New("winhello: invalid key name")
)

// MinKeyBits is the minimum accepted RSA modulus size; new keys use it.
const MinKeyBits = 2048

// maxNameLen bounds the caller-chosen part of the key name.
const maxNameLen = 64

// maxPromptRunes bounds the text shown in the Windows Hello dialog.
const maxPromptRunes = 200

// keyDomain is the Passport "domain" component of every key name.
const keyDomain = "keyleash"

// validateName accepts [A-Za-z0-9._-]{1,64}.
func validateName(name string) error {
	if name == "" || len(name) > maxNameLen {
		return ErrInvalidName
	}
	for _, r := range name {
		ok := r == '.' || r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return ErrInvalidName
		}
	}
	if name == "." || name == ".." {
		return ErrInvalidName
	}
	return nil
}

// fullKeyName builds the Passport key name for a user SID.
func fullKeyName(sid, name string) string {
	return sid + "//" + keyDomain + "//" + name
}

// sanitizePrompt makes caller text safe to show in the system dialog:
// control characters become spaces, whitespace is collapsed and the length
// is bounded. Callers must never put secrets in a prompt.
func sanitizePrompt(s string) string {
	var b strings.Builder
	n := 0
	space := false
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			if !space && b.Len() > 0 {
				b.WriteByte(' ')
				space = true
			}
			continue
		}
		if !unicode.IsPrint(r) {
			continue
		}
		if n >= maxPromptRunes {
			b.WriteString("…")
			break
		}
		b.WriteRune(r)
		space = false
		n++
	}
	out := strings.TrimSpace(b.String())
	if out == "" {
		out = "keyleash needs to confirm it's you"
	}
	return out
}

// BCRYPT_RSAKEY_BLOB header layout (bcrypt.h): six little-endian ULONGs
// Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2, followed for
// a public blob by the big-endian exponent and modulus.
const (
	rsaBlobHeaderSize = 24
	rsaPublicMagic    = 0x31415352 // BCRYPT_RSAPUBLIC_MAGIC, "RSA1"
)

// parseRSAPublicBlob decodes a BCRYPT_RSAPUBLIC_BLOB.
func parseRSAPublicBlob(b []byte) (*rsa.PublicKey, error) {
	if len(b) < rsaBlobHeaderSize {
		return nil, errors.New("winhello: short RSA public blob")
	}
	le := binary.LittleEndian
	magic := le.Uint32(b[0:])
	bitLen := le.Uint32(b[4:])
	cbExp := le.Uint32(b[8:])
	cbMod := le.Uint32(b[12:])
	if magic != rsaPublicMagic {
		return nil, fmt.Errorf("winhello: RSA blob magic %#x is not RSA1", magic)
	}
	if cbExp == 0 || cbExp > 8 || cbMod == 0 || cbMod > 2048 {
		return nil, errors.New("winhello: RSA blob sizes out of range")
	}
	if uint64(len(b)) != uint64(rsaBlobHeaderSize)+uint64(cbExp)+uint64(cbMod) {
		return nil, errors.New("winhello: RSA blob length mismatch")
	}
	expBytes := b[rsaBlobHeaderSize : rsaBlobHeaderSize+cbExp]
	modBytes := b[rsaBlobHeaderSize+cbExp:]
	var e uint64
	for _, x := range expBytes {
		e = e<<8 | uint64(x)
	}
	if e < 3 || e%2 == 0 || e > 1<<31-1 {
		return nil, errors.New("winhello: RSA exponent out of range")
	}
	n := new(big.Int).SetBytes(modBytes)
	if n.Sign() <= 0 || n.Bit(0) == 0 {
		return nil, errors.New("winhello: RSA modulus invalid")
	}
	if uint32(n.BitLen()) != bitLen {
		return nil, fmt.Errorf("winhello: RSA blob bit length %d does not match modulus (%d)", bitLen, n.BitLen())
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

// Key is a handle to a persisted Passport KSP key. It holds no OS handles
// and no secret material (only the name and cached public key), so it is
// safe to copy and to use from several goroutines; each operation opens and
// closes its own KSP handles.
type Key struct {
	name    string // caller-chosen short name
	keyName string // full Passport key name
	pub     *rsa.PublicKey
}

// KeyName returns the full Passport key name ("<SID>//keyleash//<name>").
// It identifies the key but is not secret.
func (k *Key) KeyName() string { return k.keyName }

// PublicKey returns a copy of the key's RSA public key. It never prompts.
func (k *Key) PublicKey() (*rsa.PublicKey, error) {
	if k == nil || k.pub == nil {
		return nil, errors.New("winhello: nil key")
	}
	return &rsa.PublicKey{N: new(big.Int).Set(k.pub.N), E: k.pub.E}, nil
}

// String identifies the key for logs.
func (k *Key) String() string {
	if k == nil {
		return "winhello.Key(nil)"
	}
	return "winhello.Key(" + k.name + ")"
}
