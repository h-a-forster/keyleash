package vault

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	"github.com/h-a-forster/keyleash/internal/secmem"
)

// infoSlotKEK is the HKDF info prefix for passphrase/recovery slot KEKs. It is
// applied to an X25519 shared secret, never to the DEK.
const infoSlotKEK = "keyleash/v1/slot-kek"

// parseHelloPub parses a hello slot's stored RSA public key and enforces the
// size policy.
func parseHelloPub(der []byte) (*rsa.PublicKey, error) {
	if len(der) == 0 || len(der) > 4096 {
		return nil, errors.New("bad length")
	}
	pub, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return nil, err
	}
	if b := pub.N.BitLen(); b < minRSABits || b > maxRSABits {
		return nil, errors.New("bad key size")
	}
	return pub, nil
}

// x25519KEK derives a slot KEK from X25519(scalar, peer), bound to both
// public values: HKDF-SHA256(shared, info = infoSlotKEK || 0 || epk || pub).
func x25519KEK(scalar, peer, epk, pub []byte) (*secmem.Buffer, error) {
	if len(scalar) != x25519Size || len(peer) != x25519Size || len(epk) != x25519Size || len(pub) != x25519Size {
		return nil, errAuth
	}
	shared, err := curve25519.X25519(scalar, peer)
	if err != nil {
		// Low-order point: only possible with a crafted file.
		return nil, errAuth
	}
	defer secmem.Wipe(shared)
	info := make([]byte, 0, len(infoSlotKEK)+1+2*x25519Size)
	info = append(info, infoSlotKEK...)
	info = append(info, 0)
	info = append(info, epk...)
	info = append(info, pub...)
	buf, err := secmem.New(32)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, nil, info), buf.Bytes()); err != nil {
		buf.Destroy()
		return nil, fmt.Errorf("vault: hkdf: %w", err)
	}
	return buf, nil
}

// x25519Public returns the public key of an X25519 scalar.
func x25519Public(scalar []byte) ([]byte, error) {
	pub, err := curve25519.X25519(scalar, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("vault: x25519: %w", err)
	}
	return pub, nil
}

// passphraseKEK recomputes the KEK of a passphrase/recovery slot from the
// user secret: scalar = Argon2id(secret, s.KDF), then X25519 with the stored
// ephemeral public key.
func passphraseKEK(secret []byte, s *slotV1) (*secmem.Buffer, error) {
	scalar, err := argon2KEK(secret, s.KDF)
	if err != nil {
		return nil, err
	}
	defer scalar.Destroy()
	k, err := x25519KEK(scalar.Bytes(), s.KEKBlob, s.KEKBlob, s.Pub)
	if errors.Is(err, errAuth) {
		return nil, errSkipSlot
	}
	return k, err
}

// rsaWrap encrypts kek to pub with the given hello padding.
func rsaWrap(pub *rsa.PublicKey, padding string, kek []byte) ([]byte, error) {
	switch padding {
	case PaddingOAEPSHA256:
		return rsa.EncryptOAEP(sha256.New(), randReader(), pub, kek, nil)
	case PaddingPKCS1v15:
		return rsa.EncryptPKCS1v15(randReader(), pub, kek) //nolint:staticcheck // spec §5.2 fallback
	default:
		return nil, fmt.Errorf("%w: hello padding", ErrInvalid)
	}
}

// wrapSlot (re)wraps dek into s with fresh per-wrap key material, using only
// the public material stored in s. It needs no user secret and never prompts,
// so it can run during a re-key. It overwrites s.KEKBlob, s.Nonce, s.Wrapped.
func wrapSlot(vaultID string, s *slotV1, dek []byte) error {
	var kek *secmem.Buffer
	var blob []byte
	var err error
	switch s.Type {
	case SlotPassphrase, SlotRecovery:
		eph, err := randomKEK()
		if err != nil {
			return err
		}
		defer eph.Destroy()
		if blob, err = x25519Public(eph.Bytes()); err != nil {
			return err
		}
		if kek, err = x25519KEK(eph.Bytes(), s.Pub, blob, s.Pub); err != nil {
			return fmt.Errorf("vault: wrap %s slot: %w", s.Type, err)
		}
	case SlotHello:
		pub, err := parseHelloPub(s.Pub)
		if err != nil {
			return fmt.Errorf("%w: hello public key", ErrInvalid)
		}
		if kek, err = randomKEK(); err != nil {
			return err
		}
		if blob, err = rsaWrap(pub, s.Padding, kek.Bytes()); err != nil {
			kek.Destroy()
			return fmt.Errorf("vault: hello wrap: %w", err)
		}
	case SlotDPAPI:
		if kek, err = randomKEK(); err != nil {
			return err
		}
		if blob, err = dpapiProtect(kek.Bytes(), []byte(vaultID)); err != nil {
			kek.Destroy()
			return fmt.Errorf("vault: dpapi wrap: %w", err)
		}
	default:
		return fmt.Errorf("%w: slot type", ErrInvalid)
	}
	defer kek.Destroy()
	return sealSlot(vaultID, s, kek.Bytes(), blob, dek)
}

func sealSlot(vaultID string, s *slotV1, kek, blob, dek []byte) error {
	nonce, wrapped, err := seal(kek, dek, slotAAD(vaultID, s.ID, s.Type))
	if err != nil {
		return err
	}
	s.KEKBlob, s.Nonce, s.Wrapped = blob, nonce, wrapped
	return nil
}

// slotPrep is a slot whose secret-dependent and interactive work is done:
// Argon2id for passphrase/recovery, the test unwrap for hello. It can wrap a
// DEK without the user secret. Callers prepare outside the vault lock and
// must call destroy.
type slotPrep struct {
	s slotV1
	// helloKEK/helloBlob are the KEK and blob the hello key was tested
	// with; the first wrap reuses them so the stored blob is the tested one.
	helloKEK  *secmem.Buffer
	helloBlob []byte
}

func (p *slotPrep) destroy() {
	if p != nil {
		p.helloKEK.Destroy()
		p.helloKEK = nil
	}
}

// wrap returns the finished slot wrapping dek.
func (p *slotPrep) wrap(vaultID string, dek []byte) (slotV1, error) {
	s := p.s
	if p.helloKEK != nil {
		if err := sealSlot(vaultID, &s, p.helloKEK.Bytes(), p.helloBlob, dek); err != nil {
			return slotV1{}, err
		}
		return s, nil
	}
	if err := wrapSlot(vaultID, &s, dek); err != nil {
		return slotV1{}, err
	}
	return s, nil
}

func newSlotID() (string, error) {
	id, err := randHex(idHexLen / 2)
	if err != nil {
		return "", err
	}
	return slotIDPrefix + id, nil
}

// prepareSlot prepares a passphrase, hello or dpapi slot. For hello it
// performs a test unwrap, which prompts the user once (twice if the KSP
// rejects OAEP and the PKCS#1 v1.5 fallback is tried).
func prepareSlot(spec SlotSpec) (*slotPrep, error) {
	if err := checkSpec(spec); err != nil {
		return nil, err
	}
	id, err := newSlotID()
	if err != nil {
		return nil, err
	}
	p := &slotPrep{s: slotV1{ID: id, Type: spec.Type, Label: spec.Label, Created: nowString()}}
	switch spec.Type {
	case SlotPassphrase:
		if err := preparePassphrase(&p.s, spec.Passphrase); err != nil {
			return nil, err
		}
	case SlotHello:
		if err := prepareHello(p, spec); err != nil {
			return nil, err
		}
	case SlotDPAPI:
		// Nothing secret-dependent; wrapping happens with the DEK.
	}
	return p, nil
}

// preparePassphrase picks KDF parameters and stores the X25519 public key
// of Argon2id(secret).
func preparePassphrase(s *slotV1, secret []byte) error {
	k, scalar, err := newKDF(secret)
	if err != nil {
		return err
	}
	defer scalar.Destroy()
	pub, err := x25519Public(scalar.Bytes())
	if err != nil {
		return err
	}
	s.KDF, s.Pub = k, pub
	return nil
}

// prepareRecovery prepares a recovery slot and returns its code.
func prepareRecovery() (*slotPrep, string, error) {
	secret, err := secmem.New(recoverySecretLen)
	if err != nil {
		return nil, "", err
	}
	defer secret.Destroy()
	if _, err := readRandInto(secret.Bytes()); err != nil {
		return nil, "", err
	}
	id, err := newSlotID()
	if err != nil {
		return nil, "", err
	}
	p := &slotPrep{s: slotV1{ID: id, Type: SlotRecovery, Label: "recovery code", Created: nowString()}}
	if err := preparePassphrase(&p.s, secret.Bytes()); err != nil {
		return nil, "", err
	}
	return p, formatRecoveryCode(secret.Bytes()), nil
}

// prepareHello wraps a random KEK to the hello key and immediately unwraps
// it through the key (spec §5.2). RSA-OAEP-SHA256 is tried first; if the key
// reports ErrOAEPUnsupported and implements HelloKeyPKCS1, PKCS#1 v1.5 is
// used instead. Any other failure, or a wrong round trip, fails the slot.
func prepareHello(p *slotPrep, spec SlotSpec) error {
	h := spec.Hello
	pub, err := h.PublicKey()
	if err != nil {
		return fmt.Errorf("vault: hello public key: %w", err)
	}
	if pub == nil || pub.N == nil || pub.N.BitLen() < minRSABits || pub.N.BitLen() > maxRSABits {
		return fmt.Errorf("%w: hello key must be RSA %d..%d bits", ErrInvalid, minRSABits, maxRSABits)
	}
	ctx := spec.Context
	if ctx == nil {
		ctx = context.Background()
	}
	kek, err := randomKEK()
	if err != nil {
		return err
	}
	padding := PaddingOAEPSHA256
	blob, err := rsaWrap(pub, padding, kek.Bytes())
	if err != nil {
		kek.Destroy()
		return fmt.Errorf("vault: hello wrap: %w", err)
	}
	plain, err := h.Decrypt(ctx, blob, spec.HelloPrompt)
	if err != nil && errors.Is(err, ErrOAEPUnsupported) {
		p1, ok := h.(HelloKeyPKCS1)
		if !ok {
			kek.Destroy()
			return fmt.Errorf("vault: hello test unwrap: %w (no PKCS#1 v1.5 fallback)", err)
		}
		padding = PaddingPKCS1v15
		if blob, err = rsaWrap(pub, padding, kek.Bytes()); err != nil {
			kek.Destroy()
			return fmt.Errorf("vault: hello wrap: %w", err)
		}
		plain, err = p1.DecryptPKCS1v15(ctx, blob, spec.HelloPrompt)
	}
	if err != nil {
		kek.Destroy()
		return fmt.Errorf("vault: hello test unwrap: %w", err)
	}
	match := subtle.ConstantTimeCompare(plain, kek.Bytes()) == 1
	secmem.Wipe(plain)
	if !match {
		kek.Destroy()
		return fmt.Errorf("%w: hello test unwrap returned wrong data", ErrInvalid)
	}
	p.s.HelloKey = h.KeyName()
	p.s.Padding = padding
	p.s.Pub = x509.MarshalPKCS1PublicKey(pub)
	p.helloKEK, p.helloBlob = kek, blob
	return nil
}
