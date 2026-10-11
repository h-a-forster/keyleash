package vault

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"strings"

	"github.com/h-a-forster/keyleash/internal/secmem"
)

// Recovery codes encode 160 bits: a 128-bit random secret followed by a
// 32-bit checksum (first 4 bytes of SHA-256("keyleash/v1/recovery-code\x00" ||
// secret)). The 20 bytes are written in Crockford base32 without padding as
// 32 characters in eight dash-separated groups of four; the last group is
// made only of checksum bits.
//
// Parsing is case-insensitive, ignores spaces and dashes, and accepts the
// Crockford aliases O→0 and I/L→1.
const (
	recoverySecretLen = 16
	recoveryCheckLen  = 4
	recoveryCodeChars = 32
	crockfordAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
)

var crockford = base32.NewEncoding(crockfordAlphabet).WithPadding(base32.NoPadding)

func recoveryChecksum(secret []byte) []byte {
	h := sha256.New()
	h.Write([]byte("keyleash/v1/recovery-code\x00"))
	h.Write(secret)
	return h.Sum(nil)[:recoveryCheckLen]
}

// formatRecoveryCode renders a 16-byte secret as a grouped code.
func formatRecoveryCode(secret []byte) string {
	raw := make([]byte, 0, recoverySecretLen+recoveryCheckLen)
	raw = append(raw, secret...)
	raw = append(raw, recoveryChecksum(secret)...)
	s := crockford.EncodeToString(raw)
	secmem.Wipe(raw)
	var b strings.Builder
	for i := 0; i < len(s); i += 4 {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(s[i : i+4])
	}
	return b.String()
}

// parseRecoveryCode validates a code's alphabet, length and checksum and
// returns the secret in locked memory. It does no KDF work.
func parseRecoveryCode(code string) (*secmem.Buffer, error) {
	norm := make([]byte, 0, recoveryCodeChars)
	for i := 0; i < len(code); i++ {
		c := code[i]
		switch {
		case c == ' ' || c == '-' || c == '\t':
			continue
		case c >= 'a' && c <= 'z':
			c -= 'a' - 'A'
		}
		switch c {
		case 'O':
			c = '0'
		case 'I', 'L':
			c = '1'
		}
		if strings.IndexByte(crockfordAlphabet, c) < 0 || len(norm) == recoveryCodeChars {
			secmem.Wipe(norm)
			return nil, ErrBadRecoveryCode
		}
		norm = append(norm, c)
	}
	defer secmem.Wipe(norm)
	if len(norm) != recoveryCodeChars {
		return nil, ErrBadRecoveryCode
	}
	raw := make([]byte, recoverySecretLen+recoveryCheckLen)
	defer secmem.Wipe(raw)
	n, err := crockford.Decode(raw, norm)
	if err != nil || n != len(raw) {
		return nil, ErrBadRecoveryCode
	}
	secret, check := raw[:recoverySecretLen], raw[recoverySecretLen:]
	if subtle.ConstantTimeCompare(check, recoveryChecksum(secret)) != 1 {
		return nil, ErrBadRecoveryCode
	}
	buf, err := secmem.New(recoverySecretLen)
	if err != nil {
		return nil, err
	}
	copy(buf.Bytes(), secret)
	return buf, nil
}
