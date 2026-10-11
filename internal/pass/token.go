package pass

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// Token layout (spec §6):
//
//	klp_<id>_<secret>
//
// id is IDLen characters of lowercase Crockford base32; secret is the
// unpadded base64url encoding of SecretBytes random bytes (SecretLen chars).
const (
	Prefix      = "klp_"
	IDLen       = 10
	SecretBytes = 32
	SecretLen   = 43
	TokenLen    = len(Prefix) + IDLen + 1 + SecretLen
)

// crockford is the lowercase Crockford base32 alphabet (no i, l, o, u).
const crockford = "0123456789abcdefghjkmnpqrstvwxyz"

func isIDChar(c byte) bool {
	return strings.IndexByte(crockford, c) >= 0
}

// validID reports whether id is a syntactically valid pass id.
func validID(id string) bool {
	if len(id) != IDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if !isIDChar(id[i]) {
			return false
		}
	}
	return true
}

// newID returns a random pass id (50 bits of entropy).
func newID() (string, error) {
	var b [IDLen]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("pass: random id: %w", err)
	}
	out := make([]byte, IDLen)
	for i := range b {
		out[i] = crockford[b[i]&31] // 256 is a multiple of 32: no modulo bias
	}
	return string(out), nil
}

// newSecret returns SecretBytes random bytes.
func newSecret() ([]byte, error) {
	s := make([]byte, SecretBytes)
	if _, err := rand.Read(s); err != nil {
		return nil, fmt.Errorf("pass: random secret: %w", err)
	}
	return s, nil
}

func formatToken(id string, secret []byte) string {
	return Prefix + id + "_" + base64.RawURLEncoding.EncodeToString(secret)
}

// parse splits a token into id and decoded secret. It is purely syntactic and
// rejects non-canonical base64 (stray trailing bits) so every secret has
// exactly one textual form.
func parse(token string) (id string, secret []byte, ok bool) {
	if len(token) != TokenLen || !strings.HasPrefix(token, Prefix) {
		return "", nil, false
	}
	id = token[len(Prefix) : len(Prefix)+IDLen]
	if !validID(id) || token[len(Prefix)+IDLen] != '_' {
		return "", nil, false
	}
	enc := token[len(Prefix)+IDLen+1:]
	secret, err := base64.RawURLEncoding.Strict().DecodeString(enc)
	if err != nil || len(secret) != SecretBytes {
		return "", nil, false
	}
	return id, secret, true
}

// Parse extracts the pass id from token. It checks syntax only and says
// nothing about whether the pass exists or the secret is right.
func Parse(token string) (id string, ok bool) {
	id, secret, ok := parse(token)
	wipe(secret)
	return id, ok
}

// LooksLikePass reports whether s is a syntactically valid pass token. Secret
// scanners and the proxy use it to recognise passes.
func LooksLikePass(s string) bool {
	_, ok := Parse(s)
	return ok
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
