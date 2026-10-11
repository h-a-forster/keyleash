package winhello

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	good := []string{"vault", "vault-1", "a.b_c", strings.Repeat("x", 64)}
	bad := []string{"", ".", "..", "a/b", `a\b`, "a b", "ключ", "a//b", strings.Repeat("x", 65), "a\x00b"}
	for _, n := range good {
		if err := validateName(n); err != nil {
			t.Errorf("%q rejected: %v", n, err)
		}
	}
	for _, n := range bad {
		if err := validateName(n); !errors.Is(err, ErrInvalidName) {
			t.Errorf("%q accepted", n)
		}
	}
}

func TestFullKeyName(t *testing.T) {
	got := fullKeyName("S-1-5-21-1-2-3-1001", "vault")
	if got != "S-1-5-21-1-2-3-1001//keyleash//vault" {
		t.Fatal(got)
	}
}

func TestSanitizePrompt(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Unlock vault", "Unlock vault"},
		{"  a\r\n\tb  ", "a b"},
		{"evil‮exe", "evilexe"}, // bidi override dropped
		{"\x00\x07", "keyleash needs to confirm it's you"},
		{"", "keyleash needs to confirm it's you"},
	}
	for _, tc := range tests {
		if got := sanitizePrompt(tc.in); got != tc.want {
			t.Errorf("sanitizePrompt(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	long := sanitizePrompt(strings.Repeat("y", 1000))
	if r := []rune(long); len(r) != maxPromptRunes+1 || r[len(r)-1] != '…' {
		t.Errorf("long prompt not truncated: %d runes", len(r))
	}
}

// buildBlob makes a BCRYPT_RSAPUBLIC_BLOB the way the KSP exports it.
func buildBlob(magic uint32, bitLen uint32, e []byte, n []byte) []byte {
	b := make([]byte, rsaBlobHeaderSize)
	le := binary.LittleEndian
	le.PutUint32(b[0:], magic)
	le.PutUint32(b[4:], bitLen)
	le.PutUint32(b[8:], uint32(len(e)))
	le.PutUint32(b[12:], uint32(len(n)))
	b = append(b, e...)
	return append(b, n...)
}

func TestParseRSAPublicBlob(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := priv.N.Bytes()
	e := big.NewInt(int64(priv.E)).Bytes()
	good := buildBlob(rsaPublicMagic, 2048, e, n)
	pub, err := parseRSAPublicBlob(good)
	if err != nil {
		t.Fatal(err)
	}
	if pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
		t.Fatal("parsed key differs")
	}

	even := new(big.Int).Add(priv.N, big.NewInt(1)).Bytes()
	tests := []struct {
		name string
		b    []byte
	}{
		{"short", good[:10]},
		{"private magic", buildBlob(0x32415352, 2048, e, n)},
		{"truncated", good[:len(good)-1]},
		{"trailing", append(append([]byte(nil), good...), 0)},
		{"zero exp len", buildBlob(rsaPublicMagic, 2048, nil, n)},
		{"huge exp len", buildBlob(rsaPublicMagic, 2048, make([]byte, 9), n)},
		{"even exp", buildBlob(rsaPublicMagic, 2048, []byte{1, 0, 0}, n)},
		{"exp 1", buildBlob(rsaPublicMagic, 2048, []byte{1}, n)},
		{"even modulus", buildBlob(rsaPublicMagic, 2048, e, even)},
		{"bitlen mismatch", buildBlob(rsaPublicMagic, 4096, e, n)},
		{"zero modulus", buildBlob(rsaPublicMagic, 0, e, make([]byte, 256))},
	}
	for _, tc := range tests {
		if _, err := parseRSAPublicBlob(tc.b); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestKeyAccessors(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	k := &Key{name: "vault", keyName: "S-1//keyleash//vault", pub: &priv.PublicKey}
	p, err := k.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	p.N.SetInt64(1) // mutating the copy must not affect the key
	if k.pub.N.Cmp(priv.N) != 0 {
		t.Fatal("PublicKey returned shared state")
	}
	if k.KeyName() != "S-1//keyleash//vault" || k.String() != "winhello.Key(vault)" {
		t.Fatal("accessors")
	}
	var nk *Key
	if _, err := nk.PublicKey(); err == nil {
		t.Fatal("nil key PublicKey")
	}
	if nk.String() != "winhello.Key(nil)" {
		t.Fatal("nil String")
	}
}

func TestAvailableDoesNotPanic(t *testing.T) {
	ok, reason := Available()
	t.Logf("Available() = %v, %q", ok, reason)
	if !ok && reason == "" {
		t.Fatal("false without reason")
	}
}
