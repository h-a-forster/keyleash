//go:build windows

package winhello

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"unsafe"
)

func TestStructLayouts(t *testing.T) {
	ptr := unsafe.Sizeof(uintptr(0))
	// NCRYPT_UI_POLICY: DWORD, DWORD, LPCWSTR x3.
	if got, want := unsafe.Sizeof(ncryptUIPolicy{}), 8+3*ptr; got != want {
		t.Errorf("NCRYPT_UI_POLICY size %d, want %d", got, want)
	}
	if off := unsafe.Offsetof(ncryptUIPolicy{}.CreationTitle); off != 8 {
		t.Errorf("pszCreationTitle offset %d", off)
	}
	// BCRYPT_OAEP_PADDING_INFO: LPCWSTR, PUCHAR, ULONG (+ tail padding).
	wantOAEP := 2*ptr + 4
	if ptr == 8 {
		wantOAEP = 24
	}
	if got := unsafe.Sizeof(bcryptOAEPPaddingInfo{}); got != wantOAEP {
		t.Errorf("BCRYPT_OAEP_PADDING_INFO size %d, want %d", got, wantOAEP)
	}
	if got := unsafe.Sizeof(bcryptPKCS1PaddingInfo{}); got != ptr {
		t.Errorf("BCRYPT_PKCS1_PADDING_INFO size %d", got)
	}
}

func TestStatusErrorMapping(t *testing.T) {
	tests := []struct {
		status uint32
		target error
	}{
		{nteBadKeyset, ErrNotFound},
		{nteNoKey, ErrNotFound},
		{nteNotFound, ErrNotFound},
		{nteUserCancelled, ErrCancelled},
		{hrErrorCancelled, ErrCancelled},
		{scardWCancelledUser, ErrCancelled},
		{nteNotSupported, ErrUnsupported},
	}
	for _, tc := range tests {
		err := error(&statusError{op: "X", status: tc.status})
		if !errors.Is(err, tc.target) {
			t.Errorf("%#x not mapped to %v", tc.status, tc.target)
		}
	}
	err := error(&statusError{op: "NCryptDecrypt", status: nteBadData})
	for _, s := range []error{ErrNotFound, ErrCancelled, ErrUnsupported, ErrOAEPUnsupported} {
		if errors.Is(err, s) {
			t.Errorf("NTE_BAD_DATA mapped to %v", s)
		}
	}
	if msg := err.Error(); !strings.Contains(msg, "NCryptDecrypt") || !strings.Contains(msg, "0x80090005") {
		t.Errorf("message %q", msg)
	}
	if check("op", 0) != nil {
		t.Error("success mapped to error")
	}
}

func TestCurrentUserSID(t *testing.T) {
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sid, "S-1-") {
		t.Fatalf("sid %q", sid)
	}
}

func randomName(t *testing.T) string {
	b := make([]byte, 8)
	rand.Read(b)
	return "test-missing-" + hex.EncodeToString(b)
}

// These touch the real Passport KSP but only with the silent flag on a key
// that does not exist, so they never show UI.
func TestMissingKeyNoPrompt(t *testing.T) {
	if ok, reason := Available(); !ok {
		t.Skip(reason)
	}
	sid, err := currentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	name := randomName(t)
	if _, err := lookupExisting(fullKeyName(sid, name)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("lookupExisting(missing) = %v, want ErrNotFound", err)
	}
	if err := Delete(name); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete(missing) = %v, want ErrNotFound", err)
	}
}

func TestInvalidNamesRejectedBeforeOS(t *testing.T) {
	for _, n := range []string{"", "../x", "a/b"} {
		if _, err := OpenOrCreate(n); !errors.Is(err, ErrInvalidName) {
			t.Errorf("OpenOrCreate(%q) = %v", n, err)
		}
		if err := Delete(n); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Delete(%q) = %v", n, err)
		}
	}
}

// Private-key operations validate input and context before any KSP call,
// so these never prompt.
func TestPrivateOpsPreconditions(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	k := &Key{name: "x", keyName: "S-1-0//keyleash//does-not-exist", pub: &priv.PublicKey}

	if _, err := k.Decrypt(context.Background(), make([]byte, 100), "p"); err == nil {
		t.Error("short ciphertext accepted")
	}
	if _, err := k.DecryptPKCS1v15(context.Background(), make([]byte, 300), "p"); err == nil {
		t.Error("long ciphertext accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := k.Decrypt(ctx, make([]byte, 256), "p"); !errors.Is(err, context.Canceled) {
		t.Errorf("Decrypt with cancelled ctx = %v", err)
	}
	if err := k.Confirm(ctx, "p"); !errors.Is(err, context.Canceled) {
		t.Errorf("Confirm with cancelled ctx = %v", err)
	}
	var nk *Key
	if _, err := nk.Decrypt(context.Background(), nil, ""); err == nil {
		t.Error("nil key Decrypt")
	}
	if err := nk.Confirm(context.Background(), ""); err == nil {
		t.Error("nil key Confirm")
	}
}

func TestConcurrentNonPromptingCalls(t *testing.T) {
	if ok, reason := Available(); !ok {
		t.Skip(reason)
	}
	done := make(chan error, 16)
	for i := 0; i < 16; i++ {
		go func() {
			for j := 0; j < 5; j++ {
				if ok, r := Available(); !ok {
					done <- errors.New(r)
					return
				}
				if err := Delete(randomName(t)); !errors.Is(err, ErrNotFound) {
					done <- err
					return
				}
			}
			done <- nil
		}()
	}
	for i := 0; i < 16; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
