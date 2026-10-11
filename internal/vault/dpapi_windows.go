//go:build windows

package vault

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/h-a-forster/keyleash/internal/secmem"
)

// dpapiSupported reports whether DPAPI slots can be created and used.
const dpapiSupported = true

func blobOf(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// dpapiProtect seals plain for the current user with CryptProtectData
// (user scope, UI forbidden, caller-supplied entropy).
func dpapiProtect(plain, entropy []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, errors.New("vault: dpapi: empty input")
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(blobOf(plain), nil, blobOf(entropy), 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	res := make([]byte, out.Size)
	copy(res, unsafe.Slice(out.Data, out.Size))
	return res, nil
}

// dpapiUnprotect opens a DPAPI blob into locked memory and wipes the
// LocalAlloc'd copy Windows returned.
func dpapiUnprotect(blob, entropy []byte) (*secmem.Buffer, error) {
	if len(blob) == 0 {
		return nil, errors.New("vault: dpapi: empty blob")
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blobOf(blob), nil, blobOf(entropy), 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	plain := unsafe.Slice(out.Data, out.Size)
	defer func() {
		secmem.Wipe(plain)
		windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(out.Data))))
	}()
	if len(plain) == 0 {
		return nil, errors.New("vault: dpapi: empty output")
	}
	buf, err := secmem.New(len(plain))
	if err != nil {
		return nil, err
	}
	copy(buf.Bytes(), plain)
	return buf, nil
}
