//go:build windows

package winhello

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modNcrypt                     = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = modNcrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptOpenKey             = modNcrypt.NewProc("NCryptOpenKey")
	procNCryptCreatePersistedKey  = modNcrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptSetProperty         = modNcrypt.NewProc("NCryptSetProperty")
	procNCryptGetProperty         = modNcrypt.NewProc("NCryptGetProperty")
	procNCryptFinalizeKey         = modNcrypt.NewProc("NCryptFinalizeKey")
	procNCryptExportKey           = modNcrypt.NewProc("NCryptExportKey")
	procNCryptDecrypt             = modNcrypt.NewProc("NCryptDecrypt")
	procNCryptSignHash            = modNcrypt.NewProc("NCryptSignHash")
	procNCryptDeleteKey           = modNcrypt.NewProc("NCryptDeleteKey")
	procNCryptFreeObject          = modNcrypt.NewProc("NCryptFreeObject")

	modCryptngc                        = windows.NewLazySystemDLL("cryptngc.dll")
	procNgcGetDefaultDecryptionKeyName = modCryptngc.NewProc("NgcGetDefaultDecryptionKeyName")

	modOle32           = windows.NewLazySystemDLL("ole32.dll")
	procCoTaskMemFree  = modOle32.NewProc("CoTaskMemFree")
	modKernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procGetConsoleWind = modKernel32.NewProc("GetConsoleWindow")
)

// ncrypt.h / bcrypt.h constants.
const (
	msNgcKeyStorageProvider = "Microsoft Passport Key Storage Provider" // MS_NGC_KEY_STORAGE_PROVIDER
	bcryptRSAAlgorithm      = "RSA"
	bcryptSHA256Algorithm   = "SHA256"
	bcryptRSAPublicBlob     = "RSAPUBLICBLOB"

	propLength                  = "Length"
	propKeyUsage                = "Key Usage"
	propUIPolicy                = "UI Policy"
	propWindowHandle            = "HWND Handle"
	propUseContext              = "Use Context"
	propNgcCacheType            = "NgcCacheType"
	propNgcCacheTypeDeprecated  = "NgcCacheTypeProperty"
	propPinCacheGestureRequired = "PinCacheIsGestureRequired"

	ncryptSilentFlag     = 0x00000040
	ncryptPadPKCS1Flag   = 0x00000002
	ncryptPadOAEPFlag    = 0x00000004
	ncryptAllowDecrypt   = 0x00000001
	ncryptAllowSigning   = 0x00000002
	ngcCacheAuthMandator = 0x00000001 // NCRYPT_NGC_CACHE_TYPE_PROPERTY_AUTH_MANDATORY_FLAG
	uiPolicyVersion      = 1
)

// SECURITY_STATUS values (winerror.h).
const (
	nteBadData           = 0x80090005
	nteBadFlags          = 0x80090009
	nteBadKeyset         = 0x80090016
	nteBadType           = 0x8009000A
	nteExists            = 0x8009000F
	nteNoKey             = 0x8009000D
	ntePerm              = 0x80090010
	nteNotFound          = 0x80090011
	nteInvalidParameter  = 0x80090027
	nteNotSupported      = 0x80090029
	nteDecryptionFailure = 0x8009002C
	nteUserCancelled     = 0x80090036
	hrErrorCancelled     = 0x800704C7 // HRESULT_FROM_WIN32(ERROR_CANCELLED)
	scardWCancelledUser  = 0x8010006E
	nteDeviceNotReady    = 0x80090030
)

// ncryptUIPolicy mirrors NCRYPT_UI_POLICY.
type ncryptUIPolicy struct {
	Version       uint32
	Flags         uint32
	CreationTitle *uint16
	FriendlyName  *uint16
	Description   *uint16
}

// bcryptOAEPPaddingInfo mirrors BCRYPT_OAEP_PADDING_INFO.
type bcryptOAEPPaddingInfo struct {
	AlgID   *uint16
	Label   *byte
	LabelSz uint32
}

// bcryptPKCS1PaddingInfo mirrors BCRYPT_PKCS1_PADDING_INFO.
type bcryptPKCS1PaddingInfo struct {
	AlgID *uint16
}

// statusError is a failed NCrypt call. Its text names the function and the
// status code only.
type statusError struct {
	op     string
	status uint32
}

func (e *statusError) Error() string {
	return fmt.Sprintf("winhello: %s failed: %#08x (%s)", e.op, e.status, windows.Errno(e.status).Error())
}

// Is maps status codes onto the package sentinels.
func (e *statusError) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.status == nteBadKeyset || e.status == nteNoKey || e.status == nteNotFound
	case ErrCancelled:
		return e.status == nteUserCancelled || e.status == hrErrorCancelled || e.status == scardWCancelledUser
	case ErrUnsupported:
		return e.status == nteNotSupported
	}
	return false
}

func check(op string, r uintptr) error {
	if uint32(r) == 0 {
		return nil
	}
	return &statusError{op: op, status: uint32(r)}
}

func utf16Ptr(s string) *uint16 {
	p, err := windows.UTF16PtrFromString(s)
	if err != nil {
		// Only possible with an embedded NUL, which callers never pass.
		p, _ = windows.UTF16PtrFromString("")
	}
	return p
}

func freeObject(h uintptr) {
	if h != 0 {
		procNCryptFreeObject.Call(h)
	}
}

func loadNcrypt() error {
	if err := modNcrypt.Load(); err != nil {
		return fmt.Errorf("%w: ncrypt.dll: %v", ErrUnavailable, err)
	}
	return nil
}

func openProvider() (uintptr, error) {
	if err := loadNcrypt(); err != nil {
		return 0, err
	}
	var h uintptr
	r, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(utf16Ptr(msNgcKeyStorageProvider))), 0)
	if err := check("NCryptOpenStorageProvider", r); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return h, nil
}

func openKey(prov uintptr, keyName string, flags uint32) (uintptr, error) {
	var h uintptr
	r, _, _ := procNCryptOpenKey.Call(prov, uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(utf16Ptr(keyName))), 0, uintptr(flags))
	if err := check("NCryptOpenKey", r); err != nil {
		return 0, err
	}
	return h, nil
}

func setProp(h uintptr, name string, data unsafe.Pointer, size uintptr, flags uint32) error {
	r, _, _ := procNCryptSetProperty.Call(h, uintptr(unsafe.Pointer(utf16Ptr(name))),
		uintptr(data), size, uintptr(flags))
	return check("NCryptSetProperty("+name+")", r)
}

func setDWORD(h uintptr, name string, v uint32) error {
	return setProp(h, name, unsafe.Pointer(&v), 4, 0)
}

func setString(h uintptr, name, v string) error {
	u, err := windows.UTF16FromString(v)
	if err != nil {
		return err
	}
	return setProp(h, name, unsafe.Pointer(&u[0]), uintptr(len(u)*2), 0)
}

func getDWORD(h uintptr, name string) (uint32, error) {
	var v, n uint32
	r, _, _ := procNCryptGetProperty.Call(h, uintptr(unsafe.Pointer(utf16Ptr(name))),
		uintptr(unsafe.Pointer(&v)), 4, uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
	if err := check("NCryptGetProperty("+name+")", r); err != nil {
		return 0, err
	}
	if n != 4 {
		return 0, fmt.Errorf("winhello: property %s has size %d", name, n)
	}
	return v, nil
}

// promptWindow picks a parent window so the Hello dialog surfaces: the
// console window if the process has one, else the foreground window.
func promptWindow() windows.HWND {
	if procGetConsoleWind.Find() == nil {
		if h, _, _ := procGetConsoleWind.Call(); h != 0 {
			return windows.HWND(h)
		}
	}
	return windows.GetForegroundWindow()
}

// setUIContext attaches the parent window and prompt text to a handle.
// Failures are tolerated: they only affect how the dialog looks.
func setUIContext(h uintptr, prompt string) {
	if hwnd := promptWindow(); hwnd != 0 {
		_ = setProp(h, propWindowHandle, unsafe.Pointer(&hwnd), unsafe.Sizeof(hwnd), 0)
	}
	_ = setString(h, propUseContext, sanitizePrompt(prompt))
}

func currentUserSID() (string, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("winhello: current user: %w", err)
	}
	return tu.User.Sid.String(), nil
}

// Available reports whether Windows Hello can be used by this user: the
// Passport KSP opens and a Hello container (default NGC decryption key)
// exists. It never shows a prompt. reason explains a false result.
func Available() (ok bool, reason string) {
	prov, err := openProvider()
	if err != nil {
		return false, "Microsoft Passport Key Storage Provider is not available"
	}
	freeObject(prov)

	if err := procNgcGetDefaultDecryptionKeyName.Find(); err != nil {
		return false, "cryptngc.dll is missing; Windows Hello is not supported on this system"
	}
	sid, err := currentUserSID()
	if err != nil {
		return false, "cannot determine the current user SID"
	}
	var p *uint16
	r, _, _ := procNgcGetDefaultDecryptionKeyName.Call(uintptr(unsafe.Pointer(utf16Ptr(sid))), 0, 0,
		uintptr(unsafe.Pointer(&p)))
	name := ""
	if p != nil {
		name = windows.UTF16PtrToString(p)
		if procCoTaskMemFree.Find() == nil {
			procCoTaskMemFree.Call(uintptr(unsafe.Pointer(p)))
		}
	}
	if uint32(r) != 0 || name == "" {
		return false, "Windows Hello is not set up for this user (no PIN or biometric enrolled)"
	}
	return true, ""
}

// exportPublic exports the RSA public key of an open key handle.
func exportPublic(key uintptr) (*rsa.PublicKey, error) {
	blobType := utf16Ptr(bcryptRSAPublicBlob)
	var n uint32
	r, _, _ := procNCryptExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0,
		uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
	if err := check("NCryptExportKey", r); err != nil {
		return nil, err
	}
	if n < rsaBlobHeaderSize || n > 1<<16 {
		return nil, errors.New("winhello: unexpected public blob size")
	}
	buf := make([]byte, n)
	r, _, _ = procNCryptExportKey.Call(key, 0, uintptr(unsafe.Pointer(blobType)), 0,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), ncryptSilentFlag)
	if err := check("NCryptExportKey", r); err != nil {
		return nil, err
	}
	return parseRSAPublicBlob(buf[:n])
}

// cacheTypeMandatory reports whether the key requires authentication on
// every use.
func cacheTypeMandatory(key uintptr) (bool, error) {
	v, err := getDWORD(key, propNgcCacheType)
	if err != nil {
		var err2 error
		v, err2 = getDWORD(key, propNgcCacheTypeDeprecated)
		if err2 != nil {
			return false, errors.Join(err, err2)
		}
	}
	return v&ngcCacheAuthMandator != 0, nil
}

// inspect validates an open existing key and returns its public key.
func inspect(key uintptr) (*rsa.PublicKey, error) {
	mandatory, err := cacheTypeMandatory(key)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read cache policy: %v", ErrWeakKey, err)
	}
	if !mandatory {
		return nil, fmt.Errorf("%w: key does not require authentication on every use", ErrWeakKey)
	}
	pub, err := exportPublic(key)
	if err != nil {
		return nil, err
	}
	if pub.N.BitLen() < MinKeyBits {
		return nil, fmt.Errorf("%w: RSA-%d", ErrWeakKey, pub.N.BitLen())
	}
	return pub, nil
}

// lookupExisting opens an existing key silently. It never prompts.
func lookupExisting(keyName string) (*rsa.PublicKey, error) {
	prov, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)
	key, err := openKey(prov, keyName, ncryptSilentFlag)
	if err != nil {
		return nil, err
	}
	defer freeObject(key)
	return inspect(key)
}

// create makes and finalizes a new persisted key. Finalizing may show a
// Windows Hello prompt.
func create(keyName string) (*rsa.PublicKey, error) {
	prov, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)

	var key uintptr
	r, _, _ := procNCryptCreatePersistedKey.Call(prov, uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(utf16Ptr(bcryptRSAAlgorithm))),
		uintptr(unsafe.Pointer(utf16Ptr(keyName))), 0, 0)
	if err := check("NCryptCreatePersistedKey", r); err != nil {
		return nil, err
	}
	finalized := false
	defer func() {
		if !finalized {
			freeObject(key)
		}
	}()

	if err := setDWORD(key, propLength, MinKeyBits); err != nil {
		return nil, err
	}
	if err := setDWORD(key, propKeyUsage, ncryptAllowDecrypt|ncryptAllowSigning); err != nil {
		return nil, err
	}
	// Mandatory: without it Hello may cache the gesture and later
	// operations would not prompt. Fail closed if neither name works.
	if err := setDWORD(key, propNgcCacheType, ngcCacheAuthMandator); err != nil {
		if err2 := setDWORD(key, propNgcCacheTypeDeprecated, ngcCacheAuthMandator); err2 != nil {
			return nil, errors.Join(err, err2)
		}
	}
	// UI policy: describes the key in any KSP UI. Best effort; the Passport
	// KSP may ignore or reject it.
	policy := ncryptUIPolicy{
		Version:       uiPolicyVersion,
		CreationTitle: utf16Ptr("keyleash"),
		FriendlyName:  utf16Ptr("keyleash vault key"),
		Description:   utf16Ptr("Unlocks the keyleash API-key vault and approves spending."),
	}
	_ = setProp(key, propUIPolicy, unsafe.Pointer(&policy), unsafe.Sizeof(policy), 0)
	runtime.KeepAlive(&policy)
	setUIContext(key, "Create the keyleash Windows Hello key")

	r, _, _ = procNCryptFinalizeKey.Call(key, 0)
	if err := check("NCryptFinalizeKey", r); err != nil {
		// Remove any half-created key. NCryptDeleteKey releases the handle
		// on success; otherwise the deferred free does.
		if d, _, _ := procNCryptDeleteKey.Call(key, ncryptSilentFlag); uint32(d) == 0 {
			finalized = true
		}
		return nil, err
	}
	defer freeObject(key)
	finalized = true
	return inspect(key)
}

// OpenOrCreate opens the key name for the current user, creating an
// RSA-2048 key with mandatory per-use authentication if it does not exist.
// Opening never prompts; creating may show a Windows Hello prompt. An
// existing key that does not meet policy (RSA ≥ 2048, auth mandatory) is
// refused with ErrWeakKey rather than used.
func OpenOrCreate(name string) (*Key, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	sid, err := currentUserSID()
	if err != nil {
		return nil, err
	}
	keyName := fullKeyName(sid, name)
	pub, err := lookupExisting(keyName)
	if errors.Is(err, ErrNotFound) {
		pub, err = create(keyName)
		var se *statusError
		if errors.As(err, &se) && se.status == nteExists {
			pub, err = lookupExisting(keyName) // lost a creation race
		}
	}
	if err != nil {
		return nil, err
	}
	return &Key{name: name, keyName: keyName, pub: pub}, nil
}

// opResult carries a private-key operation's output across goroutines.
type opResult struct {
	out []byte
	err error
}

// runPrivate opens the key (prompting allowed), applies the prompt and
// runs fn on a locked OS thread. If ctx ends first, runPrivate returns
// ctx.Err() at once; the OS call (and any visible prompt) continues until
// the user answers or Windows times it out, and its output is wiped.
func (k *Key) runPrivate(ctx context.Context, prompt string, fn func(key uintptr) ([]byte, error)) ([]byte, error) {
	if k == nil || k.pub == nil {
		return nil, errors.New("winhello: nil key")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	ch := make(chan opResult, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		ch <- func() opResult {
			prov, err := openProvider()
			if err != nil {
				return opResult{err: err}
			}
			defer freeObject(prov)
			setUIContext(prov, prompt)
			key, err := openKey(prov, k.keyName, 0)
			if err != nil {
				return opResult{err: err}
			}
			defer freeObject(key)
			setUIContext(key, prompt)
			// Ask the KSP to require a fresh gesture; cache type already
			// enforces this, so failure here is tolerated.
			_ = setDWORD(key, propPinCacheGestureRequired, 1)
			out, err := fn(key)
			return opResult{out: out, err: err}
		}()
	}()
	select {
	case res := <-ch:
		return res.out, res.err
	case <-ctx.Done():
		go func() {
			res := <-ch
			wipe(res.out)
		}()
		return nil, ctx.Err()
	}
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (k *Key) decrypt(ctx context.Context, ct []byte, prompt string, oaep bool) ([]byte, error) {
	size := (k.pub.N.BitLen() + 7) / 8
	if len(ct) != size {
		return nil, fmt.Errorf("winhello: ciphertext is %d bytes, want %d", len(ct), size)
	}
	in := append([]byte(nil), ct...)
	return k.runPrivate(ctx, prompt, func(key uintptr) ([]byte, error) {
		buf := make([]byte, size)
		var n uint32
		var r uintptr
		if oaep {
			info := bcryptOAEPPaddingInfo{AlgID: utf16Ptr(bcryptSHA256Algorithm)}
			r, _, _ = procNCryptDecrypt.Call(key, uintptr(unsafe.Pointer(&in[0])), uintptr(len(in)),
				uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
				uintptr(unsafe.Pointer(&n)), ncryptPadOAEPFlag)
			runtime.KeepAlive(&info)
		} else {
			r, _, _ = procNCryptDecrypt.Call(key, uintptr(unsafe.Pointer(&in[0])), uintptr(len(in)),
				0, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
				uintptr(unsafe.Pointer(&n)), ncryptPadPKCS1Flag)
		}
		if err := check("NCryptDecrypt", r); err != nil {
			wipe(buf)
			var se *statusError
			if oaep && errors.As(err, &se) {
				switch se.status {
				case nteNotSupported, nteInvalidParameter, nteBadFlags, nteBadType:
					return nil, fmt.Errorf("%w (%v)", ErrOAEPUnsupported, err)
				}
			}
			return nil, err
		}
		if int(n) > len(buf) {
			wipe(buf)
			return nil, errors.New("winhello: KSP reported oversized plaintext")
		}
		out := make([]byte, n)
		copy(out, buf[:n])
		wipe(buf)
		return out, nil
	})
}

// Decrypt unwraps ct (RSA-OAEP with SHA-256, empty label, as produced by
// rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil)) with the
// private key. It shows a Windows Hello prompt displaying prompt, which
// must not contain secrets. The caller owns (and should wipe) the result.
// If the KSP rejects OAEP the error wraps ErrOAEPUnsupported.
func (k *Key) Decrypt(ctx context.Context, ct []byte, prompt string) ([]byte, error) {
	if k == nil || k.pub == nil {
		return nil, errors.New("winhello: nil key")
	}
	return k.decrypt(ctx, ct, prompt, true)
}

// DecryptPKCS1v15 is the fallback for KSPs without OAEP support (spec
// §5.2): it unwraps an RSAES-PKCS1-v1_5 ciphertext. Use it only for slots
// that were wrapped with PKCS#1 v1.5 because Decrypt reported
// ErrOAEPUnsupported.
func (k *Key) DecryptPKCS1v15(ctx context.Context, ct []byte, prompt string) ([]byte, error) {
	if k == nil || k.pub == nil {
		return nil, errors.New("winhello: nil key")
	}
	return k.decrypt(ctx, ct, prompt, false)
}

// Confirm asks the user to verify with Windows Hello by signing a fresh
// random SHA-256-sized digest (RSASSA-PKCS1-v1_5). It returns nil only if
// the KSP produced a signature that verifies under the key's public key.
// A dismissed prompt returns an error wrapping ErrCancelled.
func (k *Key) Confirm(ctx context.Context, prompt string) error {
	if k == nil || k.pub == nil {
		return errors.New("winhello: nil key")
	}
	digest := make([]byte, 32)
	if _, err := rand.Read(digest); err != nil {
		return fmt.Errorf("winhello: random: %w", err)
	}
	size := (k.pub.N.BitLen() + 7) / 8
	sig, err := k.runPrivate(ctx, prompt, func(key uintptr) ([]byte, error) {
		info := bcryptPKCS1PaddingInfo{AlgID: utf16Ptr(bcryptSHA256Algorithm)}
		buf := make([]byte, size)
		var n uint32
		r, _, _ := procNCryptSignHash.Call(key, uintptr(unsafe.Pointer(&info)),
			uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)),
			uintptr(unsafe.Pointer(&n)), ncryptPadPKCS1Flag)
		runtime.KeepAlive(&info)
		if err := check("NCryptSignHash", r); err != nil {
			return nil, err
		}
		if int(n) > len(buf) {
			return nil, errors.New("winhello: KSP reported oversized signature")
		}
		return buf[:n], nil
	})
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(k.pub, crypto.SHA256, digest, sig); err != nil {
		return errors.New("winhello: confirmation signature did not verify")
	}
	return nil
}

// Delete removes the named key for the current user. It returns an error
// wrapping ErrNotFound if there is no such key. Windows may prompt.
func Delete(name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	sid, err := currentUserSID()
	if err != nil {
		return err
	}
	prov, err := openProvider()
	if err != nil {
		return err
	}
	defer freeObject(prov)
	key, err := openKey(prov, fullKeyName(sid, name), ncryptSilentFlag)
	if err != nil {
		return err
	}
	r, _, _ := procNCryptDeleteKey.Call(key, 0)
	if err := check("NCryptDeleteKey", r); err != nil {
		freeObject(key) // the handle is only released on success
		return err
	}
	return nil
}
