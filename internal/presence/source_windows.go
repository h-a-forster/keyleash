//go:build windows

package presence

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modUser32                    = windows.NewLazySystemDLL("user32.dll")
	procGetLastInputInfo         = modUser32.NewProc("GetLastInputInfo")
	procOpenInputDesktop         = modUser32.NewProc("OpenInputDesktop")
	procCloseDesktop             = modUser32.NewProc("CloseDesktop")
	procGetUserObjectInformation = modUser32.NewProc("GetUserObjectInformationW")

	modKernel32        = windows.NewLazySystemDLL("kernel32.dll")
	procGetTickCount64 = modKernel32.NewProc("GetTickCount64")

	modWtsapi32                    = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformation = modWtsapi32.NewProc("WTSQuerySessionInformationW")
)

const (
	wtsCurrentServerHandle = 0
	wtsCurrentSession      = 0xFFFFFFFF
	wtsSessionInfoEx       = 25 // WTS_INFO_CLASS.WTSSessionInfoEx

	// Offsets inside WTSINFOEXW. Level is a DWORD; the union that follows
	// contains LARGE_INTEGERs, so it is 8-byte aligned on every Windows
	// ABI (MSVC aligns LARGE_INTEGER to 8 on x86 too).
	wtsInfoExLevelOff        = 0
	wtsInfoExSessionStateOff = 8 + 4
	wtsInfoExSessionFlagsOff = 8 + 8
	wtsInfoExMinSize         = 8 + 12

	wtsSessionStateLock    = 0
	wtsSessionStateUnlock  = 1
	wtsSessionStateUnknown = 0xFFFFFFFF

	wtsActive       = 0 // WTS_CONNECTSTATE_CLASS.WTSActive
	wtsDisconnected = 4 // WTS_CONNECTSTATE_CLASS.WTSDisconnected

	desktopSwitchDesktop = 0x0100
	uoiName              = 2
)

// OSSource is the Windows presence Source returned by NewOSSource and
// NewOSSourceWithOptions.
//
//   - IdleFor (default, CountInjected=false): time since the last PHYSICAL
//     keyboard/mouse event, observed with low-level hooks (WH_KEYBOARD_LL,
//     WH_MOUSE_LL) on a dedicated thread. Events flagged LLKHF_INJECTED /
//     LLMHF_INJECTED (or the lower-integrity injected bits) are ignored, so
//     an automation or computer-use agent driving the desktop with
//     SendInput does not keep the owner "present". The baseline is taken
//     from GetLastInputInfo at start, so a freshly started daemon is not
//     instantly idle. The result is never less than the GetLastInputInfo
//     idle time. If the hooks stop delivering events (Windows silently
//     removes a low-level hook whose callback times out, or after Close),
//     idle time only grows: the failure mode is Away, never present.
//     Remote-desktop tools that inject input (Parsec, Sunshine, some VNC
//     servers) look idle in this mode; set CountInjected for them. RDP
//     input is typically delivered as physical input and is counted.
//   - IdleFor (CountInjected=true, or Degraded): GetLastInputInfo compared
//     with the low 32 bits of GetTickCount64, subtracted modulo 2^32 so the
//     49.7-day tick wrap is handled. This counts injected input.
//   - ScreenLocked: WTSQuerySessionInformation(WTSSessionInfoEx) lock flag
//     for the caller's session (a disconnected session counts as locked).
//     If that is unavailable or reports "unknown", it falls back to
//     OpenInputDesktop: failure to open the input desktop, or an input
//     desktop other than "Default" (Winlogon, screen saver), counts as
//     locked. The fallback also reads a UAC secure-desktop prompt as locked.
//
// The daemon must run in the user's interactive session; in session 0
// (a service) these signals are meaningless.
type OSSource struct {
	countInjected  bool
	hooks          *inputHooks // nil when countInjected or degraded
	degradedReason string
	closed         atomic.Bool
}

// Options configures NewOSSourceWithOptions.
type Options struct {
	// CountInjected makes injected (synthetic) input count as presence,
	// using GetLastInputInfo instead of low-level hooks. Needed when the
	// owner works through a remote-desktop tool that injects input.
	CountInjected bool
}

// NewOSSource returns the default Windows presence source
// (CountInjected=false). If even GetLastInputInfo is unavailable, the
// returned Source fails every IdleFor call, which the Monitor treats as
// idle (fail closed).
func NewOSSource() Source {
	s, err := NewOSSourceWithOptions(Options{})
	if err != nil {
		return errSource{err}
	}
	return s
}

// NewOSSourceWithOptions returns an *OSSource (see its doc). With
// CountInjected false it installs low-level input hooks; if they cannot be
// installed it falls back to GetLastInputInfo and Degraded reports true
// with a reason. It returns an error only when GetLastInputInfo itself is
// unusable. Call Close on the returned *OSSource to remove the hooks.
func NewOSSourceWithOptions(opts Options) (Source, error) {
	s := &OSSource{countInjected: opts.CountInjected}
	gli, err := gliIdle()
	if err != nil {
		return nil, err
	}
	if opts.CountInjected {
		return s, nil
	}
	// Baseline before the hooks exist: a fresh daemon is not instantly idle.
	notePhysical(tickCount64() - gli.Milliseconds())
	h, err := startInputHooks()
	if err != nil {
		s.degradedReason = "low-level input hooks unavailable, injected input counts as presence: " + err.Error()
		return s, nil
	}
	s.hooks = h
	return s, nil
}

// Degraded reports whether physical-input detection was requested but is
// unavailable, so IdleFor falls back to GetLastInputInfo (which counts
// injected input).
func (s *OSSource) Degraded() bool { return s.degradedReason != "" }

// DegradedReason explains Degraded; empty when not degraded.
func (s *OSSource) DegradedReason() string { return s.degradedReason }

// Close removes the input hooks and stops their thread. Afterwards IdleFor
// returns an error (treated as idle). Safe to call more than once.
func (s *OSSource) Close() error {
	s.closed.Store(true)
	if s.hooks != nil {
		return s.hooks.close()
	}
	return nil
}

func (s *OSSource) IdleFor() (time.Duration, error) {
	if s.closed.Load() {
		return 0, errHooksClosed
	}
	gli, err := gliIdle()
	if err != nil {
		return 0, err
	}
	if s.hooks == nil {
		return gli, nil
	}
	// If the hook thread has died, lastPhysicalTick stops advancing and
	// the reported idle time keeps growing (fail closed).
	return physicalIdle(tickCount64(), lastPhysicalTick.Load(), gli), nil
}

// physicalIdle is the idle time from the last hook-observed physical input
// tick, never less than the GetLastInputInfo idle time.
func physicalIdle(now, lastPhysical int64, gli time.Duration) time.Duration {
	d := time.Duration(0)
	if now > lastPhysical {
		d = time.Duration(now-lastPhysical) * time.Millisecond
	}
	if gli > d {
		d = gli
	}
	return d
}

func (s *OSSource) ScreenLocked() (bool, error) { return screenLocked() }

// errSource fails every call; used when the OS source cannot be built.
type errSource struct{ err error }

func (e errSource) IdleFor() (time.Duration, error) { return 0, e.err }
func (e errSource) ScreenLocked() (bool, error)     { return screenLocked() }

// gliIdle returns the session-wide idle time from GetLastInputInfo
// (counts injected input).
func gliIdle() (time.Duration, error) {
	if err := procGetLastInputInfo.Find(); err != nil {
		return 0, fmt.Errorf("presence: GetLastInputInfo unavailable: %w", err)
	}
	if err := procGetTickCount64.Find(); err != nil {
		return 0, fmt.Errorf("presence: GetTickCount64 unavailable: %w", err)
	}
	var lii struct {
		cbSize uint32
		dwTime uint32
	}
	lii.cbSize = uint32(unsafe.Sizeof(lii))
	r, _, e := procGetLastInputInfo.Call(uintptr(unsafe.Pointer(&lii)))
	if r == 0 {
		return 0, fmt.Errorf("presence: GetLastInputInfo: %w", e)
	}
	now, _, _ := procGetTickCount64.Call()
	return idleFromTicks(uint64(now), lii.dwTime), nil
}

// idleFromTicks computes idle time from a 64-bit tick count and the 32-bit
// tick of the last input, tolerating wrap of the 32-bit counter.
func idleFromTicks(now64 uint64, last32 uint32) time.Duration {
	ms := uint32(now64) - last32 // modulo 2^32
	return time.Duration(ms) * time.Millisecond
}

func screenLocked() (bool, error) {
	locked, known, wtsErr := wtsLocked()
	if wtsErr == nil && known {
		return locked, nil
	}
	locked, err := desktopLocked()
	if err != nil {
		return false, errors.Join(wtsErr, err)
	}
	return locked, nil
}

// wtsLocked queries the session lock flag. known is false when the OS
// reports the state as unknown.
func wtsLocked() (locked, known bool, err error) {
	if err := procWTSQuerySessionInformation.Find(); err != nil {
		return false, false, fmt.Errorf("presence: WTSQuerySessionInformation unavailable: %w", err)
	}
	var buf *byte
	var n uint32
	r, _, e := procWTSQuerySessionInformation.Call(
		wtsCurrentServerHandle,
		wtsCurrentSession,
		wtsSessionInfoEx,
		uintptr(unsafe.Pointer(&buf)),
		uintptr(unsafe.Pointer(&n)),
	)
	if r == 0 {
		return false, false, fmt.Errorf("presence: WTSQuerySessionInformation: %w", e)
	}
	if buf == nil {
		return false, false, errors.New("presence: WTSQuerySessionInformation returned no data")
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(buf)))
	if n < wtsInfoExMinSize {
		return false, false, errors.New("presence: short WTSINFOEX")
	}
	b := unsafe.Slice(buf, wtsInfoExMinSize)
	return parseWTSInfoEx(b)
}

// parseWTSInfoEx decodes the lock state from the head of a WTSINFOEXW.
func parseWTSInfoEx(b []byte) (locked, known bool, err error) {
	if len(b) < wtsInfoExMinSize {
		return false, false, errors.New("presence: short WTSINFOEX")
	}
	if lvl := binary.LittleEndian.Uint32(b[wtsInfoExLevelOff:]); lvl != 1 {
		return false, false, fmt.Errorf("presence: unexpected WTSINFOEX level %d", lvl)
	}
	if binary.LittleEndian.Uint32(b[wtsInfoExSessionStateOff:]) == wtsDisconnected {
		return true, true, nil
	}
	switch binary.LittleEndian.Uint32(b[wtsInfoExSessionFlagsOff:]) {
	case wtsSessionStateLock:
		return true, true, nil
	case wtsSessionStateUnlock:
		return false, true, nil
	case wtsSessionStateUnknown:
		return false, false, nil
	default:
		return false, false, nil
	}
}

// desktopLocked reports whether the input desktop is not the user's
// "Default" desktop.
func desktopLocked() (bool, error) {
	if err := procOpenInputDesktop.Find(); err != nil {
		return false, fmt.Errorf("presence: OpenInputDesktop unavailable: %w", err)
	}
	h, _, _ := procOpenInputDesktop.Call(0, 0, desktopSwitchDesktop)
	if h == 0 {
		// Access to the input desktop is denied while Winlogon's secure
		// desktop is active (locked screen or UAC).
		return true, nil
	}
	defer procCloseDesktop.Call(h)
	name := make([]uint16, 64)
	var need uint32
	r, _, e := procGetUserObjectInformation.Call(h, uoiName,
		uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)*2), uintptr(unsafe.Pointer(&need)))
	if r == 0 {
		return false, fmt.Errorf("presence: GetUserObjectInformation: %w", e)
	}
	return windows.UTF16ToString(name) != "Default", nil
}
