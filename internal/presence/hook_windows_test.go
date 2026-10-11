//go:build windows

package presence

import (
	"testing"
	"time"
	"unsafe"
)

func TestHookStructLayout(t *testing.T) {
	ptr := unsafe.Sizeof(uintptr(0))
	var k kbdLLHookStruct
	var m msLLHookStruct
	var wantK, wantM uintptr
	switch ptr {
	case 8:
		wantK, wantM = 24, 32
	case 4:
		wantK, wantM = 20, 24
	default:
		t.Fatalf("unexpected pointer size %d", ptr)
	}
	if got := unsafe.Sizeof(k); got != wantK {
		t.Errorf("KBDLLHOOKSTRUCT size %d, want %d", got, wantK)
	}
	if got := unsafe.Sizeof(m); got != wantM {
		t.Errorf("MSLLHOOKSTRUCT size %d, want %d", got, wantM)
	}
	if off := unsafe.Offsetof(k.flags); off != 8 {
		t.Errorf("KBDLLHOOKSTRUCT.flags offset %d, want 8", off)
	}
	if off := unsafe.Offsetof(m.flags); off != 12 {
		t.Errorf("MSLLHOOKSTRUCT.flags offset %d, want 12", off)
	}
	if off, want := unsafe.Offsetof(m.dwExtraInfo), wantM-ptr; off != want {
		t.Errorf("MSLLHOOKSTRUCT.dwExtraInfo offset %d, want %d", off, want)
	}
}

func TestInjectedFlagFiltering(t *testing.T) {
	kbd := []struct {
		flags uint32
		phys  bool
	}{
		{0, true},
		{0x01, true}, // LLKHF_EXTENDED
		{0x20, true}, // LLKHF_ALTDOWN
		{0x80, true}, // LLKHF_UP
		{0x10, false},
		{0x12, false},
		{0x02, false}, // lower-IL injected alone: still injected
		{0x10 | 0x80 | 0x01, false},
	}
	for _, tc := range kbd {
		if got := isPhysicalKeyboard(tc.flags); got != tc.phys {
			t.Errorf("keyboard flags %#x: physical=%v want %v", tc.flags, got, tc.phys)
		}
	}
	mouse := []struct {
		flags uint32
		phys  bool
	}{
		{0, true},
		{0x01, false},
		{0x02, false},
		{0x03, false},
		{0x04, true}, // unrelated bit
	}
	for _, tc := range mouse {
		if got := isPhysicalMouse(tc.flags); got != tc.phys {
			t.Errorf("mouse flags %#x: physical=%v want %v", tc.flags, got, tc.phys)
		}
	}
}

func TestPhysicalIdle(t *testing.T) {
	if got := physicalIdle(10_000, 4_000, time.Second); got != 6*time.Second {
		t.Errorf("got %v", got)
	}
	// Never less than GetLastInputInfo idle.
	if got := physicalIdle(10_000, 9_000, 5*time.Second); got != 5*time.Second {
		t.Errorf("got %v", got)
	}
	// Last physical tick in the future (clock oddity) clamps to gli.
	if got := physicalIdle(10_000, 20_000, 0); got != 0 {
		t.Errorf("got %v", got)
	}
}

func TestCountInjectedUsesLastInputInfo(t *testing.T) {
	src, err := NewOSSourceWithOptions(Options{CountInjected: true})
	if err != nil {
		t.Fatal(err)
	}
	s := src.(*OSSource)
	defer s.Close()
	if s.hooks != nil || s.Degraded() {
		t.Fatalf("CountInjected source installed hooks or is degraded: %q", s.DegradedReason())
	}
	if _, err := s.IdleFor(); err != nil {
		t.Fatal(err)
	}
}

func hookedSource(t *testing.T) *OSSource {
	t.Helper()
	src, err := NewOSSourceWithOptions(Options{})
	if err != nil {
		t.Fatalf("NewOSSourceWithOptions: %v", err)
	}
	s := src.(*OSSource)
	if s.Degraded() {
		s.Close()
		t.Skipf("low-level hooks not installable here (non-interactive session?): %s", s.DegradedReason())
	}
	return s
}

func TestHookInstallUninstall(t *testing.T) {
	s := hookedSource(t)
	d, err := s.IdleFor()
	if err != nil {
		t.Fatal(err)
	}
	gli, _ := gliIdle()
	// Baseline comes from GetLastInputInfo: not instantly "idle forever".
	if d < gli || d > gli+time.Hour {
		t.Errorf("hook idle %v vs GetLastInputInfo idle %v", d, gli)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case <-s.hooks.done:
	default:
		t.Fatal("hook thread still running after Close")
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := s.IdleFor(); err == nil {
		t.Error("IdleFor after Close must fail closed")
	}
	// Install again: hooks and callbacks are reusable.
	s2 := hookedSource(t)
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
}

// SendInput structures (INPUT with a MOUSEINPUT union member).
type testMouseInput struct {
	dx, dy      int32
	mouseData   uint32
	dwFlags     uint32
	time        uint32
	dwExtraInfo uintptr
}

type testInput struct {
	typ uint32
	mi  testMouseInput
}

var procSendInput = modUser32.NewProc("SendInput")

const (
	inputMouse      = 0
	mouseeventfMove = 0x0001
)

func sendMouseMove(dx, dy int32) bool {
	in := testInput{typ: inputMouse, mi: testMouseInput{dx: dx, dy: dy, dwFlags: mouseeventfMove}}
	r, _, _ := procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
	return r == 1
}

// Regression: injected input must not reset hook-based idle time, while
// GetLastInputInfo (the old implementation) is reset by it.
func TestInjectedMouseDoesNotResetIdle(t *testing.T) {
	if sz := unsafe.Sizeof(testInput{}); sz != 40 && sz != 28 {
		t.Fatalf("INPUT size %d", sz)
	}
	s := hookedSource(t)
	defer s.Close()

	// Let some idle time accumulate so a reset is observable.
	time.Sleep(1500 * time.Millisecond)
	phys0, inj0 := physicalEvents.Load(), injectedEvents.Load()
	before, err := s.IdleFor()
	if err != nil {
		t.Fatal(err)
	}
	if !sendMouseMove(1, 0) || !sendMouseMove(-1, 0) {
		t.Skip("SendInput rejected (no interactive desktop or UIPI)")
	}
	deadline := time.Now().Add(2 * time.Second)
	for injectedEvents.Load() == inj0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if injectedEvents.Load() == inj0 {
		t.Skip("hook did not observe the injected input (desktop not receiving input?)")
	}
	if physicalEvents.Load() != phys0 {
		t.Skipf("real keyboard/mouse input during the test (physical %d->%d, injected %d->%d); cannot judge", phys0, physicalEvents.Load(), inj0, injectedEvents.Load())
	}
	gli, _ := gliIdle()
	after, err := s.IdleFor()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("idle before=%v after=%v GetLastInputInfo after injection=%v", before, after, gli)
	if gli >= before {
		t.Skipf("GetLastInputInfo idle %v not reset by injection (before %v); test cannot discriminate", gli, before)
	}
	if after < before {
		t.Errorf("injected input reset hook-based idle: before %v, after %v", before, after)
	}
}
