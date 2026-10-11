//go:build windows

package presence

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Low-level input hooks (WH_KEYBOARD_LL / WH_MOUSE_LL) let us tell physical
// input from input injected with SendInput / keybd_event / mouse_event.
// GetLastInputInfo cannot: it counts both, so an automation agent driving
// the desktop would keep the owner "present" forever.

var (
	procSetWindowsHookExW   = modUser32.NewProc("SetWindowsHookExW")
	procUnhookWindowsHookEx = modUser32.NewProc("UnhookWindowsHookEx")
	procCallNextHookEx      = modUser32.NewProc("CallNextHookEx")
	procGetMessageW         = modUser32.NewProc("GetMessageW")
	procPeekMessageW        = modUser32.NewProc("PeekMessageW")
	procPostThreadMessageW  = modUser32.NewProc("PostThreadMessageW")
)

const (
	whKeyboardLL = 13
	whMouseLL    = 14
	hcAction     = 0
	wmQuit       = 0x0012
	wmUser       = 0x0400
	pmNoRemove   = 0x0000

	// KBDLLHOOKSTRUCT.flags
	llkhfInjected         = 0x10
	llkhfLowerILInjected  = 0x02
	llkhfInjectedAnyLevel = llkhfInjected | llkhfLowerILInjected
	// MSLLHOOKSTRUCT.flags
	llmhfInjected         = 0x01
	llmhfLowerILInjected  = 0x02
	llmhfInjectedAnyLevel = llmhfInjected | llmhfLowerILInjected
)

// kbdLLHookStruct mirrors KBDLLHOOKSTRUCT (24 bytes on 64-bit, 20 on 32-bit).
type kbdLLHookStruct struct {
	vkCode      uint32
	scanCode    uint32
	flags       uint32
	time        uint32
	dwExtraInfo uintptr
}

// msLLHookStruct mirrors MSLLHOOKSTRUCT (32 bytes on 64-bit, 24 on 32-bit).
type msLLHookStruct struct {
	ptX, ptY    int32
	mouseData   uint32
	flags       uint32
	time        uint32
	dwExtraInfo uintptr
}

// winMsg mirrors MSG; only used as a buffer for GetMessageW/PeekMessageW.
type winMsg struct {
	hwnd     uintptr
	message  uint32
	wParam   uintptr
	lParam   uintptr
	time     uint32
	ptX, ptY int32
	lPrivate uint32
}

// isPhysicalKeyboard reports whether a KBDLLHOOKSTRUCT.flags value describes
// input from a real device. Both the injected bit and the lower-integrity
// injected bit are treated as injected (fail closed).
func isPhysicalKeyboard(flags uint32) bool { return flags&llkhfInjectedAnyLevel == 0 }

// isPhysicalMouse is isPhysicalKeyboard for MSLLHOOKSTRUCT.flags.
func isPhysicalMouse(flags uint32) bool { return flags&llmhfInjectedAnyLevel == 0 }

// Hook state is process-wide: Windows callbacks created with NewCallback
// can never be freed, so there is exactly one keyboard and one mouse
// callback, and every hook installation shares the counters below.
var (
	// lastPhysicalTick is the GetTickCount64 value (ms) of the most recent
	// physical keyboard/mouse event seen by any installed hook. It only
	// ever moves forward.
	lastPhysicalTick atomic.Int64
	// Event counters, for diagnostics and tests.
	physicalEvents atomic.Uint64
	injectedEvents atomic.Uint64

	callbacksOnce sync.Once
	kbdCallback   uintptr
	mouseCallback uintptr
)

// notePhysical advances lastPhysicalTick to tick if tick is newer.
func notePhysical(tick int64) {
	for {
		cur := lastPhysicalTick.Load()
		if tick <= cur || lastPhysicalTick.CompareAndSwap(cur, tick) {
			return
		}
	}
}

func tickCount64() int64 {
	r, _, _ := procGetTickCount64.Call()
	return int64(r)
}

// The hook procedures must be minimal (Windows silently removes a
// low-level hook whose callback exceeds LowLevelHooksTimeout) and must
// always chain to CallNextHookEx.
func kbdHookProc(nCode uintptr, wParam uintptr, info *kbdLLHookStruct) uintptr {
	if int32(nCode) == hcAction && info != nil {
		if isPhysicalKeyboard(info.flags) {
			notePhysical(tickCount64())
			physicalEvents.Add(1)
		} else {
			injectedEvents.Add(1)
		}
	}
	r, _, _ := procCallNextHookEx.Call(0, nCode, wParam, uintptr(unsafe.Pointer(info)))
	return r
}

func mouseHookProc(nCode uintptr, wParam uintptr, info *msLLHookStruct) uintptr {
	if int32(nCode) == hcAction && info != nil {
		if isPhysicalMouse(info.flags) {
			notePhysical(tickCount64())
			physicalEvents.Add(1)
		} else {
			injectedEvents.Add(1)
		}
	}
	r, _, _ := procCallNextHookEx.Call(0, nCode, wParam, uintptr(unsafe.Pointer(info)))
	return r
}

// inputHooks owns one hook thread with a keyboard and a mouse LL hook.
type inputHooks struct {
	tid       uint32
	done      chan struct{}
	closeOnce sync.Once
}

// startInputHooks starts a goroutine locked to its OS thread, installs
// both low-level hooks there and pumps messages until close. It returns
// only after the hooks are installed (or installation failed).
func startInputHooks() (*inputHooks, error) {
	for _, p := range []*windows.LazyProc{procSetWindowsHookExW, procUnhookWindowsHookEx,
		procCallNextHookEx, procGetMessageW, procPeekMessageW, procPostThreadMessageW, procGetTickCount64} {
		if err := p.Find(); err != nil {
			return nil, fmt.Errorf("presence: %s unavailable: %w", p.Name, err)
		}
	}
	callbacksOnce.Do(func() {
		kbdCallback = windows.NewCallback(kbdHookProc)
		mouseCallback = windows.NewCallback(mouseHookProc)
	})

	h := &inputHooks{done: make(chan struct{})}
	ready := make(chan error, 1)
	go h.run(ready)
	if err := <-ready; err != nil {
		<-h.done
		return nil, err
	}
	return h, nil
}

func (h *inputHooks) run(ready chan<- error) {
	runtime.LockOSThread()
	// The thread is never unlocked: it exits with the goroutine, so no
	// other goroutine inherits its hook/message-queue state.
	defer close(h.done)

	h.tid = windows.GetCurrentThreadId()
	var msg winMsg
	// Force creation of this thread's message queue so that
	// PostThreadMessageW(WM_QUIT) from Close cannot fail.
	procPeekMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, wmUser, wmUser, pmNoRemove)

	var mod windows.Handle
	if err := windows.GetModuleHandleEx(0, nil, &mod); err != nil {
		ready <- fmt.Errorf("presence: GetModuleHandleEx: %w", err)
		return
	}
	kh, _, e := procSetWindowsHookExW.Call(whKeyboardLL, kbdCallback, uintptr(mod), 0)
	if kh == 0 {
		ready <- fmt.Errorf("presence: SetWindowsHookExW(WH_KEYBOARD_LL): %w", e)
		return
	}
	defer procUnhookWindowsHookEx.Call(kh)
	mh, _, e := procSetWindowsHookExW.Call(whMouseLL, mouseCallback, uintptr(mod), 0)
	if mh == 0 {
		ready <- fmt.Errorf("presence: SetWindowsHookExW(WH_MOUSE_LL): %w", e)
		return
	}
	defer procUnhookWindowsHookEx.Call(mh)
	ready <- nil

	// LL hook callbacks are delivered while this thread waits in
	// GetMessageW. It returns 0 on WM_QUIT and -1 on error.
	for {
		r, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			return
		}
	}
}

// close stops the message loop and removes the hooks. Safe to call more
// than once and from any goroutine.
func (h *inputHooks) close() error {
	var err error
	h.closeOnce.Do(func() {
		select {
		case <-h.done:
			return
		default:
		}
		r, _, e := procPostThreadMessageW.Call(uintptr(h.tid), wmQuit, 0, 0)
		if r == 0 {
			err = fmt.Errorf("presence: PostThreadMessageW(WM_QUIT): %w", e)
			return
		}
		<-h.done
	})
	return err
}

var errHooksClosed = errors.New("presence: input hooks closed")
