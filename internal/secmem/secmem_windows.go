//go:build windows

package secmem

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// allocNative reserves and commits fresh pages with VirtualAlloc and asks the
// OS to keep them resident with VirtualLock. A VirtualLock failure is not
// fatal; it only clears the locked flag.
func allocNative(n int) (region, bool, error) {
	size := roundUp(n, windows.Getpagesize())
	addr, err := windows.VirtualAlloc(0, uintptr(size), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return region{}, false, err
	}
	// Convert the OS address to a pointer without tripping vet's unsafeptr
	// check: the memory is not managed by the Go GC, so this is sound.
	p := *(*unsafe.Pointer)(unsafe.Pointer(&addr))
	mem := unsafe.Slice((*byte)(p), size)
	locked := windows.VirtualLock(addr, uintptr(size)) == nil
	return region{mem: mem, native: true}, locked, nil
}

// freeNative unlocks and releases memory obtained from allocNative. The
// caller has already wiped it.
func freeNative(r region, locked bool) {
	if len(r.mem) == 0 {
		return
	}
	addr := uintptr(unsafe.Pointer(unsafe.SliceData(r.mem)))
	if locked {
		_ = windows.VirtualUnlock(addr, uintptr(len(r.mem)))
	}
	_ = windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
}

// HardenProcess reduces the chance that key material leaves the process via
// crash reporting. On Windows it sets the process error mode so faults do
// not raise the Windows Error Reporting UI or critical-error dialogs
// (SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX), keeping any mode bits
// already set.
//
// It deliberately does not call WerAddExcludedApplication: that writes a
// persistent per-user registry setting, which is outside the scope of a
// process-level hardening call. A system-wide WER LocalDumps policy set by an
// administrator can still capture dumps; that attacker is out of scope.
func HardenProcess() error {
	const want = windows.SEM_FAILCRITICALERRORS | windows.SEM_NOGPFAULTERRORBOX
	// SetErrorMode returns the previous mode; set once to read it, then
	// merge so we never clear bits another component relied on.
	prev := windows.SetErrorMode(want)
	windows.SetErrorMode(prev | want)
	return nil
}
