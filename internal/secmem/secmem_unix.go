//go:build unix

package secmem

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// allocNative maps fresh anonymous private pages and asks the OS to keep them
// resident with mlock. An mlock failure (commonly RLIMIT_MEMLOCK) is not
// fatal; it only clears the locked flag.
func allocNative(n int) (region, bool, error) {
	size := roundUp(n, unix.Getpagesize())
	mem, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return region{}, false, err
	}
	adviseNoDump(mem)
	locked := unix.Mlock(mem) == nil
	return region{mem: mem, native: true}, locked, nil
}

// freeNative unlocks and unmaps memory obtained from allocNative. The caller
// has already wiped it.
func freeNative(r region, locked bool) {
	if len(r.mem) == 0 {
		return
	}
	if locked {
		_ = unix.Munlock(r.mem)
	}
	_ = unix.Munmap(r.mem)
}

// HardenProcess disables core dumps for the process (RLIMIT_CORE = 0) and,
// on Linux, marks the process non-dumpable, which also blocks same-user
// ptrace attach.
func HardenProcess() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("secmem: disable core dumps: %w", err)
	}
	return hardenPlatform()
}
