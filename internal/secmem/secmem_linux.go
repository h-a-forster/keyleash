//go:build linux

package secmem

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// adviseNoDump excludes the pages from core dumps (best effort).
func adviseNoDump(mem []byte) {
	_ = unix.Madvise(mem, unix.MADV_DONTDUMP)
}

// hardenPlatform clears the dumpable flag so the kernel writes no core file
// and same-user processes cannot ptrace-attach.
func hardenPlatform() error {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("secmem: clear dumpable flag: %w", err)
	}
	return nil
}
