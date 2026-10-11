//go:build !windows

package daemon

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// acquireInstanceLock takes an exclusive, non-blocking flock on path. The
// lock is released when the file is closed or the process exits.
func acquireInstanceLock(path string) (io.Closer, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("keyleash: instance lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errors.New("keyleash: another keyleash daemon is already running for this data directory")
		}
		return nil, fmt.Errorf("keyleash: instance lock: %w", err)
	}
	return f, nil
}
