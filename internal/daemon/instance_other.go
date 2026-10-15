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

// instanceLockHeld reports whether a daemon holds the instance lock at path
// (its exclusive flock makes a shared, non-blocking one fail).
func instanceLockHeld(path string) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return true, nil
		}
		return false, err
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return false, nil
}
