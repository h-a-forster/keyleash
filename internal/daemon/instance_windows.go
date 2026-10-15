//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// acquireInstanceLock opens path with no sharing, so a second daemon's open
// fails until this handle is closed (also on crash: the OS closes it).
func acquireInstanceLock(path string) (io.Closer, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil,
		windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, errors.New("keyleash: another keyleash daemon is already running for this data directory")
		}
		return nil, fmt.Errorf("keyleash: instance lock: %w", err)
	}
	return os.NewFile(uintptr(h), path), nil
}

// instanceLockHeld reports whether a daemon holds the instance lock at path:
// its handle allows no sharing, so any other open fails with a sharing
// violation while it is held.
func instanceLockHeld(path string) (bool, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	switch {
	case err == nil:
		windows.CloseHandle(h)
		return false, nil
	case errors.Is(err, windows.ERROR_SHARING_VIOLATION):
		return true, nil
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND):
		return false, nil
	}
	return false, err
}
