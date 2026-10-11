//go:build windows

package daemon

import (
	"errors"
	"net"

	"golang.org/x/sys/windows"
)

// connPeerPID returns the PID of the client process of an admin pipe
// connection (GetNamedPipeClientProcessId on the server end's handle).
func connPeerPID(c net.Conn) (int, error) {
	f, ok := c.(interface{ Fd() uintptr })
	if !ok {
		return 0, errors.New("keyleash: admin connection exposes no pipe handle")
	}
	var pid uint32
	if err := windows.GetNamedPipeClientProcessId(windows.Handle(f.Fd()), &pid); err != nil {
		return 0, err
	}
	if pid == 0 {
		return 0, errors.New("keyleash: admin pipe client pid unknown")
	}
	return int(pid), nil
}
