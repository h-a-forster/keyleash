//go:build darwin

package daemon

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// connPeerPID returns the PID of the peer of an admin socket connection
// (LOCAL_PEERPID).
func connPeerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("keyleash: admin connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var pid int
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		pid, cerr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	if pid <= 0 {
		return 0, errors.New("keyleash: admin socket peer pid unknown")
	}
	return pid, nil
}
