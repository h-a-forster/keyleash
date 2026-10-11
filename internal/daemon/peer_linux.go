//go:build linux

package daemon

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// connPeerPID returns the PID of the peer of an admin socket connection
// (SO_PEERCRED).
func connPeerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("keyleash: admin connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	if cred.Pid <= 0 {
		return 0, errors.New("keyleash: admin socket peer pid unknown")
	}
	return int(cred.Pid), nil
}
