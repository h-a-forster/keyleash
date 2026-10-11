//go:build freebsd

package daemon

import (
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/unix"
)

// connPeerPID returns the PID of the peer of an admin socket connection
// (LOCAL_PEERCRED). FreeBSD 13 and later report the peer's pid in the
// union that ends struct xucred (cr_pid); older kernels leave it zero,
// and the caller is then treated as unidentified (confined).
func connPeerPID(c net.Conn) (int, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, errors.New("keyleash: admin connection is not a unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, err
	}
	var x *unix.Xucred
	var cerr error
	if err := raw.Control(func(fd uintptr) {
		x, cerr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	}); err != nil {
		return 0, err
	}
	if cerr != nil {
		return 0, cerr
	}
	if x == nil || x.Version != 0 { // XUCRED_VERSION
		return 0, errors.New("keyleash: unexpected xucred version")
	}
	// The union { void *_cr_unused1; pid_t cr_pid; } is the last field.
	off := unsafe.Sizeof(*x) - unsafe.Sizeof(uintptr(0))
	pid := int(*(*int32)(unsafe.Add(unsafe.Pointer(x), off)))
	if pid <= 0 {
		return 0, errors.New("keyleash: admin socket peer pid unknown")
	}
	return pid, nil
}
