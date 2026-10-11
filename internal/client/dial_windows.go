//go:build windows

package client

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

// PipePrefix is the admin pipe name prefix; the full name appends the
// current user's SID (spec §12).
const PipePrefix = `\\.\pipe\keyleash-`

// CurrentUserSID returns the string SID of the user running this process.
func CurrentUserSID() (string, error) {
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("keyleash: current user SID: %w", err)
	}
	return tu.User.Sid.String(), nil
}

// PipeName returns the admin pipe name for the current user.
func PipeName() (string, error) {
	sid, err := CurrentUserSID()
	if err != nil {
		return "", err
	}
	return PipePrefix + sid, nil
}

// ErrPipeOwner is returned when the admin pipe is not owned by the current
// user (another account created it first): nothing is sent over it.
var ErrPipeOwner = errors.New("keyleash client: admin pipe is not owned by the current user; refusing to use it")

func adminDialer(string) (DialFunc, error) {
	name, err := PipeName()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context) (net.Conn, error) { return DialPipe(ctx, name) }, nil
}

// DialPipe connects to the named pipe name and verifies, on the connected
// handle itself, that the pipe object is owned by the current user before
// returning it. The client uses anonymous impersonation level, so the server
// cannot impersonate it.
func DialPipe(ctx context.Context, name string) (net.Conn, error) {
	conn, err := winio.DialPipeAccessImpLevel(ctx, name,
		uint32(windows.GENERIC_READ|windows.GENERIC_WRITE), winio.PipeImpLevelAnonymous)
	if err != nil {
		return nil, err
	}
	fd, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		conn.Close()
		return nil, errors.New("keyleash client: cannot inspect the admin pipe handle")
	}
	if err := checkOwner(windows.Handle(fd.Fd())); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// checkOwner fails unless the kernel object behind h is owned by the
// current user's SID.
func checkOwner(h windows.Handle) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("keyleash client: read admin pipe owner: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return ErrPipeOwner
	}
	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("keyleash client: current user SID: %w", err)
	}
	if !owner.Equals(tu.User.Sid) {
		return ErrPipeOwner
	}
	return nil
}
