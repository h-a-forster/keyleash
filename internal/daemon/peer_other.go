//go:build !windows && !linux && !darwin && !freebsd

package daemon

import (
	"errors"
	"net"
)

// connPeerPID is not implemented here (OpenBSD and NetBSD have no portable
// peer-PID option in x/sys; SO_PEERCRED/LOCAL_PEEREID are not wrapped):
// callers are treated as unidentified, hence confined, for
// mutating admin calls (spec §12).
func connPeerPID(net.Conn) (int, error) {
	return 0, errors.ErrUnsupported
}
