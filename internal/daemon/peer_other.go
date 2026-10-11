//go:build !windows && !linux && !darwin

package daemon

import (
	"errors"
	"net"
)

// connPeerPID is not implemented here: callers are treated as confined for
// mutating admin calls (spec §12).
func connPeerPID(net.Conn) (int, error) {
	return 0, errors.ErrUnsupported
}
