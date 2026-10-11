//go:build !windows

package procinfo

import "net/netip"

// Non-Windows platforms have no implementation yet (Linux /proc/net/tcp and
// macOS libproc are later phases). Every call fails with ErrUnsupported, so
// process-bound passes are rejected rather than silently unbound.

func peerPID(local, remote netip.AddrPort) (int, error) { return 0, ErrUnsupported }

func lookup(pid int) (Process, error) { return Process{}, ErrUnsupported }

func isDescendant(pid int, ancestor Process) (bool, error) { return false, ErrUnsupported }
