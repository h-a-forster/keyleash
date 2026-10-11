// Package procinfo answers "which local process is on the other end of this
// loopback connection, and is it a descendant of a given process?".
//
// It backs pass process-binding (spec §6 bind) and per-request attribution
// (spec §10.5). On Windows it uses the TCP owner table (GetExtendedTcpTable),
// OpenProcess/QueryFullProcessImageName/GetProcessTimes and a Toolhelp
// process snapshot. Other platforms currently return ErrUnsupported, so
// callers that require binding fail closed there.
package procinfo

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrNotFound is returned when no process matches the query: no TCP row
// owns the connection, or the PID does not exist (any more).
var ErrNotFound = errors.New("procinfo: not found")

// ErrUnsupported is returned on platforms without an implementation.
var ErrUnsupported = errors.New("procinfo: not supported on this platform")

// Process identifies a running process. PID alone is not an identity because
// PIDs are reused; (PID, StartTime) is.
type Process struct {
	// PID is the process id.
	PID int
	// ParentPID is the id of the process that created it at creation time.
	// The parent may have exited and its PID may have been reused since.
	ParentPID int
	// Image is the full path of the executable (may be empty if the OS
	// refused to reveal it).
	Image string
	// StartTime is the process creation time in Unix nanoseconds
	// (Windows resolution: 100 ns). Zero means unknown.
	StartTime int64
}

// String renders the process for logs and audit records. It contains no
// secrets.
func (p Process) String() string {
	return fmt.Sprintf("pid=%d ppid=%d image=%q", p.PID, p.ParentPID, p.Image)
}

// PeerPID returns the PID owning the client end of a loopback TCP
// connection. local is the server-side address (what the listener's
// net.Conn.LocalAddr reports) and remote is the client-side address
// (net.Conn.RemoteAddr). The row searched for is the one whose local
// endpoint equals remote and whose remote endpoint equals local.
//
// IPv4-mapped IPv6 addresses are unmapped first. Returns ErrNotFound when no
// owning row exists (for example the client already closed the connection).
func PeerPID(local, remote netip.AddrPort) (int, error) {
	if !local.IsValid() || !remote.IsValid() {
		return 0, errors.New("procinfo: invalid address")
	}
	local = unmap(local)
	remote = unmap(remote)
	if local.Addr().Is4() != remote.Addr().Is4() {
		return 0, errors.New("procinfo: address family mismatch")
	}
	return peerPID(local, remote)
}

// Lookup returns the identity of a running process.
func Lookup(pid int) (Process, error) {
	if pid <= 0 {
		return Process{}, fmt.Errorf("procinfo: invalid pid %d", pid)
	}
	return lookup(pid)
}

// IsDescendant reports whether the process pid is ancestor itself or one of
// its descendants. Identity is (PID, StartTime): ancestor.StartTime must be
// known (non-zero) or the answer is false.
//
// The walk follows parent PIDs and stops (answering false) when a parent has
// exited, when a "parent" started after its child (the PID was reused, so it
// is not the real parent), or when a cycle is detected. Intermediate
// processes that have exited therefore break the chain: this errs on the
// side of denying.
func IsDescendant(pid int, ancestor Process) (bool, error) {
	if pid <= 0 || ancestor.PID <= 0 || ancestor.StartTime == 0 {
		return false, nil
	}
	return isDescendant(pid, ancestor)
}

// walkTable is the data IsDescendant needs, abstracted so the walk can be
// unit-tested without real processes.
type walkTable interface {
	// parent returns the recorded parent PID of pid, or ok=false if pid is
	// not running.
	parent(pid int) (ppid int, ok bool)
	// startTime returns the creation time of a running pid, or an error.
	startTime(pid int) (int64, error)
}

// maxDepth bounds the parent walk; real process trees are far shallower.
const maxDepth = 1024

// walk implements IsDescendant over a walkTable.
func walk(t walkTable, pid int, ancestor Process) (bool, error) {
	cur := pid
	curStart, err := t.startTime(cur)
	if err != nil {
		return false, err
	}
	seen := make(map[int]bool)
	for depth := 0; depth < maxDepth; depth++ {
		if cur == ancestor.PID {
			return curStart == ancestor.StartTime, nil
		}
		if seen[cur] {
			return false, nil // cycle
		}
		seen[cur] = true
		ppid, ok := t.parent(cur)
		if !ok || ppid <= 0 || ppid == cur {
			return false, nil
		}
		pStart, err := t.startTime(ppid)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				return false, nil // parent exited: chain broken
			}
			return false, err
		}
		// A parent cannot start after its child: the PID was reused.
		if pStart == 0 || pStart > curStart {
			return false, nil
		}
		cur, curStart = ppid, pStart
	}
	return false, nil
}

func unmap(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}
