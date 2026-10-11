//go:build windows

package procinfo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modIphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	afInet               = 2
	afInet6              = 23
	tcpTableOwnerPIDAll  = 5
	tcpRowOwnerPIDSize   = 24 // MIB_TCPROW_OWNER_PID
	tcp6RowOwnerPIDSize  = 56 // MIB_TCP6ROW_OWNER_PID
	tcpTableHeaderSize   = 4  // DWORD dwNumEntries
	maxTCPTableAttempts  = 8
	maxTCPTableSizeBytes = 64 << 20
)

// getTCPTable fetches the raw TCP_TABLE_OWNER_PID_ALL table for one family.
func getTCPTable(family uint32) ([]byte, error) {
	if err := procGetExtendedTcpTable.Find(); err != nil {
		return nil, fmt.Errorf("procinfo: GetExtendedTcpTable unavailable: %w", err)
	}
	size := uint32(16 << 10)
	for attempt := 0; attempt < maxTCPTableAttempts; attempt++ {
		if size > maxTCPTableSizeBytes {
			return nil, errors.New("procinfo: TCP table too large")
		}
		// Back the buffer with uint64s so it is 8-byte aligned.
		words := make([]uint64, (size+7)/8)
		buf := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(words)*8)
		n := uint32(len(buf))
		r, _, _ := procGetExtendedTcpTable.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&n)),
			0, // unsorted
			uintptr(family),
			tcpTableOwnerPIDAll,
			0,
		)
		switch windows.Errno(r) {
		case 0:
			if n > uint32(len(buf)) {
				n = uint32(len(buf))
			}
			return buf[:n], nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			// The table can grow between calls; add headroom.
			size = n + n/4 + 1024
			continue
		default:
			return nil, fmt.Errorf("procinfo: GetExtendedTcpTable: %w", windows.Errno(r))
		}
	}
	return nil, errors.New("procinfo: TCP table kept growing")
}

// tcpRow is one parsed owner-PID row.
type tcpRow struct {
	local, remote netip.AddrPort
	pid           int
}

// parsePort decodes a DWORD port field stored in network byte order in its
// low two bytes.
func parsePort(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

// parseTCP4Table parses a MIB_TCPTABLE_OWNER_PID buffer.
func parseTCP4Table(buf []byte) ([]tcpRow, error) {
	return parseTable(buf, tcpRowOwnerPIDSize, func(r []byte) tcpRow {
		la := netip.AddrFrom4([4]byte(r[4:8]))
		ra := netip.AddrFrom4([4]byte(r[12:16]))
		return tcpRow{
			local:  netip.AddrPortFrom(la, parsePort(r[8:12])),
			remote: netip.AddrPortFrom(ra, parsePort(r[16:20])),
			pid:    int(binary.LittleEndian.Uint32(r[20:24])),
		}
	})
}

// parseTCP6Table parses a MIB_TCP6TABLE_OWNER_PID buffer.
func parseTCP6Table(buf []byte) ([]tcpRow, error) {
	return parseTable(buf, tcp6RowOwnerPIDSize, func(r []byte) tcpRow {
		la := netip.AddrFrom16([16]byte(r[0:16]))
		ra := netip.AddrFrom16([16]byte(r[24:40]))
		return tcpRow{
			local:  netip.AddrPortFrom(la, parsePort(r[20:24])),
			remote: netip.AddrPortFrom(ra, parsePort(r[44:48])),
			pid:    int(binary.LittleEndian.Uint32(r[52:56])),
		}
	})
}

func parseTable(buf []byte, rowSize int, parse func([]byte) tcpRow) ([]tcpRow, error) {
	if len(buf) < tcpTableHeaderSize {
		return nil, errors.New("procinfo: short TCP table")
	}
	n := int(binary.LittleEndian.Uint32(buf[:4]))
	body := buf[tcpTableHeaderSize:]
	if n < 0 || n > len(body)/rowSize {
		return nil, errors.New("procinfo: malformed TCP table")
	}
	rows := make([]tcpRow, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, parse(body[i*rowSize:(i+1)*rowSize]))
	}
	return rows, nil
}

// matchPeer finds the row of the client side of the connection.
func matchPeer(rows []tcpRow, local, remote netip.AddrPort) (int, error) {
	for _, r := range rows {
		if unmap(r.local) == remote && unmap(r.remote) == local {
			if r.pid <= 0 {
				return 0, ErrNotFound // e.g. TIME_WAIT rows owned by PID 0
			}
			return r.pid, nil
		}
	}
	return 0, ErrNotFound
}

func peerPID(local, remote netip.AddrPort) (int, error) {
	var (
		buf  []byte
		rows []tcpRow
		err  error
	)
	if local.Addr().Is4() {
		if buf, err = getTCPTable(afInet); err != nil {
			return 0, err
		}
		rows, err = parseTCP4Table(buf)
	} else {
		if buf, err = getTCPTable(afInet6); err != nil {
			return 0, err
		}
		rows, err = parseTCP6Table(buf)
	}
	if err != nil {
		return 0, err
	}
	return matchPeer(rows, local, remote)
}

// openErr maps OpenProcess failures for a vanished PID to ErrNotFound.
func openErr(pid int, err error) error {
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return fmt.Errorf("procinfo: pid %d: %w", pid, ErrNotFound)
	}
	return fmt.Errorf("procinfo: open pid %d: %w", pid, err)
}

// processStart returns the creation time of pid in Unix nanoseconds, and
// the open handle's image path if wantImage is set.
func processStart(pid int, wantImage bool) (start int64, image string, err error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return 0, "", openErr(pid, err)
	}
	defer windows.CloseHandle(h)

	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0, "", fmt.Errorf("procinfo: GetProcessTimes pid %d: %w", pid, err)
	}
	// A handle can be opened to a process that has exited but whose object
	// is still referenced; treat that as gone.
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err == nil && code != 259 /* STILL_ACTIVE */ {
		return 0, "", fmt.Errorf("procinfo: pid %d exited: %w", pid, ErrNotFound)
	}
	start = creation.Nanoseconds()
	if wantImage {
		image = imageName(h)
	}
	return start, image, nil
}

func imageName(h windows.Handle) string {
	n := uint32(windows.MAX_LONG_PATH)
	buf := make([]uint16, n)
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

// snapshotParents returns pid → parent pid for all running processes.
func snapshotParents() (map[int]int, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("procinfo: process snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)
	m := make(map[int]int, 256)
	var e windows.ProcessEntry32
	e.Size = uint32(unsafe.Sizeof(e))
	err = windows.Process32First(snap, &e)
	for err == nil {
		m[int(e.ProcessID)] = int(e.ParentProcessID)
		err = windows.Process32Next(snap, &e)
	}
	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, fmt.Errorf("procinfo: process snapshot walk: %w", err)
	}
	return m, nil
}

func lookup(pid int) (Process, error) {
	start, image, err := processStart(pid, true)
	if err != nil {
		return Process{}, err
	}
	parents, err := snapshotParents()
	if err != nil {
		return Process{}, err
	}
	ppid, ok := parents[pid]
	if !ok {
		return Process{}, fmt.Errorf("procinfo: pid %d: %w", pid, ErrNotFound)
	}
	return Process{PID: pid, ParentPID: ppid, Image: image, StartTime: start}, nil
}

// osTable is the live walkTable.
type osTable struct{ parents map[int]int }

func (t osTable) parent(pid int) (int, bool) {
	p, ok := t.parents[pid]
	return p, ok
}

func (t osTable) startTime(pid int) (int64, error) {
	s, _, err := processStart(pid, false)
	return s, err
}

func isDescendant(pid int, ancestor Process) (bool, error) {
	parents, err := snapshotParents()
	if err != nil {
		return false, err
	}
	return walk(osTable{parents: parents}, pid, ancestor)
}
