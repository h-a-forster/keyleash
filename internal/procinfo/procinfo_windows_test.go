//go:build windows

package procinfo

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestMain lets the test binary act as a child process for descendant tests.
func TestMain(m *testing.M) {
	if os.Getenv("PROCINFO_HELPER") == "sleep" {
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func loopbackPair(t *testing.T, network, addr string) (server, client net.Conn) {
	t.Helper()
	ln, err := net.Listen(network, addr)
	if err != nil {
		t.Skipf("listen %s %s: %v", network, addr, err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			ch <- nil
			return
		}
		ch <- c
	}()
	client, err = net.Dial(network, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server = <-ch
	if server == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	return server, client
}

func addrPort(a net.Addr) netip.AddrPort { return a.(*net.TCPAddr).AddrPort() }

func TestPeerPIDLoopback(t *testing.T) {
	for _, tc := range []struct{ network, addr string }{
		{"tcp4", "127.0.0.1:0"},
		{"tcp6", "[::1]:0"},
	} {
		t.Run(tc.network, func(t *testing.T) {
			server, _ := loopbackPair(t, tc.network, tc.addr)
			pid, err := PeerPID(addrPort(server.LocalAddr()), addrPort(server.RemoteAddr()))
			if err != nil {
				t.Fatal(err)
			}
			if pid != os.Getpid() {
				t.Fatalf("PeerPID = %d, want %d", pid, os.Getpid())
			}
		})
	}
}

func TestPeerPIDUnknownConnection(t *testing.T) {
	server, _ := loopbackPair(t, "tcp4", "127.0.0.1:0")
	local := addrPort(server.LocalAddr())
	// Swapping the endpoints names the server side; a bogus port names nothing.
	bogus := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 1)
	if _, err := PeerPID(local, bogus); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestPeerPIDConcurrent(t *testing.T) {
	server, _ := loopbackPair(t, "tcp4", "127.0.0.1:0")
	l, r := addrPort(server.LocalAddr()), addrPort(server.RemoteAddr())
	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				pid, err := PeerPID(l, r)
				if err != nil {
					errs <- err
					return
				}
				if pid != os.Getpid() {
					errs <- errors.New("wrong pid")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestParseTablesSynthetic(t *testing.T) {
	// IPv4: one row 127.0.0.1:50000 -> 127.0.0.1:47114 owned by pid 4242.
	row := make([]byte, tcpRowOwnerPIDSize)
	binary.LittleEndian.PutUint32(row[0:], 5) // ESTABLISHED
	copy(row[4:8], []byte{127, 0, 0, 1})
	row[8], row[9] = 0xC3, 0x50 // 50000
	copy(row[12:16], []byte{127, 0, 0, 1})
	row[16], row[17] = 0xB8, 0x0A // 47114
	binary.LittleEndian.PutUint32(row[20:], 4242)
	buf := append([]byte{1, 0, 0, 0}, row...)
	rows, err := parseTCP4Table(buf)
	if err != nil || len(rows) != 1 {
		t.Fatalf("parse: %v %v", rows, err)
	}
	if rows[0].local.String() != "127.0.0.1:50000" || rows[0].remote.String() != "127.0.0.1:47114" || rows[0].pid != 4242 {
		t.Fatalf("row = %+v", rows[0])
	}
	pid, err := matchPeer(rows, netip.MustParseAddrPort("127.0.0.1:47114"), netip.MustParseAddrPort("127.0.0.1:50000"))
	if err != nil || pid != 4242 {
		t.Fatalf("matchPeer = %d, %v", pid, err)
	}

	// Malformed: claims more rows than present.
	bad := append([]byte{2, 0, 0, 0}, row...)
	if _, err := parseTCP4Table(bad); err == nil {
		t.Fatal("over-long count accepted")
	}
	if _, err := parseTCP4Table([]byte{1}); err == nil {
		t.Fatal("short buffer accepted")
	}
	if _, err := parseTCP6Table(append([]byte{1, 0, 0, 0}, make([]byte, 55)...)); err == nil {
		t.Fatal("short v6 row accepted")
	}

	// PID 0 rows (TIME_WAIT) never match.
	binary.LittleEndian.PutUint32(row[20:], 0)
	rows, _ = parseTCP4Table(append([]byte{1, 0, 0, 0}, row...))
	if _, err := matchPeer(rows, netip.MustParseAddrPort("127.0.0.1:47114"), netip.MustParseAddrPort("127.0.0.1:50000")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pid 0 matched: %v", err)
	}
}

func TestLookupSelf(t *testing.T) {
	p, err := Lookup(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	if !strings.EqualFold(p.Image, exe) {
		t.Errorf("Image = %q, want %q", p.Image, exe)
	}
	if p.ParentPID != os.Getppid() {
		t.Errorf("ParentPID = %d, want %d", p.ParentPID, os.Getppid())
	}
	if p.StartTime <= 0 || p.StartTime > time.Now().UnixNano() {
		t.Errorf("StartTime = %d", p.StartTime)
	}
}

func TestLookupMissing(t *testing.T) {
	// PIDs on Windows are multiples of 4; an odd huge one never exists.
	if _, err := Lookup(0x7ffffff1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestIsDescendantReal(t *testing.T) {
	self, err := Lookup(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := IsDescendant(self.PID, self); !ok || err != nil {
		t.Fatalf("IsDescendant(self, self) = %v, %v", ok, err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "PROCINFO_HELPER=sleep")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	childPID := cmd.Process.Pid

	if ok, err := IsDescendant(childPID, self); !ok || err != nil {
		t.Fatalf("IsDescendant(child, self) = %v, %v", ok, err)
	}
	child, err := Lookup(childPID)
	if err != nil {
		t.Fatal(err)
	}
	if child.ParentPID != self.PID {
		t.Errorf("child ParentPID = %d, want %d", child.ParentPID, self.PID)
	}
	if ok, err := IsDescendant(self.PID, child); ok || err != nil {
		t.Fatalf("IsDescendant(self, child) = %v, %v; want false", ok, err)
	}
	// Same PID, wrong start time: identity mismatch (simulated PID reuse).
	stale := self
	stale.StartTime--
	if ok, _ := IsDescendant(childPID, stale); ok {
		t.Fatal("stale ancestor identity accepted")
	}

	// After the child exits it is no longer anyone's descendant.
	cmd.Process.Kill()
	cmd.Wait()
	if ok, _ := IsDescendant(childPID, self); ok {
		t.Fatal("exited child still reported as descendant")
	}
}
