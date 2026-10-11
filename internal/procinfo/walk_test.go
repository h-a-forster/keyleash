package procinfo

import (
	"errors"
	"net/netip"
	"testing"
)

type fakeProc struct {
	ppid  int
	start int64
}

type fakeTable struct {
	procs  map[int]fakeProc
	errPID int
}

func (f fakeTable) parent(pid int) (int, bool) {
	p, ok := f.procs[pid]
	return p.ppid, ok
}

func (f fakeTable) startTime(pid int) (int64, error) {
	if pid == f.errPID {
		return 0, errors.New("access denied")
	}
	p, ok := f.procs[pid]
	if !ok {
		return 0, ErrNotFound
	}
	return p.start, nil
}

func TestWalk(t *testing.T) {
	tree := map[int]fakeProc{
		1:  {ppid: 0, start: 10},
		10: {ppid: 1, start: 100}, // ancestor
		20: {ppid: 10, start: 200},
		30: {ppid: 20, start: 300}, // grandchild
		40: {ppid: 99, start: 400}, // parent exited
		50: {ppid: 60, start: 500}, // parent 60 started after child: PID reuse
		60: {ppid: 10, start: 600},
		70: {ppid: 80, start: 700}, // cycle 70 <-> 80
		80: {ppid: 70, start: 650},
		90: {ppid: 90, start: 900}, // self-parent
		95: {ppid: 1, start: 50},   // unrelated, older than ancestor
	}
	anc := Process{PID: 10, StartTime: 100}
	tests := []struct {
		name   string
		table  fakeTable
		pid    int
		anc    Process
		want   bool
		hasErr bool
	}{
		{"self", fakeTable{procs: tree}, 10, anc, true, false},
		{"child", fakeTable{procs: tree}, 20, anc, true, false},
		{"grandchild", fakeTable{procs: tree}, 30, anc, true, false},
		{"unrelated", fakeTable{procs: tree}, 95, anc, false, false},
		{"parent exited", fakeTable{procs: tree}, 40, anc, false, false},
		{"pid reuse of parent", fakeTable{procs: tree}, 50, anc, false, false},
		{"cycle", fakeTable{procs: tree}, 70, anc, false, false},
		{"self parent", fakeTable{procs: tree}, 90, anc, false, false},
		{"ancestor pid reused", fakeTable{procs: tree}, 30, Process{PID: 10, StartTime: 99}, false, false},
		{"ancestor itself not running", fakeTable{procs: tree}, 1234, anc, false, true},
		{"access denied mid-walk", fakeTable{procs: tree, errPID: 20}, 30, anc, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := walk(tc.table, tc.pid, tc.anc)
			if (err != nil) != tc.hasErr {
				t.Fatalf("err = %v, want error %v", err, tc.hasErr)
			}
			if got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsDescendantRejectsIncompleteIdentity(t *testing.T) {
	cases := []struct {
		pid int
		anc Process
	}{
		{0, Process{PID: 1, StartTime: 1}},
		{-5, Process{PID: 1, StartTime: 1}},
		{1, Process{PID: 0, StartTime: 1}},
		{1, Process{PID: 1, StartTime: 0}}, // unknown start time: no PID-only trust
	}
	for _, c := range cases {
		ok, err := IsDescendant(c.pid, c.anc)
		if ok || err != nil {
			t.Errorf("IsDescendant(%d, %+v) = %v, %v; want false, nil", c.pid, c.anc, ok, err)
		}
	}
}

func TestPeerPIDInvalid(t *testing.T) {
	v4 := netip.MustParseAddrPort("127.0.0.1:1")
	v6 := netip.MustParseAddrPort("[::1]:1")
	if _, err := PeerPID(netip.AddrPort{}, v4); err == nil {
		t.Error("zero local accepted")
	}
	if _, err := PeerPID(v4, v6); err == nil {
		t.Error("family mismatch accepted")
	}
	if _, err := Lookup(0); err == nil {
		t.Error("Lookup(0) accepted")
	}
}

func TestProcessStringHasNoSurprises(t *testing.T) {
	s := Process{PID: 1, ParentPID: 2, Image: `C:\x.exe`, StartTime: 3}.String()
	if s != `pid=1 ppid=2 image="C:\\x.exe"` {
		t.Fatalf("String() = %s", s)
	}
}
