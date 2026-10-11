//go:build windows

package runjob

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/procinfo"
)

// The test binary doubles as the helper processes:
//
//	chain: wait for a line on stdin, start "spawn" and wait for it, print the
//	       grandchild's pid, then wait for stdin to close;
//	spawn: start "sleep", print its pid and exit at once (orphaning it);
//	sleep: sleep for a minute.
func TestMain(m *testing.M) {
	switch os.Getenv("RUNJOB_HELPER") {
	case "chain":
		r := bufio.NewReader(os.Stdin)
		if _, err := r.ReadString('\n'); err != nil {
			os.Exit(2)
		}
		out, err := helper("spawn").Output()
		if err != nil {
			os.Exit(3)
		}
		fmt.Print(string(out))
		_, _ = r.ReadString('\n')
		os.Exit(0)
	case "spawn":
		c := helper("sleep")
		if err := c.Start(); err != nil {
			os.Exit(4)
		}
		fmt.Println(c.Process.Pid)
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helper(mode string) *exec.Cmd {
	c := exec.Command(os.Args[0], "-test.run=^$")
	c.Env = append(os.Environ(), "RUNJOB_HELPER="+mode)
	return c
}

// TestJobConfinesOrphanedDescendants replays finding A: a grandchild whose
// parent exited is no longer a descendant by the parent-chain walk, but it
// is still in the run pass's job, so it stays confined; a process outside
// is not a member; the job outlives the pass while members live; closing a
// kill-on-close manager ends the members.
func TestJobConfinesOrphanedDescendants(t *testing.T) {
	m := New(true)
	if m == nil {
		t.Skip("job objects unavailable")
	}
	defer m.Close()

	b := helper("chain")
	stdin, err := b.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := b.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { stdin.Close(); _ = b.Process.Kill(); _ = b.Wait() }()
	bp, err := procinfo.Lookup(b.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Confine("p_run", bp.PID, bp.StartTime+1); err == nil {
		t.Fatal("confined a process whose start time does not match")
	}
	if err := m.Confine("p_run", bp.PID, bp.StartTime); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte("go\n")); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	gpid, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("grandchild pid %q", line)
	}
	defer func() {
		if p, err := os.FindProcess(gpid); err == nil {
			_ = p.Kill()
		}
	}()

	// The intermediate parent has exited: the parent walk cannot connect
	// the grandchild to the bound process any more (the old fail-open).
	if ok, err := procinfo.IsDescendant(gpid, bp); err != nil || ok {
		t.Fatalf("parent walk: %v %v (expected a broken chain)", ok, err)
	}
	if in, err := m.Member("p_run", gpid); err != nil || !in {
		t.Fatalf("orphaned grandchild not in the job: %v %v", in, err)
	}
	if in, err := m.MemberOfAny(gpid); err != nil || !in {
		t.Fatalf("MemberOfAny(grandchild) = %v %v", in, err)
	}
	if in, err := m.MemberOfAny(os.Getpid()); err != nil || in {
		t.Fatalf("the test process is in the job: %v %v", in, err)
	}
	if _, err := m.Member("other", gpid); !errors.Is(err, ErrNoJob) {
		t.Fatalf("unknown job: %v", err)
	}

	// The pass ends but members live: the job keeps confining them.
	m.Sweep(func(string) bool { return false })
	if m.Len() != 1 {
		t.Fatal("job released while members are alive")
	}
	if in, _ := m.MemberOfAny(gpid); !in {
		t.Fatal("orphan no longer confined after its pass ended")
	}

	// Closing the manager (the daemon exiting) ends the members.
	m.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := procinfo.Lookup(gpid); errors.Is(err, procinfo.ErrNotFound) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("grandchild survived the job closing (kill on close)")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
