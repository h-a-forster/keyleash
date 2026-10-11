//go:build windows

package daemon

import (
	"context"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/h-a-forster/keyleash/internal/client"
)

func TestAdminSDDL(t *testing.T) {
	sid, err := client.CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	got := AdminSDDL(sid)
	want := "O:" + sid + "D:P(A;;GA;;;" + sid + ")"
	if got != want {
		t.Fatalf("AdminSDDL = %q, want %q", got, want)
	}
	for _, bad := range []string{"WD", "NU", "AN", "BU", "AU", "IU"} {
		if strings.Contains(got, ";;;"+bad+")") {
			t.Fatalf("descriptor grants %s: %s", bad, got)
		}
	}
	sd, err := windows.SecurityDescriptorFromString(got)
	if err != nil {
		t.Fatalf("descriptor does not parse: %v", err)
	}
	if !sd.IsValid() {
		t.Fatal("descriptor invalid")
	}
}

// TestAdminPipeOwnerOnly creates the real admin pipe (under a unique test
// name), talks to a daemon through it, and checks the pipe object's actual
// owner and DACL.
func TestAdminPipeOwnerOnly(t *testing.T) {
	sid, err := client.CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	name := client.PipePrefix + sid + "-test-" + newID("")
	ln, err := listenPipe(name, sid)
	if err != nil {
		t.Fatal(err)
	}
	// A second listener on the same name must fail (no squatting/sharing).
	if ln2, err := listenPipe(name, sid); err == nil {
		ln2.Close()
		t.Fatal("second pipe instance with the same name was allowed")
	}

	e := &env{t: t, dir: t.TempDir(), clk: newFakeClock(), pres: &fakePresence{}, appr: &switchApprover{}}
	e.cfg = testConfig(t)
	if _, err := Init(e.dir, InitOptions{Method: "passphrase", Passphrase: testPassphrase}); err != nil {
		t.Fatal(err)
	}
	e.up = newUpstream(t)
	e.adminLn = ln
	e.start()
	pc := client.New(func(ctx context.Context) (netConn, error) { return client.DialPipe(ctx, name) })
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := pc.Status(ctx); err != nil {
		t.Fatalf("status over pipe: %v", err)
	}
	if _, err := pc.Unlock(ctx, client.MethodPassphrase, testPassphrase); err != nil {
		t.Fatalf("unlock over pipe: %v", err)
	}

	// Inspect the pipe object itself.
	conn, err := client.DialPipe(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	h := windows.Handle(conn.(interface{ Fd() uintptr }).Fd())
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner.String() != sid {
		t.Fatalf("owner = %v (%v), want %s", owner, err, sid)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("dacl: %v", err)
	}
	if dacl.AceCount != 1 {
		t.Fatalf("DACL has %d ACEs, want exactly 1 (%s)", dacl.AceCount, sd.String())
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil {
		t.Fatal(err)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || aceSID.String() != sid {
		t.Fatalf("ACE = type %d sid %s", ace.Header.AceType, aceSID)
	}
	// GENERIC_ALL is mapped to the pipe's specific full-access rights.
	if ace.Mask&fileAllAccess != fileAllAccess && ace.Mask&windows.GENERIC_ALL == 0 {
		t.Fatalf("ACE mask %#x does not grant full access to the owner", ace.Mask)
	}
}

// fileAllAccess is FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF).
const fileAllAccess = 0x1F01FF
