//go:build windows

package vault

import (
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// checkOwnerOnly asserts a protected DACL with exactly two allow ACEs: the
// current user and SYSTEM.
func checkOwnerOnly(t *testing.T, path string, dir bool) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sddl, "D:P") {
		t.Fatalf("DACL not protected: %s", sddl)
	}
	aces := strings.Split(strings.TrimPrefix(sddl[strings.Index(sddl, "("):], "("), "(")
	if len(aces) == 0 || (!dir && len(aces) != 2) {
		t.Fatalf("unexpected ACE count: %s", sddl)
	}
	for _, ace := range aces {
		f := strings.Split(strings.TrimSuffix(ace, ")"), ";")
		if len(f) != 6 || f[0] != "A" {
			t.Fatalf("unexpected ACE %q in %s", ace, sddl)
		}
		if trustee := f[5]; trustee != user.User.Sid.String() && trustee != "SY" {
			t.Fatalf("unexpected trustee %q in %s", trustee, sddl)
		}
	}
	if strings.Contains(sddl, "(D;") {
		t.Fatalf("unexpected deny ACE: %s", sddl)
	}
}
