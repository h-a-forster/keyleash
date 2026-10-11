//go:build !windows

package vault

import (
	"os"
	"testing"
)

// checkOwnerOnly asserts mode 0700 for directories and 0600 for files.
func checkOwnerOnly(t *testing.T, path string, dir bool) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	want := os.FileMode(0o600)
	if dir {
		want = 0o700
	}
	if st.Mode().Perm() != want {
		t.Fatalf("%s mode %v, want %v", path, st.Mode().Perm(), want)
	}
}
