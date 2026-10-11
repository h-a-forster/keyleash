//go:build !windows

package main

import (
	"fmt"
	"os"
)

// checkPrivateDir verifies that dir is not accessible to group or others.
func checkPrivateDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("mode %04o allows group/other access (want 0700)", perm)
	}
	return nil
}
