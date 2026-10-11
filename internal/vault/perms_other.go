//go:build !windows

package vault

import "os"

// restrictPath sets owner-only permissions: 0700 for directories, 0600 for
// files.
func restrictPath(path string, dir bool) error {
	mode := os.FileMode(0o600)
	if dir {
		mode = 0o700
	}
	return os.Chmod(path, mode)
}

// syncDir fsyncs a directory so a rename inside it is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
