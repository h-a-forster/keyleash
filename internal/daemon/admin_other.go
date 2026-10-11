//go:build !windows

package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"

	"github.com/h-a-forster/keyleash/internal/client"
)

// listenAdmin listens on <data>/admin.sock with mode 0600 (the data dir is
// 0700). A stale socket is removed first; the instance lock guarantees no
// other daemon owns it.
func listenAdmin(dataDir string) (net.Listener, error) {
	p := client.SocketPath(dataDir)
	if fi, err := os.Lstat(p); err == nil {
		if fi.Mode().Type() != fs.ModeSocket {
			return nil, fmt.Errorf("keyleash: %s exists and is not a socket", p)
		}
		if err := os.Remove(p); err != nil {
			return nil, fmt.Errorf("keyleash: remove stale admin socket: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", p)
	if err != nil {
		return nil, fmt.Errorf("keyleash: admin socket: %w", err)
	}
	if err := os.Chmod(p, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("keyleash: admin socket permissions: %w", err)
	}
	return ln, nil
}

func cleanupAdmin(dataDir string, custom bool) {
	if !custom {
		os.Remove(client.SocketPath(dataDir))
	}
}
