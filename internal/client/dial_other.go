//go:build !windows

package client

import (
	"context"
	"net"
	"path/filepath"
)

// SocketName is the admin socket's file name inside the data directory.
const SocketName = "admin.sock"

// SocketPath returns the admin socket path for dataDir.
func SocketPath(dataDir string) string { return filepath.Join(dataDir, SocketName) }

func adminDialer(dataDir string) (DialFunc, error) {
	p := SocketPath(dataDir)
	return func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", p)
	}, nil
}
