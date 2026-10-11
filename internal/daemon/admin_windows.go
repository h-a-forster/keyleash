//go:build windows

package daemon

import (
	"fmt"
	"net"

	"github.com/Microsoft/go-winio"

	"github.com/h-a-forster/keyleash/internal/client"
)

// AdminSDDL returns the security descriptor of the admin pipe: owned by sid,
// with a protected DACL (no inherited entries) holding a single ACE that
// grants GENERIC_ALL to sid. Everyone, Network, Anonymous and other users get
// nothing. The owner is set explicitly so clients can verify it.
func AdminSDDL(sid string) string {
	return "O:" + sid + "D:P(A;;GA;;;" + sid + ")"
}

// listenAdmin listens on \.\pipe\keyleash-<SID> with AdminSDDL.
func listenAdmin(string) (net.Listener, error) {
	sid, err := client.CurrentUserSID()
	if err != nil {
		return nil, err
	}
	return listenPipe(client.PipePrefix+sid, sid)
}

// listenPipe creates the named pipe with the owner-only descriptor. go-winio
// creates the first instance with FILE_FLAG_FIRST_PIPE_INSTANCE, so this
// fails if another process already owns the name.
func listenPipe(name, sid string) (net.Listener, error) {
	ln, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: AdminSDDL(sid)})
	if err != nil {
		return nil, fmt.Errorf("keyleash: admin pipe %s: %w (is another daemon running?)", name, err)
	}
	return ln, nil
}

func cleanupAdmin(string, bool) {}
