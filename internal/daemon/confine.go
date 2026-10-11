package daemon

import (
	"context"
	"net"
	"net/http"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/procinfo"
)

// The admin channel admits every process of the owner's OS user, including
// agents started under `keyleash run`. Access to it is therefore never
// sufficient for anything that weakens protection or spends more (spec §9,
// §12): such calls need a step-up, and processes inside a run pass's tree
// ("confined" callers) may not make them at all.

type callerKey struct{}

// caller is the verified identity of an admin connection's peer.
type caller struct {
	// pid is the client process id (0 when it could not be determined).
	pid int
	// confined is set by the guard middleware (see confinedPID).
	confined bool
}

func (c caller) known() bool { return c.pid > 0 }

// callerFrom returns the caller recorded for a request's connection.
func callerFrom(ctx context.Context) caller {
	c, _ := ctx.Value(callerKey{}).(caller)
	return c
}

// connContext records the peer PID of each admin connection when it is
// accepted (http.Server.ConnContext).
func (d *Daemon) connContext(ctx context.Context, c net.Conn) context.Context {
	pid, err := d.adminPeerPID(c)
	if err != nil || pid <= 0 {
		pid = 0
	}
	return context.WithValue(ctx, callerKey{}, caller{pid: pid})
}

// confinedPID reports whether pid is the bind process of an active run pass
// or one of its descendants. Any error checking a binding counts as
// confined (fail closed).
func (d *Daemon) confinedPID(pid int) bool {
	now := d.clk.Now()
	for _, p := range d.passes.List() {
		if p.Kind != pass.KindRun || p.Bind == nil || p.Revoked || p.Expired(now) {
			continue
		}
		ok, err := d.isDescendant(pid, procinfo.Process{PID: p.Bind.PID, StartTime: p.Bind.StartTime})
		if err != nil || ok {
			return true
		}
	}
	return false
}

// guard enforces caller confinement before any handler runs:
//
//   - GET /v1/status is always allowed;
//   - a confined caller may otherwise only revoke its own pass (checked by
//     hPassRevoke); everything else is 403 "confined";
//   - a caller whose PID cannot be verified is treated as confined for
//     mutating calls (it may still read).
func (d *Daemon) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := callerFrom(r.Context())
		if r.Method == http.MethodGet && r.URL.Path == "/v1/status" {
			next.ServeHTTP(w, r)
			return
		}
		switch {
		case !c.known():
			c.confined = true
			if r.Method == http.MethodGet || r.Method == http.MethodHead {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, c)))
				return
			}
		default:
			c.confined = d.confinedPID(c.pid)
		}
		r = r.WithContext(context.WithValue(r.Context(), callerKey{}, c))
		if c.confined && !(r.Method == http.MethodDelete && r.URL.Path == "/v1/passes" && c.known()) {
			d.writeErr(w, statusErr(http.StatusForbidden, client.CodeConfined,
				"this process runs under a keyleash run pass (or could not be identified); it may only read status and revoke its own pass"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
