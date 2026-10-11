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

// JobManager confines the process trees of run passes (internal/runjob on
// Windows). The daemon creates one job per run pass when the pass is issued
// and places the bound process in it; every process that process starts
// later is a member and cannot leave.
type JobManager interface {
	// Confine creates the job for pass id and places the process (pid,
	// startTime) into it.
	Confine(id string, pid int, startTime int64) error
	// Member reports whether pid is in the job of pass id.
	Member(id string, pid int) (bool, error)
	// MemberOfAny reports whether pid is in any job still held, including
	// jobs of ended passes whose processes are still alive.
	MemberOfAny(pid int) (bool, error)
	// Sweep releases jobs of passes that are no longer active once their
	// last member has exited.
	Sweep(active func(id string) bool)
	// Close releases every job (and with kill-on-close ends the members).
	Close()
}

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

// confinedPID reports whether pid is confined: a member of any run job the
// daemon holds (Windows; this covers descendants whose parent chain is
// broken and processes that outlived their pass), or the bind process of an
// active run pass or one of its descendants by the parent-process walk.
// Any error while checking counts as confined (fail closed).
func (d *Daemon) confinedPID(pid int) bool {
	if d.jobs != nil {
		if in, err := d.jobs.MemberOfAny(pid); err != nil || in {
			return true
		}
	}
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

// inRunTree reports whether pid belongs to run pass p: a member of its job,
// or (by the parent walk) its bind process or a descendant. Errors deny.
func (d *Daemon) inRunTree(p pass.Pass, pid int) bool {
	if pid <= 0 || p.Bind == nil {
		return false
	}
	if d.jobs != nil && p.Kind == pass.KindRun {
		if in, err := d.jobs.Member(p.ID, pid); err == nil && in {
			return true
		}
	}
	ok, err := d.isDescendant(pid, procinfo.Process{PID: p.Bind.PID, StartTime: p.Bind.StartTime})
	return err == nil && ok
}

// guard enforces caller confinement before any handler runs:
//
//   - GET /v1/status, POST /v1/lock and POST /v1/panic are always allowed
//     (locking only ever increases protection);
//   - a confined caller may otherwise only revoke its own pass (checked by
//     hPassRevoke); everything else is 403 "confined";
//   - a caller whose PID cannot be verified is treated as confined for
//     mutating calls (it may still read).
func (d *Daemon) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := callerFrom(r.Context())
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/status",
			r.Method == http.MethodPost && (r.URL.Path == "/v1/lock" || r.URL.Path == "/v1/panic"):
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
				"this process runs under a keyleash run pass (or could not be identified); it may only read status, lock, panic and revoke its own pass"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
