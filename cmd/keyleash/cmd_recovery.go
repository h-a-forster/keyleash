package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
)

var cmdRecovery = &command{
	name:    "recovery",
	args:    "rotate",
	summary: "replace the recovery code (step-up approval)",
	help: `
  keyleash recovery rotate
                          generate a new recovery code and re-key the vault.

Needs the daemon unlocked and a step-up approval: Windows Hello, or your
passphrase or current recovery code (asked at a hidden prompt), or the
daemon's console, per approval.method. The vault gets a new data key: every
entry is re-sealed and every remaining slot re-wrapped, so the old code no
longer opens the vault (nor vault.prev; if keyleash is killed in the middle
of the rotation, vault.prev keeps the old key until the next unlock, which
replaces it). Backups of the vault file taken before the rotation still
open with the old code and show the keys as they were then; rotate
provider keys if the old code may have leaked.

The new code is shown exactly once, like at init: write it down and store
it offline, then re-type its last group to confirm. The audit log records
the rotation, never the code.

Interrupting the command (Ctrl-C) while it waits for approval cancels the
rotation; the daemon does not commit for a caller that has gone. If the
connection is lost while the rotation is being committed, the command
checks the audit log and says whether it happened: if it did, the old code
no longer works and the new one is lost, so run 'keyleash recovery rotate'
again.`,
	run: runRecovery,
}

func runRecovery(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return usagef("recovery", "missing subcommand: rotate")
	}
	sub, args := args[0], args[1:]
	if pos, err := parseFlags(newFlagSet("recovery"), args, true); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("recovery", "unexpected argument")
	}
	if sub != "rotate" {
		return usagef("recovery", "unknown subcommand %q (expected rotate)", sanitizeArg(sub))
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	// The last audit record before the request: a rotation committed by
	// this request is audited after it.
	since, sinceOK := lastAuditSeq(ctx, c)
	fmt.Fprintln(a.stderr, "Waiting for step-up approval...")
	var resp client.RotateRecoveryResponse
	err = a.withStepUp(ctx, c, func(ctx context.Context) error {
		var err error
		resp, err = c.RotateRecovery(ctx)
		return err
	})
	if err != nil {
		// The daemon does not commit for a caller that has gone, but an
		// interruption or a lost connection during the commit itself
		// leaves the outcome unknown: look it up, since a committed
		// rotation means the old code is dead and the new one is lost.
		return rotationLost(ctx, c, err, since, sinceOK)
	}
	fmt.Fprintln(a.stdout)
	fmt.Fprintln(a.stdout, "New recovery code (shown once; write it down and keep it offline):")
	fmt.Fprintln(a.stdout)
	fmt.Fprintf(a.stdout, "    %s\n", resp.Code)
	fmt.Fprintln(a.stdout)
	if resp.Warning != "" {
		fmt.Fprintf(a.stderr, "warning: %s\n", resp.Warning)
	}
	if a.interactive() {
		if err := a.confirmRecovery(resp.Code, "recovery code not confirmed; the rotation is done and the old code no longer works, so keep the code you were shown"); err != nil {
			return err
		}
		fmt.Fprintln(a.stdout, "Recovery code confirmed. Clear your terminal scrollback if others can see this screen.")
	} else {
		fmt.Fprintln(a.stderr, "note: without a terminal the recovery-code check is skipped; make sure the code above is stored safely.")
	}
	fmt.Fprintln(a.stdout, "The old recovery code no longer unlocks the vault.")
	return nil
}

// lastAuditSeq returns the seq of the newest audit record.
func lastAuditSeq(ctx context.Context, c *client.Client) (uint64, bool) {
	qctx, cancel := withTimeout(ctx)
	defer cancel()
	recs, err := c.AuditTail(qctx, 1)
	if err != nil {
		return 0, false
	}
	if len(recs) == 0 {
		return 0, true
	}
	return recs[len(recs)-1].Seq, true
}

// rotationSettle bounds how long a failed `recovery rotate` waits for the
// audit record that settles its outcome.
var rotationSettle = 3 * time.Second

// rotationLost turns a failed `recovery rotate` call (err) into the error
// to report. An answer from the daemon (an API error) means nothing was
// committed. Otherwise (interrupted, connection lost) it reads the audit
// log after record since until it shows the outcome: a committed rotation
// means the old code no longer works and the new one never reached this
// terminal, which it says plainly; an aborted re-key or a step-up that was
// not approved means nothing changed. If the log does not settle it within
// rotationSettle, it says the outcome is unknown and how to check.
func rotationLost(ctx context.Context, c *client.Client, err error, since uint64, sinceOK bool) error {
	const again = "Run `keyleash recovery rotate` again now to get a recovery code you can use."
	var ae *client.APIError
	if errors.As(err, &ae) {
		return err
	}
	// Not cancelled by Ctrl-C: this lookup is what tells the user whether
	// they still have a working recovery code.
	bg := context.WithoutCancel(ctx)
	self := float64(os.Getpid())
	deadline := time.Now().Add(rotationSettle)
	for sinceOK {
		qctx, cancel := withTimeout(bg)
		recs, aerr := c.AuditTail(qctx, 500)
		cancel()
		if aerr != nil {
			break
		}
		for _, rec := range recs {
			if rec.Seq <= since {
				continue
			}
			switch {
			case rec.Type == "rekey" && rec.Fields["op"] == "rotate_recovery" && rec.Fields["ok"] == true:
				return fmt.Errorf("%v\nThe recovery code WAS rotated (audit record %d), but the new code never reached this terminal and cannot be recovered. Your old recovery code no longer works. %s", friendly(err), rec.Seq, again)
			case rec.Type == "rekey" && rec.Fields["op"] == "rotate_recovery":
				return err // aborted: nothing committed
			case rec.Type == "approval" && rec.Fields["kind"] == "admin_change" && rec.Fields["requester_pid"] == self && rec.Fields["approved"] == false:
				return err // never approved: nothing committed
			}
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("%v\nCould not tell whether the recovery code was rotated. Check `keyleash audit tail` for a \"rekey\" record with op rotate_recovery and ok true: if there is one, your old recovery code no longer works and the new one was lost. %s", friendly(err), again)
}
