package main

import (
	"context"
	"fmt"

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
longer opens the vault (nor vault.prev). Backups of the vault file taken
before the rotation still open with the old code and show the keys as they
were then; rotate provider keys if the old code may have leaked.

The new code is shown exactly once, like at init: write it down and store
it offline, then re-type its last group to confirm. The audit log records
the rotation, never the code.`,
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
	fmt.Fprintln(a.stderr, "Waiting for step-up approval...")
	var resp client.RotateRecoveryResponse
	err = a.withStepUp(ctx, c, func(ctx context.Context) error {
		var err error
		resp, err = c.RotateRecovery(ctx)
		return err
	})
	if err != nil {
		return err
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
