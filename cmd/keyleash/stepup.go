package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/secmem"
)

// stepUpPoll is how often a waiting command looks for its own approval.
var stepUpPoll = 300 * time.Millisecond

// maxSecretTries bounds the hidden-prompt retries for one approval.
const maxSecretTries = 3

// withStepUp runs call, which may block on a daemon step-up approval (spec
// §9). While it waits, it looks for the approval this process triggered
// (the daemon records the verified caller PID) and, when the daemon accepts
// the vault passphrase or recovery code as proof of presence (approval
// method passphrase or console) and a terminal is available, asks for it at
// a hidden prompt and submits it. With Windows Hello it says to confirm the
// prompt; otherwise it prints how to approve from a terminal. call gets a
// context without the quick-call timeout: approvals take human time.
func (a *app) withStepUp(ctx context.Context, c *client.Client, call func(ctx context.Context) error) error {
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- call(cctx) }()
	tick := time.NewTicker(stepUpPoll)
	defer tick.Stop()
	seen := map[string]bool{}
	method := ""
	self := os.Getpid()
	for {
		select {
		case err := <-done:
			return err
		case <-ctx.Done():
			cancel()
			<-done
			return ctx.Err()
		case <-tick.C:
		}
		qctx, qcancel := withTimeout(ctx)
		list, err := c.Approvals(qctx)
		qcancel()
		if err != nil {
			continue
		}
		for _, ap := range list {
			if ap.Requester != self || seen[ap.ID] {
				continue
			}
			seen[ap.ID] = true
			if method == "" {
				sctx, scancel := withTimeout(ctx)
				if st, serr := c.Status(sctx); serr == nil {
					method = st.ApprovalMethod
				}
				scancel()
			}
			fmt.Fprintf(a.stderr, "Step-up approval needed (%s): %s\n", ap.ID, oneLine(ap.Prompt))
			switch {
			case method == "hello":
				fmt.Fprintln(a.stderr, "Confirm at the Windows Hello prompt.")
			case method == "deny":
				fmt.Fprintln(a.stderr, "approval.method is deny: the request will be refused.")
			case a.interactive():
				if err := a.approveWithSecret(ctx, c, ap.ID, nil, false); err != nil {
					fmt.Fprintf(a.stderr, "Not approved: %v\n", friendly(err))
				}
			default:
				fmt.Fprintf(a.stderr, "Approve it from a terminal with: keyleash approvals approve %s\n", ap.ID)
			}
		}
	}
}

// approveWithSecret approves a pending request with the vault passphrase or
// recovery code (read at a hidden prompt, or from stdin), retrying a wrong
// secret at the prompt a few times. The secret is wiped after each try.
func (a *app) approveWithSecret(ctx context.Context, c *client.Client, id string, grant *client.ApprovalGrant, fromStdin bool) error {
	for try := 1; ; try++ {
		secret, err := a.readSecret("Passphrase or recovery code to approve (input is hidden): ", fromStdin)
		if err != nil {
			secmem.Wipe(secret)
			return err
		}
		// No timeout: the vault re-derives the key from the secret (Argon2).
		err = c.Decide(ctx, id, client.DecideRequest{Approved: true, Grant: grant, Secret: secret})
		secmem.Wipe(secret)
		if err == nil {
			fmt.Fprintf(a.stderr, "Approved %s.\n", id)
			return nil
		}
		if !client.IsCode(err, client.CodeWrongSecret) || fromStdin || try >= maxSecretTries {
			return err
		}
		fmt.Fprintln(a.stderr, "Wrong passphrase or recovery code; try again.")
	}
}

// errNoSuchApproval is returned when an approval id is not pending.
var errNoSuchApproval = errors.New("no such pending approval (it may have been decided or timed out; see `keyleash approvals`)")
