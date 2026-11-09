# keyleash v0.1.1 (unreleased)

Fixes from a state-machine audit of v0.1.0.

## Stopping and accounting

- `lock`, `panic` and `pass revoke` stop requests already running, including
  streams, which are cut off so a truncated body cannot pass as complete. The
  provider may still bill for work it had started.
- A pass is checked again when a request is admitted: one revoked, expired or
  whose process has gone after its request arrived spends nothing.
- In-flight spend survives a killed daemon: it is journaled and charged at the
  next unlock. A stream that keeps delivering keeps its reservation however
  long it runs.
- A trip ends only with `keyleash resume`, also across a restart, and a resume
  approval applies only to the session it was asked in. Accepting a failed
  ledger check sticks (the original is kept in `ledger/rejected-<time>/`), and a
  damaged ledger line trips at unlock rather than stopping the daemon starting.
- The vault records the audit log's head, so deleting the log or cutting it back
  trips the next unlock.
- With `[run] kill_on_daemon_exit = false`, every `keyleash run` needs a step-up.
- With `presence.screen_lock = "lock"`, an unlock under a locked screen fails and
  stays locked.
