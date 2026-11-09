# keyleash v0.1.1 (unreleased)

Fixes from a state-machine audit of v0.1.0.

## Stopping and accounting

- `lock`, `panic` and `pass revoke` stop requests already running, including
  streams, which are cut off so a truncated body cannot pass as complete. The
  provider may still bill for work it had started.
- A pass is checked again when a request is admitted: one revoked, expired or
  whose process has gone after its request arrived spends nothing.
- In-flight spend survives a killed daemon: it is journaled, authenticated and
  charged once at the next unlock; a forged line charges nothing and trips. A
  stream that keeps delivering keeps its reservation however
  long it runs.
- A velocity or audit-failure trip ends only with `keyleash resume`, also across
  a restart; a trip derived from the files (a changed config, say) ends with a
  resume or once the files verify again. A resume approval applies only to the
  trip its prompt showed, and with `approval.method = "deny"` a held trip is
  resumed with the passphrase or recovery code. Accepting a failed
  ledger check shows the counts and totals in the prompt and the audit record
  and sticks (the original is kept in `ledger/rejected-<time>/`), and a
  damaged ledger line trips at unlock rather than stopping the daemon starting.
- The vault records the audit log's head, so deleting the log or cutting it back
  trips every unlock until the owner resumes.
- With `[run] kill_on_daemon_exit = false`, every `keyleash run` needs a step-up.
- With `presence.screen_lock = "lock"`, an unlock under a locked screen fails and
  stays locked.
