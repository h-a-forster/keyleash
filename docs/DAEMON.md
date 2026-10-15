# Daemon design

The daemon (`internal/daemon`) wires the engine packages together. It owns
the state machine, implements the proxy's policy interfaces, and serves the
admin channel. This document is normative for that wiring; behaviour is
specified in [SPEC.md](SPEC.md).

## Data directory

```
<data>/                     owner-only ACL (vault.SecureDir)
  config.toml               optional; missing = recommended profile
  vault.json, vault.prev    vault + crash-recovery copy (+ anti-rollback sidecar)
  passes.json               pass store (hashes only)
  ledger/                   budget ledger (ledger-YYYY-MM.jsonl)
  audit/                    audit log (audit-YYYY-MM.jsonl)
  state.json                non-security bookkeeping (models seen without a
                            price), MAC'd with a vault-derived key; deleting
                            it changes nothing
  daemon.lock               single-instance lock
```

Security-relevant daemon state lives **in the vault**, in an entry with
provider `keyleash`, kind `admin_key`, label `daemon-state` (created by
`Init`, or on the first unlock of an older vault; hidden from `/v1/keys` and
never removable through the API). Its JSON holds `{version, counter, saved,
checkpoint, config_hash, config_toml, active_keys, approval_method,
pass_store, keys_ever_added}`: the ledger checkpoint (written on lock,
shutdown and every `VaultCheckpointEvery` = 5 min), the last accepted
effective config (config.Encode plus, with a pricing override, a
`[pricing_override_file]` table with its path and SHA-256) and its approval
method, each provider's active `api_key` entry, the pass store baseline
(`{counter, digests: {pass id: sha256}}`, updated by the store's commit hook
after every authenticated write), and whether the vault ever held an
`api_key`. The counter increases with every write. A vault without the entry is migrated
once from the checkpoint in an old state.json.

## Start-up

1. `secmem.HardenProcess()`; resolve data dir; `vault.SecureDir`.
2. Single-instance lock (exclusive open of `daemon.lock`). A second daemon
   exits with a clear error.
3. Load config (`config.Load`). Invalid config → refuse to start.
4. Open vault (locked), pass store, ledger (`budget.Open` with Dir
   `<data>/ledger`), audit log, pricing (the override file is read once with
   `meter.ReadPricingOverride`; its SHA-256 is kept for the config check).
   On Windows create the run-job manager (`internal/runjob`, kill-on-close
   per `[run] kill_on_daemon_exit`; `Options.Jobs` overrides it).
5. Apply limits from config to the ledger (see *Scopes*).
6. Start presence monitor, admin server, proxy listener.
7. Audit `daemon_start`; with a job manager, revoke run passes left by an
   earlier daemon (audit `pass_revoke`, reason `daemon_restart`). State =
   **Locked**.

## State machine

States: `Locked`, `Unlocked`, `Away`, `Tripped`. One mutex guards state;
transitions are audited.

| Event | From | To | Side effects |
|---|---|---|---|
| unlock (slot verified) | Locked | Unlocked | new session id; lease = now + max_lease; `audit.SetAnchorKey(vault.DeriveKey(audit-anchor))`; ledger `SetMACKey` + `VerifyIntegrity` against the checkpoint in the daemon-state entry (failure, or ledger records without a checkpoint → Tripped `integrity`); `audit.Verify` with the anchor key (failure → Tripped `audit_integrity`); `passes.VerifyAgainst(vault baseline)` with the passes MAC key (mismatch or unreadable daemon state → audit `pass_store` with the added/removed/changed ids, Tripped `pass_store`, MAC key left unset; match → `passes.Commit()` re-baselines and folds in revocations made while locked); config hash vs the accepted one (changed → audit `config_change` with the changed keys, Tripped `config_changed`, approvals switch to the accepted method; first unlock records it); `ResetSession("session:<id>")`. Trip priority: integrity, audit_integrity, pass_store, config_changed, velocity, audit |
| presence Idle ≥ idle_after | Unlocked | Away | `ResetSession("away")`; away timer starts |
| presence ScreenLocked | Unlocked | Away or Locked | per `presence.screen_lock` |
| presence Active | Away | Unlocked | |
| presence Resumed (sleep/clock gap) | any unlocked | Locked | |
| away ≥ away_max | Away | Locked | |
| lease expiry | Unlocked/Away | Locked | |
| tripwire fired / integrity failure / security audit record rejected | Unlocked/Away | Tripped | in-flight requests finish; new ones get 423 `tripped` |
| step-up approved "resume" | Tripped | Unlocked | approved with the accepted method for owner trips (integrity, audit_integrity, pass_store, config_changed; never console); `ledger.ResetTrip()`; `audit_integrity`: move `audit/*.jsonl` to `audit/rejected-<UTC time>/` and start a new chain; `pass_store`: revoke added and changed passes, `Commit()`; `config_changed`: record the config and its approval method as accepted; audit `resume` |
| lock / panic | any | Locked | settle in-flight at their reserved amount; checkpoint to the vault; `passes.SetMACKey(nil)`, `vault.Lock()`, `audit.ClearAnchorKey()`, wipe derived keys; drop pass grants and pending config; panic also revokes all passes |

An **unattended grant** (`keyleash away --budget $X --for D`, step-up
required) records `{id, amount, until, pass?}`. While it is active, Away uses
scope `grant:<id>` with a session-window limit of `$X` instead of the away
limits, and `away_max` is extended to `until`.

## Proxy wiring

### Authenticator

1. State Locked → `Denial{423, "locked"}`; Tripped → `Denial{423, "tripped"}`.
2. `pass.Verify(token)` → errors map to `401 pass_invalid` / `pass_expired`.
3. `AllowsProvider(provider)` else `403 provider_denied`.
4. Bound pass: `procinfo.IsDescendant(client.PID, bind)`; any error or false →
   `401 pass_invalid` (never fall back to unbound).
5. Away state: passes created after Away began are refused (`403
   away_limit`), except `run` passes with `limits.away.allow_new_run_passes`.
6. Principal.EntryID = the vault entry for this provider: the pass's
   `entries` mapping if it has one for the provider (mapped entry gone → `403
   no_key`, never redirected); else the provider's active key from the
   daemon-state entry; else its **oldest** `api_key`; none → `403 no_key`.
   Internal entries are never used.

### Gate.Admit

1. Model policy: config deny/allow globs, then pass `AllowsModel` → `403
   model_denied`.
2. Unmetered endpoint → admit with a no-op ticket (still audited).
3. `meter.Estimate`. If not priced:
   - *unpriced* = the model is not in the pricing table; *unbounded* =
     `meter.WorstCaseEstimate` cannot bound it (or the model is priced but
     the estimate is not).
   - Unpriced: refused while Away (`403 model_denied`); `models.unknown =
     deny` → `403 model_denied`. Bounded → reserve the worst case at the
     provider's maximum rates.
   - Unbounded: refused while Away; reserve `requestLimitLocked` = the
     smallest `request` limit that applies (global, provider, model glob,
     pass); none → `403 budget_exceeded`.
   - Approval (kind `unknown_model`) when unbounded or `models.unknown =
     approve`; coalesce key `unknown_model:<pass>:<provider>/<model>:<bucket>:<unbounded>`
     with the bucket = the reservation rounded up to a power of two
     micro-dollars (stated in the prompt).
4. Scopes: `global`, `provider:<p>`, `pass:<id>`, `session:<id>`, plus
   `away` (or `grant:<g_id>`) when Away, plus `grant:pg_<approval id>` for
   each active pass grant of this pass. Model limits apply automatically.
5. `ledger.ReserveWith(scopes, amount, meta, {Skip})`:
   - `ErrExceeded` on `away` or an away grant → 403 `away_limit`; on a pass
     grant scope → 403 `budget_exceeded` (allowance used up).
   - `ErrExceeded` + `on_exceed = deny` → 403 `budget_exceeded`, message names
     the scope, window and remaining amount.
   - `ErrExceeded` + `on_exceed = approve` → approval (kind `over_limit`,
     never coalesced, with `scope`, `window`, `limit`); if approved, retry
     with `Skip` = that limit for this reservation only (at most 3 approvals
     per request, one per exceeded limit); audit `limit_override` once
     admitted. A grant on the approval becomes a **pass grant** after the
     request is admitted: `{id: pg_<approval id>, pass, scope, window,
     amount ≤ grant_max_multiple × limit, until ≤ now + grant_max_duration}`;
     later reservations of that pass skip that limit and count against the
     session-window limit `grant:pg_<id>` = amount instead. Idempotent per
     approval id; expired by housekeeping; dropped on lock.
   - `ErrConcurrency` → 429 `concurrency`.
   - `ErrTripped` → state Tripped, 423 `tripped`.
   - `ErrPersist`/`ErrClosed` → 503 `internal`.
6. Ticket.Finish(outcome):
   - `!Sent` → `Release()`.
   - else, when `UsageOK`: priced model → `meter.Cost`; unpriced model →
     `meter.WorstCaseCost` (maximum rates, `estimated = true`); otherwise the
     reserved amount, `estimated = true`.
   - `Settle(cost, estimated)`; audit `request` record; `pass.Touch`.
   - Finish must run even on panic (proxy guarantees one call).

### KeySource

`vault.WithSecret(entryID, fn)`; `vault.ErrLocked` → `Denial{423, "locked"}`.

### Meter adapter

Wraps `*meter.Meter`; `NewUsageParser(p, ep, stream)` calls
`NewProviderUsageParser(p.Name, ep, stream)`.

## Approvals

`approval.Queue` with the configured approver (`hello` via a winhello key
named `approval`, `passphrase` = waits for an external decision, `console`,
`deny`); `approverFor(method, forResume)` maps a method to an approver
(for a resume: `console`, `deny` and an unavailable `hello` become
`passphrase`). `Queue.RequestWith` runs one request with a given approver
(no coalescing); each pending approval reports its approver's `method`.
Every approver shows `approval.PromptText` (≤ 200 runes: title, requester
image and PID, risk `Detail`, amount, model, pass, then `Note`); `stepUp`
refuses with 400 when `approval.Fits` fails. Pending approvals are visible from the admin API with the verified
requester PID and image, and for `over_limit` the exceeded scope, window and
limit plus the grant caps (`grant_max_micros`, `grant_max_for_ns`). The first
decision wins.

Deciding over the admin API (`POST /v1/approvals/{id}`): a denial needs
nothing. An approval needs `secret` (passphrase or recovery code; `method`
`passphrase`, `recovery`, or empty = recovery-code format first, then
passphrase), which the vault verifies with `VerifyPassphrase` /
`VerifyRecovery` (the KDF runs without any vault or daemon lock; the slot's
unwrapped key is compared in constant time with the loaded DEK; vault state is
not changed). The attempt is reserved under `secretMu` first: one
verification at a time, a concurrent one → 429 `rate_limited`. It is refused
when the pending approval's method is `deny`, or `approval.method = deny`
unless the approval waits for the passphrase (403). A wrong secret → 401
`wrong_secret`, audited as `approval_secret`; per caller (`pid:image`, at most
1024 tracked) after 5 consecutive failures each attempt waits 30 s doubling to
15 min, and across callers after 10 failures each attempt waits 2 s doubling
to 1 min → 429 `rate_limited`. A correct secret resets both. A grant is
accepted only on `over_limit` approvals and only within the caps (else 400).
The queue records the decision method (`passphrase`/`recovery`).

Admin step-ups (`stepUp`) never coalesce and carry the caller's verified PID
as `Requester`. Proxy approvals (`over_limit`, `unknown_model`) carry PID 0.

## Admin channel

- Windows: named pipe `\\.\pipe\keyleash-<SID>` (go-winio) with SDDL granting
  only the current user SID. Unix: `<data>/admin.sock`, mode 0600.
- HTTP/1.1 + JSON. Each request carries no credential; access control is the
  OS ACL, which admits every process of the owner's user. Mutations that
  weaken protection or spend more additionally require a step-up (SPEC §9).
- `http.Server.ConnContext` records each connection's client PID
  (`connPeerPID`: `GetNamedPipeClientProcessId`, `SO_PEERCRED`,
  `LOCAL_PEERPID`, FreeBSD `LOCAL_PEERCRED` `cr_pid`; elsewhere unknown;
  `Options.AdminPeerPID` overrides it). The `guard` middleware then applies
  confinement (SPEC §12): `GET /v1/status`, `POST /v1/lock` and
  `POST /v1/panic` always pass (`POST /v1/shutdown` does not: a confined
  or unidentified caller gets 403 `confined`); a confined caller (a member of any held run
  job, or inside an active run pass's process tree) may only `DELETE
  /v1/passes` for its own pass (`inRunTree`: job member or descendant); an
  unidentified caller may only read; everything else → 403 `confined`.
- Run jobs (`JobManager`, Windows `internal/runjob`): `Confine(pass id, pid,
  start time)` at pass creation (failure → the pass is removed, 409);
  `MemberOfAny(pid)` for confinement (an error counts as member);
  `Member(id, pid)` for proxy authentication of run passes; housekeeping
  `Sweep` releases a job once its pass has ended and it has no live member;
  `Close` on shutdown (kill-on-close ends the members).
- `internal/client` is the typed Go client used by the CLI. The CLI's
  `withStepUp` runs a step-up call without the quick-call timeout and polls
  `/v1/approvals` for the approval whose `requester_pid` is its own PID; with
  method `passphrase`/`console` and a terminal it asks for the passphrase or
  recovery code at a hidden prompt and decides it.

| Method | Path | Body → Response |
|---|---|---|
| GET | /v1/status | → state, trip reason, lease, session, limits status, in-flight, degraded presence, vault info, `approval_method` (the queue's current approver), `config_changes`, `pass_store_changes` |
| POST | /v1/unlock | {method: hello\|passphrase\|recovery\|dpapi, secret?, accept_rollback?} → status (a rollback → 409 `rollback` with the file and recorded seqs; `accept_rollback` accepts it for this unlock only, not with dpapi, audited `accept_rollback {file_seq, recorded_seq}`; status `vault.rollback_*`) |
| POST | /v1/lock | → status (any caller) |
| POST | /v1/panic | {revoke_upstream?} → summary (any caller) |
| POST | /v1/shutdown | → 202 {stopping} (no step-up; not for confined or unidentified callers); audit `shutdown` {requester_pid, requester}, then the *Shutdown* sequence runs after the response |
| POST | /v1/away | {budget ≤ `limits.away.max_grant`, for, pass?} (step-up, never coalesced) → grant |
| POST | /v1/resume | (step-up) leave Tripped, accepting what the trip reported |
| GET/POST/DELETE | /v1/passes | create {name, kind, providers, models, limits, ttl, bind?} (lists ≤ 32, no duplicates; step-up unless a run pass bound to the caller within the defaults; refused while Away; order: issue → job confine → audit `pass_issue` → limits, rolled back on failure) → {pass, token (once)}; list; revoke {id} (a confined caller: its own pass only) |
| GET | /v1/keys | entries (masked metadata, `active`); internal entries hidden |
| POST | /v1/keys | {provider, label, kind?, secret} (step-up, except the first `api_key` the vault ever holds: `keys_ever_added`) → entry |
| POST | /v1/keys/{id}/use | (step-up) make the `api_key` its provider's active key → entry |
| DELETE | /v1/keys/{id} | (step-up) |
| GET | /v1/usage | ?by=pass\|model\|provider\|process&since= |
| GET | /v1/approvals | pending, with requester and grant caps |
| POST | /v1/approvals/{id} | {approved, grant?, method?, secret?}: deny needs nothing; approve needs the secret |

There is no rollback-arming endpoint (the former `POST
/v1/vault/accept-rollback` is gone): accepting a rollback is the
`accept_rollback` flag of the unlock request.
| GET | /v1/audit/tail | ?n= |
| GET | /v1/config | effective config (TOML) |
| POST | /v1/vault/recovery | (step-up) new recovery code, re-keys the vault → {code (once), warning?}; audit `rekey` / `slot_change` {op: rotate_recovery}, never the code |
| DELETE | /v1/vault/slots/{id} | (step-up) remove a slot and re-key |

Secrets travel only in request bodies over the ACL-protected channel and are
wiped after use. Responses never contain provider keys; a pass token is
returned exactly once, at creation.

## Shutdown

Triggered by the context ending (Ctrl-C, SIGTERM, logoff) or by `POST
/v1/shutdown` (`keyleash stop`); both run the same sequence (`Close`).
Stop accepting proxy connections; wait up to `ShutdownGrace` (30 s) for
in-flight requests; set the state to Locked (no new reservation can start);
if it was unlocked, settle every reservation still in flight at
its reserved amount (`ExpireInFlight(-1)`, while the ledger MAC key is set),
flush the ledger, write the checkpoint to the vault and state.json, audit
`lock` and anchor; then `ledger.Close`, `audit.Close`,
`passes.SetMACKey(nil)`, `vault.Lock`; close the run jobs (members end with
kill-on-close); remove the socket; release the instance lock.
