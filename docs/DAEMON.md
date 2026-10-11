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
  state.json                daemon bookkeeping that must survive restarts
                            (ledger checkpoint, last seen models), MAC'd with
                            a vault-derived key
  daemon.lock               single-instance lock
```

## Start-up

1. `secmem.HardenProcess()`; resolve data dir; `vault.SecureDir`.
2. Single-instance lock (exclusive open of `daemon.lock`). A second daemon
   exits with a clear error.
3. Load config (`config.Load`). Invalid config → refuse to start.
4. Open vault (locked), pass store, ledger (`budget.Open` with Dir
   `<data>/ledger`), audit log, pricing (`meter.LoadPricing`).
5. Apply limits from config to the ledger (see *Scopes*).
6. Start presence monitor, admin server, proxy listener.
7. Audit `daemon_start`. State = **Locked**.

## State machine

States: `Locked`, `Unlocked`, `Away`, `Tripped`. One mutex guards state;
transitions are audited.

| Event | From | To | Side effects |
|---|---|---|---|
| unlock (slot verified) | Locked | Unlocked | new session id; lease = now + max_lease; `audit.SetAnchorKey(vault.DeriveKey(audit-anchor))`; ledger `SetMACKey` + `VerifyIntegrity` against the checkpoint in state.json (failure → Tripped); `ResetSession("session:<id>")` |
| presence Idle ≥ idle_after | Unlocked | Away | `ResetSession("away")`; away timer starts |
| presence ScreenLocked | Unlocked | Away or Locked | per `presence.screen_lock` |
| presence Active | Away | Unlocked | |
| presence Resumed (sleep/clock gap) | any unlocked | Locked | |
| away ≥ away_max | Away | Locked | |
| lease expiry | Unlocked/Away | Locked | |
| tripwire fired / integrity failure | Unlocked/Away | Tripped | in-flight requests finish; new ones get 423 `tripped` |
| step-up approved "resume" | Tripped | Unlocked | `ledger.ResetTrip()` |
| lock / panic | any | Locked | `vault.Lock()`, `audit.ClearAnchorKey()`, wipe derived keys; panic also revokes all passes |

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
5. Away state: `run` passes created while away are refused unless
   `limits.away.allow_new_run_passes`.
6. Principal.EntryID = the vault entry for this provider: the pass's mapping
   if set, else the newest `api_key` entry for the provider; none → `403
   no_key`.

### Gate.Admit

1. Model policy: config deny/allow globs, then pass `AllowsModel` → `403
   model_denied`.
2. Unmetered endpoint → admit with a no-op ticket (still audited).
3. `meter.Estimate`. If unpriced → `models.unknown`: `deny` → 403
   `model_denied`; `approve` → approval request (kind `unknown_model`,
   coalesced per pass+model); `allow` or approved → reserve the **fallback
   amount** = the smallest configured `request` limit in scope (global,
   provider, pass), or $2 if none, and settle at that amount when cost
   cannot be computed.
4. Scopes: `global`, `provider:<p>`, `pass:<id>`, `session:<id>`, plus
   `away` (or `grant:<id>`) when Away. Model limits apply automatically.
5. `ledger.Reserve`:
   - `ErrExceeded` + `on_exceed = deny` → 403 `budget_exceeded`, message names
     the scope, window and remaining amount.
   - `ErrExceeded` + `on_exceed = approve` → approval (kind `over_limit`); if
     approved with a grant, raise that limit by the grant amount for the
     grant duration (limit overlay, re-applied with `SetLimits`) and retry
     once.
   - `ErrConcurrency` → 429 `concurrency`.
   - `ErrTripped` → state Tripped, 423 `tripped`.
   - `ErrPersist`/`ErrClosed` → 503 `internal`.
6. Ticket.Finish(outcome):
   - `!Sent` → `Release()`.
   - else cost = `meter.Cost` when `UsageOK` and priced; otherwise the
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
named `approval`, `console`, `deny`). Pending approvals are also visible to
and decidable from the admin API (`keyleash approvals`), so a headless
daemon can still be approved from a terminal; the first decision wins.

## Admin channel

- Windows: named pipe `\\.\pipe\keyleash-<SID>` (go-winio) with SDDL granting
  only the current user SID. Unix: `<data>/admin.sock`, mode 0600.
- HTTP/1.1 + JSON. Each request carries no credential; access control is the
  OS ACL. Mutations that weaken protection additionally require step-up.
- `internal/client` is the typed Go client used by the CLI.

| Method | Path | Body → Response |
|---|---|---|
| GET | /v1/status | → state, lease, session, limits status, in-flight, degraded presence, vault info |
| POST | /v1/unlock | {method: hello\|passphrase\|recovery\|dpapi, secret?} → status |
| POST | /v1/lock | → status |
| POST | /v1/panic | {revoke_upstream?} → summary |
| POST | /v1/away | {budget, for, pass?} (step-up) → grant |
| POST | /v1/resume | (step-up) leave Tripped |
| GET/POST/DELETE | /v1/passes | create {name, kind, providers, models, limits, ttl, bind?} → {pass, token (once)}; list; revoke {id} |
| GET | /v1/keys | entries (masked metadata) |
| POST | /v1/keys | {provider, label, secret} → entry |
| DELETE | /v1/keys/{id} | (step-up) |
| GET | /v1/usage | ?by=pass\|model\|provider\|process&since= |
| GET | /v1/approvals | pending |
| POST | /v1/approvals/{id} | {approved, grant?} |
| GET | /v1/audit/tail | ?n= |
| GET | /v1/config | effective config (TOML) |

Secrets travel only in request bodies over the ACL-protected channel and are
wiped after use. Responses never contain provider keys; a pass token is
returned exactly once, at creation.

## Shutdown

Stop accepting proxy connections; wait up to 30 s for in-flight requests;
`ledger.Close`, `audit.Close`, `vault.Lock`; remove the socket; release the
instance lock.
