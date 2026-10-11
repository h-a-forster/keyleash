# keyleash — Specification (v0.1 draft)

keyleash is a local credential broker and spend governor for LLM API keys.
Real provider keys live in an encrypted vault on the machine. Agents, CLIs and
SDKs talk to a loopback proxy using *passes* — scoped, revocable, local-only
stand-ins — and the proxy injects the real key, enforces hard spend limits, and
locks itself when the owner is away.

This document is normative for the engine. UI is out of scope here.

---

## 1. Goals

1. A real API key never appears in agent config, environment variables, shell
   history, screenshots, or stream output.
2. Money cannot be spent faster or further than the owner allowed, even by many
   parallel requests.
3. Access is bound to the owner's presence: an unattended or sleeping machine
   cannot run up a bill.
4. A leaked pass is worthless off the machine and short-lived on it.
5. Every spend decision is auditable after the fact, and tampering with that
   record is detectable.
6. Works with any client that lets you set a base URL and API key. No code
   changes, no Docker, no database server, one static binary.

## 2. Non-goals

- Defending against malware already running as the same OS user **while the
  vault is unlocked**. Such code can use a pass or read process memory. keyleash
  limits the damage (budgets, presence, concurrency) but cannot prevent use.
- Defending against an administrator / kernel-level attacker.
- Being a multi-tenant team gateway (use LiteLLM, Portkey, etc. for that).
- Intercepting arbitrary TLS traffic (an optional `HTTPS_PROXY` mode may come
  later; base-URL mode is the supported path).

## 3. Threat model

| # | Threat | Example | Defense |
|---|---|---|---|
| T1 | Key read from disk/config | `.env` committed, agent config scraped, infostealer grabs dotfiles | Keys only in the encrypted vault; clients hold passes |
| T2 | Key shown on screen | Livestream, screen share, screenshot, terminal scrollback | Keys never printed; reveal requires step-up and goes to an auto-clearing clipboard |
| T3 | Unattended machine | Owner asleep or away while a session is open | Presence lock: idle → away mode (tight caps), screen lock/sleep/lease expiry → locked |
| T4 | Runaway or hijacked agent | Agent loops, spawns a swarm, picks the priciest model | Reserve-then-settle budgets, concurrency caps, velocity tripwire, model allowlist, step-up approval |
| T5 | Pass leaks | Pass visible on stream or in a log | Pass is useless off-loopback; scoped; expiring; process-bound passes die with the process |
| T6 | Credential exfiltration via the proxy | Redirect to attacker host, Host-header tricks, browser page calling localhost | Fixed upstream host allowlist, redirects never followed, Host/Origin checks, client auth stripped |
| T7 | Key used elsewhere after a past leak | Old key stolen months ago | Optional usage reconciliation against provider usage APIs; panic revoke via admin APIs |
| T8 | Tampering with records | Malware edits the audit log or ledger to hide spend | Hash-chained audit log; vault metadata authenticated with a key derived from the vault key |
| T9 | Prompt injection asks the agent to reveal its key | "print your ANTHROPIC_API_KEY" | Agent only ever has a pass |

Residual risk is stated plainly in the README.

## 4. Architecture

```
 agent / SDK / CLI                  keyleash daemon (one per OS user)
 ─────────────────                  ──────────────────────────────────────────────
 ANTHROPIC_BASE_URL=http://127.0.0.1:47114/anthropic
 ANTHROPIC_API_KEY=klp_…   ──HTTP──▶ proxy ─▶ pass check ─▶ policy ─▶ budget reserve
                                       │                                   │
                                       │        vault (decrypt on use) ◀───┘
                                       ▼
                               upstream (TLS, fixed hosts, no redirects)
                                       │
                         stream back ◀─┴─▶ meter (usage) ─▶ settle ─▶ audit log

 keyleash CLI / UI ──named pipe (owner-only ACL)──▶ admin API
 presence monitor ─▶ state machine (Locked / Unlocked / Away / Tripped)
 approver (Windows Hello / console) ◀── step-up requests
```

Process model: a single long-running daemon per OS user (`keyleash daemon`),
started at logon (Task Scheduler on Windows, launchd/systemd user units later).
The CLI is a thin client over the admin channel.

### 4.1 Packages

| Package | Responsibility |
|---|---|
| `internal/secmem` | Locked, wipeable memory for key material (VirtualLock/mlock, best effort) |
| `internal/vault` | Vault file format, envelope encryption, key slots, atomic writes |
| `internal/winhello` | Windows Hello / TPM keys via the Microsoft Passport KSP (NCrypt) |
| `internal/provider` | Provider registry: hosts, auth styles, allowed endpoints, env var names |
| `internal/meter` | Request inspection (model, max tokens, stream), usage extraction (JSON + SSE), pricing, cost |
| `internal/budget` | Ledger: reserve/settle, windows, concurrency, velocity tripwire, persistence |
| `internal/pass` | Pass issue/verify/revoke, scopes, persistence |
| `internal/audit` | Hash-chained JSONL audit log, verify |
| `internal/presence` | Idle, screen-lock, sleep detection; emits presence events |
| `internal/approval` | Step-up approval queue and approvers (Hello, console, deny) |
| `internal/proxy` | Loopback reverse proxy: inbound checks, auth swap, upstream, streaming, metering hooks |
| `internal/daemon` | Wiring, state machine, admin API |
| `internal/config` | TOML config, defaults, validation, profiles |
| `cmd/keyleash` | CLI |

Packages talk through small interfaces defined by the **consumer** (e.g. the
proxy defines the `KeySource`, `Budget` and `Auditor` it needs), so each package
can be built and tested in isolation.

## 5. Vault

### 5.1 Envelope encryption

- One random 256-bit **data encryption key (DEK)** per vault.
- Sub-keys from the DEK via HKDF-SHA256 with distinct `info` strings:
  - `keyleash/v1/entry` — entry encryption key
  - `keyleash/v1/header-mac` — vault metadata MAC key
  - `keyleash/v1/audit-anchor` — audit anchor MAC key
- Each secret entry is sealed with **XChaCha20-Poly1305**, a fresh random 24-byte
  nonce, and AAD = `"keyleash/v1/entry\x00" || vault_id || entry_id || provider || kind`.
  Moving or relabeling a ciphertext breaks authentication.
- The whole vault header (format, version, ids, slots, entry metadata, sequence
  number) is authenticated with HMAC-SHA256 under the header-MAC key over a
  canonical encoding. Removing/adding/reordering slots or entries without the
  DEK is detected on unlock.
- The DEK is held only in `secmem` while unlocked and wiped on lock. Entry
  plaintext is decrypted **per request** into a short-lived buffer, never cached.

### 5.2 Key slots

Like LUKS: the DEK is wrapped independently by each slot; any one slot unlocks.
Each slot derives a 256-bit key-encryption key (KEK) and seals the DEK with
XChaCha20-Poly1305, AAD = `"keyleash/v1/slot\x00" || vault_id || slot_id || slot_type`.

| Slot | KEK source | Notes |
|---|---|---|
| `hello` | Windows Hello / TPM: RSA key in the Microsoft Passport KSP; DEK wrapped with RSA-OAEP-SHA256 (PKCS#1 v1.5 fallback only if OAEP is unsupported by the KSP) | Each unlock prompts for PIN/biometric. Default on Windows when available |
| `passphrase` | Argon2id(passphrase, salt) — defaults m=256 MiB, t=3, p=4, tuned at creation to ≥ 0.5 s | Portable; default where Hello is unavailable |
| `recovery` | Argon2id over a random 128-bit recovery code shown once (grouped base32, with checksum) | Created at init; offline backup |
| `dpapi` | Windows DPAPI (user scope, entropy = vault_id, UI forbidden) | Opt-in "unlock at logon". Any same-user process can unwrap it, so it is labelled *convenience* and off by default |
| `fido2` | FIDO2 `hmac-secret` from a security key | Later phase |

Rules:
- A vault must always keep at least one slot; removing the last
  non-convenience slot requires creating another first.
- Adding/removing slots requires the vault to be unlocked **and** a fresh step-up.
- KDF parameters are stored per slot so they can be raised later (`rekey`).

### 5.3 Entries

```
entry { id, provider, kind: "api_key" | "admin_key", label, created, rotated,
        fingerprint, nonce, ciphertext }
```

`fingerprint` = first 8 bytes of HMAC-SHA256(header-MAC key, secret), hex. It
lets `scan` recognise a vault key found on disk without decrypting anything, and
reveals nothing useful without the vault.

### 5.4 File format and storage

- JSON (human-inspectable; binary fields base64url), `format: "keyleash-vault"`,
  `version: 1`, monotonically increasing `seq` on every write.
- Writes are atomic: write temp file in the same directory → fsync → rename →
  fsync directory where supported. The previous file is kept as `vault.prev`
  for crash recovery only.
- Data directory permissions: owner-only (Windows DACL: current user + SYSTEM;
  Unix 0700/0600).
- Anti-rollback (optional): the latest `seq` is also stored in a DPAPI-protected
  sidecar; a lower `seq` on disk triggers a warning.

Default data directory: `%LOCALAPPDATA%\keyleash` on Windows,
`~/Library/Application Support/keyleash` on macOS, `$XDG_CONFIG_HOME/keyleash`
on Linux. Overridable with `KEYLEASH_HOME`.

### 5.5 Memory hygiene (best effort, documented as such)

- Key material is kept in pages allocated outside the Go heap
  (VirtualAlloc+VirtualLock / mmap+mlock), wiped before release.
- Provider keys become a Go string only at the moment the outbound header is
  set; that is unavoidable in Go and is stated in the threat model.
- Crash dumps: the daemon disables Windows Error Reporting dumps for itself
  (`SetErrorMode`) and core dumps on Unix (`RLIMIT_CORE=0`).

## 6. Passes

A pass is what a client holds instead of a key.

```
klp_<id:10 base32>_<secret:43 base64url of 32 random bytes>
```

- Stored as `id → SHA-256(secret)` plus scope; compared in constant time.
  (The secret has 256 bits of entropy, so a plain hash is sufficient.)
- Recognisable prefix so secret scanners and humans know it is not a provider
  key.
- Scope:
  - `providers` allowed (and which vault entry each maps to)
  - `models`: allow/deny glob lists
  - `endpoints`: optional narrowing of provider endpoints
  - `budget`: per-pass windows (see §7)
  - `max_concurrency`
  - `expires_at` (default 24 h for named passes)
  - `bind`: optional process binding (PID + process start time); the pass dies
    when that process exits, and requests whose TCP peer is not that process or
    a descendant are rejected (Windows: `GetExtendedTcpTable` →
    owning PID → parent chain)
- Kinds: `named` (created by the owner, e.g. for an editor), `run` (ephemeral,
  created by `keyleash run`, process-bound, revoked on exit), `admin` (none —
  the admin channel uses OS-level access control, not passes).
- Passes only work while the daemon is Unlocked or Away (§8).

## 7. Spend control

### 7.1 Money

All amounts are integer **micro-USD** (`int64`). No floats in accounting.

### 7.2 Scopes and windows

Limits can be attached to scopes: `global`, `provider:<name>`, `pass:<id>`,
`session:<unlock-id>`, `model:<glob>`.

Windows per limit: `request`, `minute`, `hour` (rolling), `day`, `month`
(calendar, local time zone), `session` (resets on unlock).

### 7.3 Reserve → settle

1. Before forwarding, the meter computes a **worst-case cost**:
   - input: `ceil(body_bytes / 3)` tokens (deliberately pessimistic) priced at
     the highest input rate that could apply (cache-write rate if higher);
   - output: `max_tokens` (or the provider/model output ceiling if absent, or
     the policy `assume_max_output_tokens`) at the output rate, plus any
     explicit thinking/reasoning budget;
   - plus fixed per-request fees where a provider has them.
2. The ledger atomically **reserves** that amount against every applicable
   scope/window. If any would exceed its limit the request is rejected
   (`403`, JSON error naming the limit; not `429`, which SDKs retry) or sent
   to step-up approval if the policy says `on_exceed = "approve"`.
3. After the response, the meter extracts actual usage (non-stream JSON
   `usage`, or SSE events) and the ledger **settles** the reservation to the
   actual cost.
4. If usage cannot be determined (stream cut, unknown format), the reservation
   is settled **at the reserved amount** and marked `estimated`. Fail-safe:
   uncertainty costs budget, never the reverse.

This makes limits hard under concurrency: N parallel requests each hold their
worst case until they settle.

### 7.4 Concurrency and velocity

- Concurrency limiter per scope (default global 8, per pass 4).
- **Velocity tripwire**: if settled+reserved spend in a rolling window exceeds a
  threshold (default $5 in 5 minutes), the daemon enters `Tripped`: new requests
  are rejected and in-flight streams may finish. Leaving `Tripped` requires
  step-up approval.

### 7.5 Models and endpoints

- Model allow/deny globs at global, provider and pass level. Default deny
  list is empty; default policy for *unknown* models (not in the pricing table)
  is `approve` (step-up), never "free".
- Only listed endpoints are forwarded per provider (messages, chat completions,
  responses, embeddings, model listing, token counting, …). Anything else is
  denied unless explicitly allowed in config.

### 7.6 Pricing

- Embedded pricing table (JSON) with per-model rates per million tokens:
  input, output, cache write, cache read; plus `source_url` and `as_of` per
  entry. Model ids are matched exactly first, then by declared prefix/glob.
- User override file merged on top. `keyleash pricing check` reports models
  seen in traffic that lack a price.

### 7.7 Persistence

- Settled charges are appended to `ledger/YYYY-MM.jsonl` (fsync'd in batches
  ≤ 1 s). On start the ledger replays the current month to rebuild windows.
- Reservations live in memory only; a crash drops in-flight requests anyway.

## 8. Presence and state machine

```
           unlock (slot + step-up)                 idle ≥ idle_after
 Locked ───────────────────────────▶ Unlocked ─────────────────────────▶ Away
   ▲  ◀── lock / lease expiry / sleep / panic ──┘   ◀── input resumes ───┘
   │                                                     │ away ≥ away_max, screen lock*
   └─────────────────────────────────────────────────────┘
 Unlocked/Away ──velocity tripwire──▶ Tripped ──step-up──▶ Unlocked
```

- **Locked**: DEK wiped. All proxied requests get `423 Locked` with a clear
  JSON error. Admin API works (status, unlock).
- **Unlocked**: normal limits. Has a lease (`max_lease`, default 12 h).
- **Away**: entered after `idle_after` (default 10 min) without keyboard/mouse
  input, or on screen lock (configurable: `screen_lock = "away" | "lock"`,
  default `away`). Existing passes keep working under **away limits** (default
  $3 total, concurrency 2, no new `run` passes, no unknown models). After
  `away_max` (default 2 h) → Locked.
- **Unattended grant**: the owner can pre-authorise a long run before leaving:
  `keyleash away --budget 20 --for 8h [--pass <id>]`. Requires step-up. This
  replaces away limits for that window.
- **Sleep/hibernate** → Locked. Detected by wall-clock vs monotonic gap in the
  presence loop (portable) and OS power notifications where available.
- **Tripped**: see §7.4.

Windows signals: `GetLastInputInfo` (idle), `OpenInputDesktop` /
`WTSQuerySessionInformation` (locked session), clock-gap (sleep).

## 9. Step-up approval

Triggered by: unlock (Hello slot implies it), exceeding a limit with
`on_exceed = "approve"`, unknown or newly-seen expensive model, leaving
Tripped, unattended grants, reveal/export, slot changes, raising limits.

```
Approver.Approve(ctx, Request{Kind, Title, Detail, Amount, PassID, Model}) → (Decision, error)
```

- `hello` approver: signs a fresh nonce with a Passport KSP key whose UI
  policy forces a Windows Hello prompt; the prompt text describes the request.
- `console` approver: TTY prompt (development / headless).
- `deny` approver: always no (CI, servers).
- Requests wait up to `approval_timeout` (default 60 s) holding the HTTP
  request open; identical pending requests (same pass + reason) coalesce.
- Approvals can carry a grant (e.g. "+$10 for this pass for 1 h") so one
  approval does not become a prompt storm.

## 10. Proxy

### 10.1 Inbound

- Listens on `127.0.0.1` only (default port 47114; `[::1]` optional). Rejects
  non-loopback peers even if misconfigured.
- `Host` must be `127.0.0.1:<port>` or `localhost:<port>` (DNS rebinding
  defence).
- Requests carrying an `Origin` header are rejected unless the origin is
  allowlisted (blocks malicious web pages calling localhost).
- Routing: `/<provider>/<upstream path>` e.g. `/anthropic/v1/messages`.
- Pass extracted from the provider's normal auth location (`x-api-key`,
  `Authorization: Bearer`, `x-goog-api-key`, `?key=`), whichever the SDK uses.
- Body limit (default 32 MiB). Body is read fully (bounded) so it can be
  inspected, then forwarded byte-for-byte.

### 10.2 Outbound

- Upstream host comes **only** from the provider registry; never from the
  request.
- TLS ≥ 1.2, system roots, certificate verification always on.
- Redirects are never followed (`CheckRedirect` returns the 3xx to the client
  with `Location` intact but no credentials are sent onward).
- Environment proxies (`HTTPS_PROXY`) are ignored unless an upstream proxy is
  explicitly configured.
- Header hygiene by exact canonical names: strip hop-by-hop headers, all
  inbound credential headers for every provider style, `Cookie`,
  `Proxy-Authorization`; then set the provider's auth header from the vault.
- Timeouts: connect 10 s, TLS 10 s, response header 10 min (LLM latency),
  idle stream 5 min.

### 10.3 Streaming

SSE responses are streamed with immediate flushes. A tee feeds the meter's
incremental parser (Anthropic `message_start`/`message_delta`, OpenAI
`stream_options.include_usage` final chunk, Gemini `usageMetadata`). If the
client did not ask for usage in an OpenAI stream, the proxy may add
`stream_options: {include_usage: true}` (on by default; the extra final chunk
is harmless to standard clients).

### 10.4 Errors

Proxy-generated errors use the provider's error JSON shape where possible so
SDKs surface a readable message. Status codes are chosen so SDK retry logic
does the right thing: `401` invalid/expired pass, `423` locked or tripped,
`403` limit/model/endpoint/approval denials (not retried), `429` only for
concurrency (retrying later is correct), `502` upstream failures. Every proxy
error carries an `x-keyleash-reason` header:
`locked`, `away_limit`, `budget_exceeded`, `concurrency`, `tripped`,
`model_denied`, `endpoint_denied`, `pass_invalid`, `pass_expired`,
`approval_denied`, `approval_timeout`.

### 10.5 Attribution

Each request records the client process (PID → image name) via the TCP owner
table, so the audit log answers "which program spent this".

## 11. Audit log

- Append-only JSONL under `audit/YYYY-MM.jsonl`.
- Each record: `{seq, ts, type, …fields, prev, hash}` where
  `hash = SHA-256(prev || canonical(record without hash))`. The first record of a
  file chains to the last hash of the previous file.
- While unlocked, the daemon periodically writes an `anchor` record carrying
  `HMAC(audit-anchor key, hash)`, so an attacker without the vault cannot
  rebuild a consistent chain after editing.
- Never contains secrets. Passes appear by id only. Keys appear by fingerprint
  only.
- Event types: `daemon_start`, `unlock`, `lock`, `away`, `present`, `trip`,
  `approval`, `pass_issue`, `pass_revoke`, `request` (provider, model, pass,
  client process, status, tokens, cost, estimated flag, latency, deny reason),
  `limit_change`, `slot_change`, `panic`, `anchor`.
- `keyleash audit verify` checks the chain and anchors.

## 12. Admin channel

- Windows: named pipe `\\.\pipe\keyleash-<user SID>` with a DACL granting only
  the current user. Unix: socket in the data dir, mode 0600.
- HTTP/JSON over the pipe. Endpoints (v1): `status`, `unlock`, `lock`, `away`,
  `panic`, `passes` (list/create/revoke), `limits` (get/set), `approvals`
  (list/decide), `usage`, `audit/tail`, `vault/entries` (list/add/remove/rotate),
  `vault/slots` (list/add/remove).
- Mutating calls that weaken protection require step-up regardless of caller.

## 13. CLI (v1)

```
keyleash init                       create vault, slots, recovery code, recommended config
keyleash daemon                     run the daemon (foreground)
keyleash status                     state, lease, spend vs limits, active passes
keyleash unlock | lock
keyleash add <provider> [--label]   add a key (read from hidden prompt or stdin; never argv)
keyleash keys                       list entries (masked, fingerprints)
keyleash run [--budget $] [--ttl] [--models] -- <cmd…>
                                    ephemeral process-bound pass; env injected; revoked on exit
keyleash env [--provider] [--shell] print base URL + pass exports for a shell (never keys)
keyleash pass create|list|revoke
keyleash limits [set …]
keyleash away --budget $ --for 8h   unattended grant
keyleash usage [--by pass|model|process] [--since]
keyleash scan [paths…]              find plaintext provider keys (files, env, shell history)
keyleash import <.env>              move keys into the vault, rewrite file to use passes (dry-run by default)
keyleash reveal <entry>             step-up, copy to clipboard (excluded from history), auto-clear 30 s
keyleash panic [--revoke-upstream]  lock, revoke all passes, optionally deactivate keys at provider
keyleash audit verify|tail
keyleash doctor                     environment checks (Hello, TPM, permissions, clock, ports)
```

Secrets are never accepted on the command line (argv is visible to other
processes and lands in shell history).

## 14. Configuration

TOML at `<data dir>/config.toml`. Every option has a recommended default; a
missing file means "recommended". Profiles: `recommended`, `strict`,
`relaxed`. `keyleash config check` validates and prints the effective config.

```toml
[proxy]
port = 47114
add_stream_usage = true

[presence]
idle_after = "10m"
screen_lock = "away"        # away | lock
away_max = "2h"
max_lease = "12h"

[limits.global]
request = "$2"
session = "$10"
day = "$20"
month = "$200"
concurrency = 8

[limits.away]
total = "$3"
concurrency = 2

[tripwire]
window = "5m"
threshold = "$5"

[models]
unknown = "approve"          # approve | deny | allow
deny = []

[limits.on_exceed]
action = "deny"              # deny | approve

[approval]
method = "hello"             # hello | console | deny
timeout = "60s"
```

## 15. Later phases (designed for, not in v0.1)

- **Usage reconciliation** (leak detector): with an optional admin key per
  provider, poll provider usage/cost APIs and compare against the ledger; a
  gap beyond tolerance raises an alert and can auto-lock or auto-revoke.
- **Upstream revoke** for `panic` via provider admin APIs.
- FIDO2 `hmac-secret` slot.
- Phone approvals (push via a self-hosted relay such as ntfy, end-to-end
  signed).
- `HTTPS_PROXY` mode with a local CA for tools that cannot set a base URL.
- Tray UI and toasts; macOS (Keychain + Touch ID) and Linux (Secret Service)
  slots.
- Daemon autostart helpers.
