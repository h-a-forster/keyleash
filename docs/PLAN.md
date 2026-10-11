# Build plan

## Principles

- Windows first, portable by design: every OS-specific piece sits behind an
  interface, with a `_windows.go` implementation and a `_other.go` stub or
  fallback.
- Pure Go, no cgo. Dependencies limited to the Go standard library,
  `golang.org/x/crypto`, `golang.org/x/sys`, `github.com/BurntSushi/toml` and
  `github.com/Microsoft/go-winio`. New dependencies need a reason in review.
- No home-made cryptography. Only standard constructions (XChaCha20-Poly1305,
  HKDF-SHA256, HMAC-SHA256, Argon2id, RSA-OAEP via the OS) from the standard
  library or `x/crypto`.
- Fail closed. On ambiguity (unknown usage, unknown model, parse error, clock
  jump), choose the outcome that spends less and exposes less.
- Every package ships with table-driven tests; security-relevant behaviour
  (tamper detection, header stripping, redirect refusal, limit races) has
  explicit negative tests.

## Phase 1: engine packages (parallel)

Each package is independent and builds against the interfaces in the spec.

| Package | Deliverable | Done when |
|---|---|---|
| `secmem`, `vault` | Envelope vault, passphrase/recovery/DPAPI slots, hello slot interface, atomic I/O, tamper detection | Round-trip, tamper, wrong-slot, crash-recovery tests pass |
| `winhello` | Passport KSP key create/open, decrypt, sign-with-prompt; availability probe | Builds on Windows; non-interactive tests pass; `doctor` probe works |
| `meter` | Request inspection, pessimistic estimates, usage parsing (JSON + SSE for Anthropic, OpenAI chat/responses, Gemini), pricing table with sources | Golden tests over recorded request/response fixtures |
| `budget` | Ledger with scopes/windows, reserve/settle, concurrency, velocity tripwire, JSONL persistence + replay | Concurrency race tests (`-race` where available) prove no overshoot |
| `pass`, `audit` | Pass issue/verify/revoke/expiry/process binding; hash-chained audit log + verify | Constant-time verify, tamper detection tests |
| `presence`, `approval` | Idle/screen-lock/sleep detection; approval queue with coalescing, timeouts, grants; console/deny approvers; hello approver | State tests with a fake clock and fake input source |
| `proxy` | Inbound checks, routing, header hygiene, upstream client, streaming tee, error shapes | httptest suites incl. redirect, Host, Origin, header-smuggling negatives |

## Phase 2: daemon and CLI

- `config`: TOML, defaults, profiles, validation.
- `daemon`: state machine, wiring, admin API over named pipe.
- `cmd/keyleash`: `init`, `daemon`, `status`, `unlock`, `lock`, `add`, `keys`,
  `run`, `env`, `pass`, `limits`, `away`, `usage`, `audit`, `doctor`.
- End-to-end test: fake upstream over TLS, real daemon, real CLI.

## Phase 3: hardening

- Independent security review of the full tree; fix findings.
- `scan`, `import`, `reveal`, `panic`.
- Fuzz tests: vault parser, SSE parser, path matcher, pass parser.

## Phase 4: reach

- Usage reconciliation and upstream revoke via provider admin APIs.
- Tray UI with toasts and approvals; autostart.
- macOS and Linux slots; FIDO2 slot; phone approvals.
