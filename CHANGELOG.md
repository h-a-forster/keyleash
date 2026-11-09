# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

## v0.1.1 - 2026-11-09

Fixes from a state-machine audit of v0.1.0: [release notes](docs/release-notes-v0.1.1.md).

## v0.1.0 - 2026-10-30

First release. Pre-alpha: unaudited; use keys you can rotate.

### Added

- Encrypted vault: envelope encryption (XChaCha20-Poly1305) with Windows
  Hello / TPM, Argon2id passphrase, one-time recovery code and optional DPAPI
  key slots; re-keyable slots and anti-rollback checks.
- Loopback reverse proxy for Anthropic, OpenAI, Gemini and OpenRouter:
  pass verification, credential stripping and key injection, fixed upstream
  hosts, no redirects, streaming usage metering.
- Hard limits with reserve-then-settle accounting across global, provider,
  pass, session and per-request scopes; concurrency caps and a burn-rate
  tripwire. Provider refusals (4xx, 529) settle at $0.
- Presence lease with away mode on idle and lock on screen lock, sleep or
  lease expiry (idle and screen-lock detection are Windows-only).
- Step-up approval (Windows Hello, passphrase or recovery code) for limit
  overruns, unknown models and long unattended runs.
- Hash-chained, vault-anchored audit log with per-process attribution and
  secret redaction.
- CLI: `init`, `daemon`, `stop`, `status`, `unlock`, `lock`, `add`, `keys`,
  `rm-key`, `run`, `env`, `pass`, `limits`, `away`, `resume`, `usage`,
  `approvals`, `audit`, `config`, `recovery rotate`, `doctor`, `panic`.
- `keyleash run` gives one process tree its own pass and budget, confined in
  a Windows job object and revoked on exit.
- CI on Windows, Linux and macOS (`go vet`, `gofmt`, `go test`).

### Known limitations

- On Linux and macOS: no process identity (no `keyleash run`, no
  process-bound passes, no per-request client attribution), no idle or
  screen-lock detection, no Windows Hello or DPAPI slot.
- `panic --revoke-upstream` is accepted but not implemented.
