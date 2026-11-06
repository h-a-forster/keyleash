# keyleash v0.1.0

First release of keyleash, a local credential broker and spend governor for
LLM API keys (Anthropic, OpenAI, Gemini, OpenRouter). Pre-alpha and
unaudited: try it with keys you can rotate.

## What it does

- Keeps provider keys in an encrypted local vault and gives tools a
  loopback-only **pass** instead of the key.
- Checks every request against hard limits (per request, session, day,
  month) before it is sent, and settles to the cost the provider reports.
- Ties access to your presence: idle time or a screen lock caps spending and
  locks the vault after `away_max`; sleep or lease expiry lock it at once
  (idle and screen-lock detection are Windows-only; the strict profile locks
  on a screen lock).
- Asks for Windows Hello, a passphrase or the recovery code before risky
  spend.
- Records every decision in a tamper-evident audit log.
- Refuses what it cannot identify: a process it cannot verify (a restricted
  shell, for example) may only read status, lock and panic, and is told why.
- `keyleash run -- <cmd>` gives one agent its own pass and budget, revoked
  when it exits.

## Platforms

Windows is the main platform. On Linux and macOS the vault, proxy and limits
work; process-bound passes (`keyleash run`), idle and screen-lock detection,
Windows Hello and DPAPI do not yet.

OpenRouter has no built-in price table: each request needs a step-up unless
the model is priced in a `pricing.override` file. Fallback lists and presets
are refused, because limits and model scopes can only speak for one model.

## Install

```sh
go install github.com/h-a-forster/keyleash/cmd/keyleash@v0.1.0
```

This needs Go 1.27.3 or later, which carries the current `crypto/x509`
denylist for the proxy's TLS connections to providers.

See [USAGE.md](USAGE.md) to get started and [CHANGELOG.md](../CHANGELOG.md)
for the full list.
