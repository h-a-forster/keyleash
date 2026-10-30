# keyleash v0.1.0

First release of keyleash, a local credential broker and spend governor for
LLM API keys (Anthropic, OpenAI, Gemini, OpenRouter). Pre-alpha and
unaudited: try it with keys you can rotate.

## What it does

- Keeps provider keys in an encrypted local vault and gives tools a
  loopback-only **pass** instead of the key.
- Checks every request against hard limits (per request, session, day,
  month) before it is sent, and settles to the cost the provider reports.
- Ties access to your presence: idle time caps spending, screen lock, sleep
  or lease expiry lock the vault (Windows).
- Asks for Windows Hello, a passphrase or the recovery code before risky
  spend.
- Records every decision in a tamper-evident audit log.
- `keyleash run -- <cmd>` gives one agent its own pass and budget, revoked
  when it exits.

## Platforms

Windows is the main platform. On Linux and macOS the vault, proxy and limits
work; process-bound passes (`keyleash run`), idle and screen-lock detection,
Windows Hello and DPAPI do not yet.

## Install

```sh
go install github.com/h-a-forster/keyleash/cmd/keyleash@v0.1.0
```

See [USAGE.md](USAGE.md) to get started and [CHANGELOG.md](../CHANGELOG.md)
for the full list.
