# keyleash

**A wallet for your AI API keys.**

An API key for Anthropic, OpenAI, Gemini or OpenRouter is a blank cheque.
Anyone who sees it (on a stream, in a screenshot, in a leaked `.env`) can
spend your money with it, and so can an agent stuck in a loop while you are
asleep. Providers only tell you afterwards, on the bill.

keyleash puts the key in an encrypted vault on your computer and hands your
tools a stand-in **pass** instead. A pass:

- **only works on your machine**: copied anywhere else, it is useless;
- **only works while you are there**: walk away, lock the screen or let the
  laptop sleep, and spending is capped or stopped;
- **only spends what you allow**: every request is checked against hard
  limits (per request, per session, per day, per month) *before* it is sent,
  so a runaway agent stops at the limit instead of at the bill.

Think of it as a hardware wallet for API keys: the key never leaves the
vault, and anything risky (a big spend, an unknown model, a long unattended
run) needs you to confirm with Windows Hello, like pressing the button on a
Ledger.

> **Status: pre-alpha.** The vault, proxy, budgets, presence lock and CLI
> work and are tested end to end, but the project is new and unaudited. Try
> it with keys you can rotate. Windows is the main platform; Linux and macOS
> run everything except Windows Hello and process-bound passes.

## Quick start

```sh
go install github.com/h-a-forster/keyleash/cmd/keyleash@latest
keyleash init                 # vault + recovery code (Windows Hello or a passphrase)
keyleash daemon --background  # start the daemon, then:
keyleash unlock
keyleash add anthropic        # paste the key at the hidden prompt, never on the command line
keyleash run --budget 5 -- claude
```

`keyleash run` starts the agent with its own pass and a $5 budget, points it
at keyleash, and revokes the pass when the agent exits. The agent never sees
the real key. `keyleash status` shows what is being spent; `keyleash lock` or
`keyleash panic` stops everything at once.

Editors and other long-lived tools use `keyleash env` instead. See
[docs/USAGE.md](docs/USAGE.md) for agents, SDKs, editors, defaults, limits,
approvals and troubleshooting.

## How it works

In technical terms, keyleash is a local credential broker and spend governor
for LLM API keys.

- **Vault.** Provider keys are stored with envelope encryption: a random
  256-bit data key seals each secret with XChaCha20-Poly1305 under
  authenticated metadata. The data key is unlocked through independent key
  slots (Windows Hello / TPM, an Argon2id passphrase, a one-time recovery code,
  optionally DPAPI). Keys are decrypted per request and never cached.
- **Proxy.** A loopback-only reverse proxy. Clients set their base URL
  (`ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, …) to keyleash and authenticate
  with a pass. keyleash verifies the pass, strips client credentials, injects
  the real key, and forwards only to a fixed set of provider hosts, never
  following redirects.
- **Hard limits.** Every metered request first *reserves* its worst-case cost
  (from `max_tokens` and a pessimistic input estimate) against hierarchical
  budgets: global, provider, pass, session, per-request. Once the response
  arrives, including streamed responses, it *settles* to the real cost the
  provider reported. Concurrency caps and a burn-rate tripwire stop runaway
  loops.
- **Presence.** Access is a lease. Idle time puts the daemon into *away mode*
  with tight limits; screen lock, sleep or lease expiry lock it.
- **Step-up approval.** Exceeding a limit, using an unknown model or making a
  long unattended run can require a fresh Windows Hello confirmation, like
  pressing the button on a hardware wallet.
- **Audit.** Every decision is written to a hash-chained log, anchored with a
  vault-derived key so edits are detectable. The log records which program made
  each request.
- **`keyleash run -- <cmd>`** gives one process its own pass with its own
  budget, revoked when the process exits.

## Why another tool

Existing tools (Infisical Agent Vault, LiteLLM, Tokfence) focus on **hiding**
the key from agents. keyleash also **governs** it:

| | keyleash |
|---|---|
| Bound to your presence | Idle → away limits; screen lock, sleep or lease end → locked |
| Limits hold under concurrency | Reserve-then-settle, not count-after-the-fact |
| Leaked passes are worthless | Loopback-only, scoped, expiring, optionally bound to one process |
| Confirm on device | Windows Hello step-up for risky spend |
| Hardware-bound vault | TPM-backed Hello slot, with passphrase and recovery slots so you can't lock yourself out |
| Tamper-evident record | Hash-chained, keyed audit log with per-process attribution |
| Small footprint | One static binary, no Docker, no database server |

## What it does not protect against

Malware already running as your user **while keyleash is unlocked** can use a
pass and read process memory. keyleash limits how much damage it can do
(budgets, presence, concurrency, audit), but it cannot prevent the use. An
administrator- or kernel-level attacker is out of scope. See
[docs/SPEC.md](docs/SPEC.md#3-threat-model).

## Docs

- [Usage](docs/USAGE.md): setup, agents, editors, defaults, troubleshooting
- [Specification](docs/SPEC.md): threat model, crypto design, behaviour
- [Plan](docs/PLAN.md): build phases

## License

MIT
