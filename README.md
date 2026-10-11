# keyleash

**A wallet for your AI API keys.**

> Status: pre-alpha. The engine is under active development; nothing here is
> ready to protect real keys yet.

## What it is

keyleash keeps your real AI API keys locked on your computer. Your coding
agents and tools get a stand-in *pass* instead, one that only works on your
machine, only while you are there, and only up to a spending limit you set.

- Walk away, fall asleep or lock your screen, and spending is capped or stopped.
- An agent goes haywire and spawns a swarm? It hits a hard limit and stops.
- A pass shows up on a stream or in a screenshot? It is useless to whoever
  copies it.

## Quick start

```sh
go install github.com/h-a-forster/keyleash/cmd/keyleash@latest
keyleash init                 # vault + recovery code (Windows Hello or a passphrase)
keyleash daemon --background  # start the daemon, then:
keyleash unlock
keyleash add anthropic        # paste the key at the hidden prompt, never on the command line
keyleash run --budget 5 -- claude
```

Editors and other long-lived tools use `keyleash env` instead. See
[docs/USAGE.md](docs/USAGE.md) for agents, SDKs, editors, defaults, limits,
approvals and troubleshooting.

## How it works

keyleash is a local credential broker and spend governor for LLM API keys.

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

- [Specification](docs/SPEC.md): threat model, crypto design, behaviour
- [Plan](docs/PLAN.md): build phases

## License

MIT
