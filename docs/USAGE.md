# Using keyleash

> keyleash is pre-alpha. Try it with keys you can rotate, and read the
> [threat model](SPEC.md#3-threat-model) first.

keyleash keeps your provider API keys in an encrypted vault and gives your
tools *passes* instead: stand-ins that only work against the local proxy,
only while you are there, and only up to the limits you set.

- [Quick start](#quick-start)
- [Running agents and SDKs](#running-agents-and-sdks)
- [Editors and long-lived tools](#editors-and-long-lived-tools)
- [Recommended defaults](#recommended-defaults)
- [How limits, away mode and approvals behave](#how-limits-away-mode-and-approvals-behave)
- [Command reference](#command-reference)
- [Troubleshooting](#troubleshooting)

## Quick start

### 1. Install

keyleash is a single Go binary (Go 1.27 or later, no cgo):

```sh
go install github.com/h-a-forster/keyleash/cmd/keyleash@latest
```

or from a checkout, with the version embedded:

```sh
go build -ldflags "-X main.version=$(git describe --tags --always)" -o keyleash ./cmd/keyleash
```

Windows is the primary platform. On Linux and macOS the vault, proxy and
budgets work, but process-bound passes (`keyleash run`) are not supported yet.

### 2. Create the vault

```sh
keyleash init
```

- With Windows Hello available, the vault is unlocked with Hello (PIN,
  fingerprint or face). Otherwise you choose a passphrase of at least 12
  characters and type it twice.
- A **recovery code** is printed once. Write it down, store it offline, and
  type its last group back to confirm. It is the only way in if Hello or the
  passphrase is lost.
- A commented `config.toml` with the recommended profile is written
  (`--profile strict` or `--profile relaxed` pick another starting point).
- keyleash then offers to start the daemon in the background and add your
  first key.

The data directory is `%LOCALAPPDATA%\keyleash` on Windows,
`~/Library/Application Support/keyleash` on macOS and `~/.config/keyleash` on
Linux. Set `KEYLEASH_HOME` to use another one.

### 3. Start the daemon and unlock

```sh
keyleash daemon               # foreground; Ctrl-C stops it
keyleash daemon --background  # or detached, logging to <data dir>/daemon.log
keyleash unlock               # Windows Hello, or the passphrase at a hidden prompt
```

The daemon starts **locked**. Unlocking starts a lease (12 hours by default);
locking the screen, sleeping or reaching the end of the lease locks it again.

### 4. Add a key

```sh
keyleash add anthropic        # paste the key at the hidden prompt
keyleash add openai --label work
```

Keys are never accepted on the command line (`keyleash add anthropic sk-ant-…`
is refused without echoing the key), because arguments are visible to other
processes and saved in shell history. To pipe a key from a password manager:

```sh
op read "op://Private/Anthropic/credential" | keyleash add anthropic --stdin
```

Then remove the key from any `.env` file, shell profile or tool config it
lived in.

### 5. Run something

```sh
keyleash run -- claude
```

## Running agents and SDKs

`keyleash run [flags] -- <command> [args…]` creates a pass just for that
command, bound to the keyleash process (the command and everything it starts
can use it, nothing else can), runs the command with the right environment,
and revokes the pass when the command exits. The exit code is the command's.

For each provider the pass covers, the command gets:

| Variable | Example value |
|---|---|
| base-URL variable | `ANTHROPIC_BASE_URL=http://127.0.0.1:47114/anthropic`, `OPENAI_BASE_URL=http://127.0.0.1:47114/openai/v1` |
| key variable | `ANTHROPIC_API_KEY=klp_…`, `OPENAI_API_KEY=klp_…` (the pass, never the key) |
| `KEYLEASH_<PROVIDER>_BASE_URL` | same as the base URL, for tools that need it set by hand |
| `KEYLEASH_PROXY`, `KEYLEASH_PASS_ID` | proxy root and the pass id |

Variables that would bypass the pass are removed (`ANTHROPIC_AUTH_TOKEN`,
`OPENAI_API_BASE`, `GOOGLE_API_KEY`). If an outbound proxy (`HTTPS_PROXY`…)
is set, loopback is added to `NO_PROXY`.

By default the pass covers the providers you stored keys for that have a
standard base-URL variable (Anthropic and OpenAI). OpenRouter and Gemini have
no such variable, so name them with `--providers` and point the tool at
`$KEYLEASH_OPENROUTER_BASE_URL` / `$KEYLEASH_GEMINI_BASE_URL`.

Examples:

```sh
# Claude Code with a $5 budget, Sonnet models only
keyleash run --budget 5 --models 'claude-sonnet-*' -- claude

# Codex CLI (use API-key authentication, not ChatGPT sign-in)
keyleash run --providers openai --budget 3 -- codex

# Any SDK script: the official Anthropic and OpenAI SDKs read these variables
keyleash run --budget 2 -- python agent.py
keyleash run -- node agent.mjs
```

If Claude Code asks whether to use the API key it found in the environment,
accept: that value is the pass.

Flags: `--budget` (total for this run), `--limit window=amount` (per window,
repeatable), `--ttl` (default 12 h), `--providers`, `--models` and
`--deny-models` (globs; `*` matches anything, including `/`),
`--concurrency`, `--name` (shown in `usage` and the audit log).

In bash and zsh write amounts as `5` or `'$5'`: `"$5"` is expanded by the
shell.

## Editors and long-lived tools

Editors, IDE extensions and desktop apps are not children of `keyleash run`,
so they use a **named pass** instead. `keyleash env` creates one and prints
the exports for your shell (detected automatically, or `--shell`):

```powershell
# PowerShell
keyleash env --name vscode | Invoke-Expression
code .
```

```sh
# bash / zsh
eval "$(keyleash env --name vscode)"
# fish
keyleash env --name vscode --shell fish | source
```

```bat
:: cmd.exe
keyleash env --shell cmd > "%TEMP%\kl.cmd" && call "%TEMP%\kl.cmd" && del "%TEMP%\kl.cmd"
```

Start the editor from that shell so it inherits the variables, or paste the
base URL and the pass into the tool's "API base URL" and "API key" settings.
Named passes expire (24 hours by default; `--ttl 7d` for longer) and accept
the same scope flags as `run`. Manage them with:

```sh
keyleash pass list
keyleash pass create --name ci-runner --providers openai --limit day=2 --ttl 7d
keyleash pass revoke <id>
```

`pass create` prints the token once on stdout. A pass is worthless off this
machine, but treat it like a password anyway.

## Recommended defaults

Limits apply in every scope listed at once; the tightest one wins.

| Setting | recommended | strict | relaxed |
|---|---|---|---|
| Per request | $2 | $1 | $10 |
| Per session (resets on unlock) | $10 | $5 | $50 |
| Per day | $20 | $10 | $100 |
| Per month | $200 | $100 | $1000 |
| Parallel requests (global / per pass) | 8 / 4 | 4 / 2 | 16 / 8 |
| Away: total budget / parallel requests | $3 / 2 | $1 / 1 | $20 / 4 |
| New `run` passes while away | refused | refused | allowed |
| Idle before away | 10 min | 5 min | 30 min |
| Screen lock | away | lock | away |
| Away before locking | 2 h | 30 min | 8 h |
| Unlock lease | 12 h | 8 h | 24 h |
| Velocity tripwire | $5 in 5 min | $2 in 5 min | $25 in 5 min |
| Over a limit | deny | ask (step-up) | deny |
| Unknown model | ask (step-up) | deny | ask (step-up) |
| Named pass lifetime (run passes) | 24 h (12 h) | 8 h (12 h) | 7 d (12 h) |

Edit `config.toml` (`keyleash config path`), check it with
`keyleash config check`, and restart the daemon. Unknown keys are rejected
so a typo cannot silently weaken a limit. `keyleash limits` shows the
effective limits and how much of each is used.

## How limits, away mode and approvals behave

**Hard limits.** Before forwarding a request, keyleash reserves its
worst-case cost (a pessimistic input estimate plus `max_tokens` at the
model's output rate) against every applicable limit. When the response
arrives (streamed or not) the reservation settles to the real cost the
provider reported. If the real usage cannot be read, the full reservation is
charged. Parallel requests therefore cannot overshoot a limit. A request
that would exceed a limit gets HTTP `403` with `x-keyleash-reason:
budget_exceeded` (not `429`, so SDKs do not retry it), and a message naming
the limit.

**Concurrency.** Too many parallel requests get `429 concurrency`; SDKs retry
those, which is correct.

**Away mode.** After `idle_after` without physical keyboard or mouse input
(input injected by automation tools does not count), or when the screen
locks (with `screen_lock = "away"`), keyleash enters away mode: existing
passes keep working under the away limits, new `run` passes are refused,
and unknown models are denied. Coming back to the keyboard ends away mode.
After `away_max` in away mode, on sleep, or at the end of the lease,
keyleash locks: every request gets `423 locked` until `keyleash unlock`.

**Unattended runs.** Before leaving an agent running overnight:

```sh
keyleash away --budget 20 --for 8h [--pass <id>]
```

This needs a step-up approval. While the grant lasts, away mode uses the
granted budget instead of the away limits and does not lock after
`away_max`.

**Tripwire.** If spend in the tripwire window crosses the threshold, or the
ledger or audit log fails an integrity check, keyleash is **tripped**: new
requests get `423 tripped` and in-flight ones finish. Check `keyleash status`
and `keyleash audit verify`, then leave it with `keyleash resume` (step-up).

**Step-up approvals** are needed for unknown models (with
`models.unknown = "approve"`), going over a limit (with
`limits.on_exceed = "approve"`), unattended grants, leaving Tripped and
removing keys. The request waits up to `approval.timeout` (60 s):

- `approval.method = "hello"` (default with Windows Hello): a Hello prompt
  describes the request. `keyleash approvals deny <id>` can refuse it, but
  approving is only possible at the prompt, so a program running as you
  cannot approve its own request.
- `"console"` (set by `init` when Hello is unavailable): the daemon's
  terminal asks `Approve? [y/N]`; `keyleash approvals approve <id>` works
  too. Any program running as your user could also call it, so prefer Hello
  where you can.
- `"deny"`: every step-up is refused (servers, CI).

`keyleash approvals` lists what is waiting. `approve <id> --grant 10 --for 1h`
attaches an allowance so one approval covers follow-up requests.

**Panic.** `keyleash panic` locks immediately and revokes every pass. Rotate
the keys at the provider if you think one leaked; automatic upstream
revocation is not implemented yet.

**Audit.** Every decision is in a hash-chained log. `keyleash audit tail`
shows recent records (passes by id, keys by fingerprint, never secrets);
`keyleash audit verify` checks the chain, and the keyed anchors while
unlocked. `keyleash usage` shows spend by pass, model, provider and program.

## Command reference

| Command | What it does |
|---|---|
| `init` | create the vault, recovery code and config |
| `daemon [--background]` | run the daemon |
| `status [--json]` | state, lease, spend vs limits, active passes |
| `unlock [--recovery] [--stdin]` / `lock` | unlock or lock the vault |
| `add <provider> [--label] [--stdin]` | store a key (hidden prompt or stdin) |
| `keys [--json]` / `rm-key <id>` | list (masked) or remove keys |
| `run [flags] -- <cmd…>` | run a command with its own pass |
| `env [--shell] [flags]` | create a named pass and print exports |
| `pass create\|list\|revoke` | manage named passes |
| `limits [--json]` | effective limits and current spend |
| `away --budget --for [--pass]` / `resume` | unattended grant / leave Tripped |
| `usage [--by] [--since] [--json]` | spend by pass, model, provider, process |
| `approvals [approve\|deny <id>]` | pending step-up requests |
| `audit verify\|tail` | check or read the audit log |
| `config show\|check\|path` | effective configuration |
| `doctor [--json]` | environment checks |
| `panic [--revoke-upstream]` | lock and revoke every pass |
| `version`, `help [command]` | |

Read commands accept `--json`. `keyleash help <command>` has details.

## Troubleshooting

`keyleash doctor` checks Windows Hello, the data directory's permissions,
the config, the daemon, the proxy port, the clock, presence detection and
how old the pricing table is. Start there.

| Symptom | Cause and fix |
|---|---|
| `the keyleash daemon is not running` | Start it: `keyleash daemon` (or `--background`). |
| `keyleash is locked — run: keyleash unlock` / HTTP `423 locked` | The screen locked, the machine slept, the lease ended or you were away too long. Unlock. |
| HTTP `423 tripped` | The tripwire or an integrity check fired. `keyleash status`, `keyleash audit verify`, then `keyleash resume`. |
| HTTP `401 pass_invalid` | Wrong, revoked or expired pass, or a `run` pass used from outside its process tree (e.g. a tool started separately). Use `keyleash run` for that tool or a named pass from `keyleash env`. |
| HTTP `403 budget_exceeded` | A limit is used up. `keyleash limits` shows which; wait for the window, raise it in config, or use `on_exceed = "approve"`. |
| HTTP `403 model_denied` / `approval_denied` / `approval_timeout` | The model is denied or unknown and the step-up was refused or not answered in time. Check `keyleash approvals` while the request waits. |
| HTTP `429 concurrency` | Too many parallel requests for the global or pass limit; SDKs retry. |
| `run passes ... away mode` | New `run` passes are refused while away. Touch the keyboard, or use `keyleash away --budget … --for …` first. |
| `no terminal for a hidden prompt` | Standard input is not a console (for example Git Bash's mintty, or a pipe). Use `winpty keyleash …`, PowerShell/cmd, or `--stdin`. |
| A tool still uses the real key | It reads a different variable or a config file. Remove the key from that file, and set the tool's base URL and key to the values from `keyleash env`. |
| Requests go to a corporate proxy | `keyleash run`/`env` add loopback to `NO_PROXY`; tools that ignore `NO_PROXY` need their proxy setting changed. |
| `proxy port … used by another program` | Free port 47114 or set `[proxy] port` and restart. |
| `the vault file is older than the last recorded state` | A backup was restored or the file rolled back. If that was you: `keyleash unlock --accept-rollback`. |
| `presence detection is degraded` | Low-level input hooks could not be installed; idle time falls back to `GetLastInputInfo`, which also counts injected input. |
| `approval.method is hello but Windows Hello is unavailable` | Every step-up is denied. Set `approval.method = "console"` in config. |
| Forgot the passphrase | `keyleash unlock --recovery` with the recovery code. |
