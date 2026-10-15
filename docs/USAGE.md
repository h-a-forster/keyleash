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
  Step-up approvals use Windows Hello when it is available, otherwise your
  passphrase or recovery code (`--approval` overrides: `hello`,
  `passphrase`, `console` or `deny`).
- keyleash then offers to start the daemon in the background and add your
  first key.

The data directory is `%LOCALAPPDATA%\keyleash` on Windows,
`~/Library/Application Support/keyleash` on macOS and `~/.config/keyleash` on
Linux. Set `KEYLEASH_HOME` to use another one.

### 3. Start the daemon and unlock

```sh
keyleash daemon               # foreground; Ctrl-C (or keyleash stop) stops it
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

The very first key goes straight into the vault. Every later key needs a
step-up approval (also after you removed every key: the exemption is used
once per vault) (Windows Hello, or your passphrase or recovery code), so a program
running as you cannot slip in a key of its own. Each pass keeps the
key it was created with; new passes use the provider's **active** key (its
oldest key, marked `*` in `keyleash keys`). To switch new passes to another
key: `keyleash keys use <id>` (step-up).

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

Variables that would bypass the pass are removed (`ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`,
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

A `run` pass needs no approval while it stays within the defaults: providers
you have keys for, lifetime up to `limits.pass.run_ttl` (12 h), every budget
up to `limits.pass.max_run_budget` ($10; without `--budget`/`--limit` the
pass gets $10 per session and per month), and concurrency up to
`limits.pass.concurrency`. Anything beyond that asks for a step-up.

Inside a `keyleash run` session, keyleash itself is off limits: the command
and everything it starts may only read `keyleash status`, lock, panic and
revoke its own pass. Creating passes, adding keys, approving, granting or
changing anything is refused with `confined`, so an agent cannot raise its
own budget.

What "everything it starts" means depends on the system. On Windows,
keyleash puts the command into a job object that only the daemon holds and
that its processes cannot leave: a process the agent starts stays confined
(and can use the run pass) even if its parent exits or it detaches, and it
stays confined after the run ends until it exits. When the daemon exits,
the run's processes are ended too (`[run] kill_on_daemon_exit = true`; set
it to `false` to let them keep running without keyleash). Restarting the
daemon ends earlier `keyleash run` passes. On Linux, macOS and the BSDs
keyleash cannot identify processes yet: passes there are not bound to a
process, `keyleash run` passes cannot be created, and no caller is treated
as confined.

The agent still runs as you and can read your files; a `--isolate` mode
that runs it under a restricted account is planned, not available.

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
machine, but treat it like a password anyway. Creating a named pass (and so
`keyleash env`) needs a step-up approval; no pass can be created while
keyleash is in away mode.

## Recommended defaults

Limits apply in every scope listed at once; the tightest one wins.

| Setting | recommended | strict | relaxed |
|---|---|---|---|
| Per request | $5 | $1 | $10 |
| Per session (resets on unlock) | $20 | $5 | $50 |
| Per day | $30 | $10 | $100 |
| Per month | $200 | $100 | $1000 |
| Parallel requests (global / per pass) | 8 / 4 | 4 / 2 | 16 / 8 |
| Away: total budget / parallel requests | $3 / 2 | $1 / 1 | $20 / 4 |
| New `run` passes while away | refused | refused | allowed |
| Largest unattended grant (`keyleash away`) | $50 | $20 | $200 |
| Idle before away | 10 min | 5 min | 30 min |
| Screen lock | away | lock | away |
| Away before locking | 2 h | 30 min | 8 h |
| Unlock lease | 12 h | 8 h | 24 h |
| Velocity tripwire (settled spend) | $5 in 5 min | $2 in 5 min | $25 in 5 min |
| Over a limit | deny | ask (step-up) | deny |
| Unknown model | ask (step-up) | deny | ask (step-up) |
| Named pass lifetime (run passes) | 24 h (12 h) | 8 h (12 h) | 7 d (12 h) |

Edit `config.toml` (`keyleash config path`), check it with
`keyleash config check`, and restart the daemon. Unknown keys are rejected
so a typo cannot silently weaken a limit. `keyleash limits` shows the
effective limits and how much of each is used.

Because any program running as you can edit `config.toml`, a changed config
does not take effect silently: at the next unlock keyleash is **tripped**
(`config_changed`), `keyleash status` and `keyleash unlock` list every
changed setting (`limits.global.day: $20 -> $500`), and `keyleash resume`
(step-up) accepts them.

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

**Models without a price** are reserved and charged at the provider's most
expensive rates for the tokens used. A request whose cost cannot be bounded
at all (for example web search with no cap on the number of searches)
reserves the per-request limit and needs a step-up; without a per-request
limit it is refused.

**Concurrency.** Too many parallel requests get `429 concurrency`; SDKs retry
those, which is correct.

**Away mode.** After `idle_after` without physical keyboard or mouse input
(input injected by automation tools does not count), or when the screen
locks (with `screen_lock = "away"`), keyleash enters away mode: existing
passes keep working under the away limits, no new passes can be created
(`run` passes only with `allow_new_run_passes`), and unknown models and
unbounded requests are denied. Coming back to the keyboard ends away mode.
After `away_max` in away mode, on sleep, or at the end of the lease,
keyleash locks: every request gets `423 locked` until `keyleash unlock`.

**Unattended runs.** Before leaving an agent running overnight:

```sh
keyleash away --budget 20 --for 8h [--pass <id>]
```

This needs a step-up approval, whose prompt shows exactly that amount,
duration and pass; each `keyleash away` call gets its own approval. A grant
is at most `limits.away.max_grant` ($50; strict $20, relaxed $200). While
the grant lasts, away mode uses the granted budget instead of the away
limits and does not lock after `away_max`.

**Tripwire.** If spend in the tripwire window crosses the threshold, the
ledger or audit log fails an integrity check after unlock (including a
deleted ledger), `passes.json` was edited, the config (or the pricing
override file it names) changed, or a security record could not be written
to the audit log, keyleash is **tripped**: new requests get `423 tripped`
and in-flight ones finish. Check `keyleash status` and `keyleash audit
verify`, then leave it with `keyleash resume` (step-up). Resuming after a
failed audit check moves the rejected log to `audit/rejected-<time>/` and
starts a new chain. Resuming after `passes.json` changed (`keyleash status`
lists the added, removed and changed passes) revokes every added or changed
pass. After a config change, an integrity failure or an edited
`passes.json`, the resume is approved with the approval method of the
config you last accepted, never with the one the changed file names: if
that is `console` or `deny`, or Windows Hello is unavailable, `keyleash
resume` asks for your passphrase or recovery code.

**Step-up approvals prove you are there.** Every program running as you can
reach keyleash's admin channel, including the agents it governs, so being
able to call it proves nothing. A step-up is one of: a Windows Hello prompt,
your vault passphrase or recovery code (checked by the vault), or an answer
typed into the daemon's own terminal. Step-ups are needed for unknown models
(with `models.unknown = "approve"`), requests whose cost cannot be bounded,
going over a limit (with `limits.on_exceed = "approve"`), unattended grants,
leaving Tripped, creating passes beyond the `run` defaults, adding keys
(after the first), `keyleash keys use`, removing keys, rotating the recovery
code and removing vault slots. The request waits up to `approval.timeout`
(60 s):

- `approval.method = "hello"` (default with Windows Hello): a Hello prompt
  describes the request.

Every prompt names the program and PID that asked, then what is at stake
(amount, providers, limits, lifetime, binding); a request whose description
would not fit the prompt is refused rather than shown cut off. A config
change shows how many keys changed, naming approval, limit, model, pricing
and presence keys first; `keyleash status` lists them all.
- `"passphrase"` (set by `init` when Hello is unavailable): the command that
  needs the approval asks for your passphrase or recovery code at a hidden
  prompt; from another terminal, `keyleash approvals approve <id>` does the
  same.
- `"console"`: the daemon's terminal asks `Approve? [y/N]`; the passphrase
  route works too.
- `"deny"`: every step-up is refused (servers, CI).

With every method except `deny`, `keyleash approvals approve <id>` approves
with your passphrase or recovery code (`--stdin` reads it from standard
input). Wrong secrets are recorded in the audit log and slowed down: after
five from one program, that program waits 30 s, doubling up to 15 min; after
ten from all programs together, every attempt waits 2 s, doubling up to
1 min. Only one secret is checked at a time. `keyleash approvals deny <id>` needs
nothing. Each approval belongs to the one request that asked: two commands
never share an approval, and approving an over-limit request admits exactly
that request without raising the limit. `approve <id> --grant 10 --for 1h`
on an over-limit request lets that pass exceed that one limit by up to the
grant for later requests; grants are capped at `approval.grant_max_multiple`
(5) times the limit and `approval.grant_max_duration` (24 h), shown by
`keyleash approvals --json`.

**Panic.** `keyleash panic` locks immediately and revokes every pass. Any
program may lock or panic, including one inside `keyleash run`. Rotate
the keys at the provider if you think one leaked; automatic upstream
revocation is not implemented yet.

**Stopping the daemon.** `keyleash stop` shuts the daemon down like Ctrl-C
in its terminal: in-flight requests get up to 30 s (any still running are
charged at their reserved amount), spend is saved, the vault locks, and
with `[run] kill_on_daemon_exit` (default) programs started by `keyleash
run` end. The command returns once the daemon has finished shutting down
(it releases its instance lock last). It needs no step-up (a stopped daemon
spends nothing) but is refused from inside `keyleash run`; use lock or
panic there. That refusal is defence in depth, not a boundary: a program
running as your user can end the daemon process directly. The request is
in the audit log.

**Rotating the recovery code.** `keyleash recovery rotate` (unlocked,
step-up: Hello, your passphrase or the current recovery code) prints a new
code once, like `init`, and asks you to re-type its last group. The vault
gets a new data key, so the old code opens neither `vault.json` nor
`vault.prev` (if keyleash is killed in the middle of the rotation,
`vault.prev` can keep the old key until the next unlock, which replaces it
and records `prev_scrub` in the audit log). Backups of the vault file made
before the rotation still open with the old code and show the keys as they
were then; rotate provider keys if the old code may have leaked.
Interrupting the command while it waits for approval cancels the rotation.
If the connection is lost while the rotation is being committed, the
command checks the audit log and tells you whether it happened; if it did,
the old code no longer works and the new one is lost, so run `keyleash
recovery rotate` again.

**Audit.** Every decision is in a hash-chained log. `keyleash audit tail`
shows recent records (passes by id, keys by fingerprint, never secrets);
`keyleash audit verify` checks the chain, and the keyed anchors while
unlocked. `keyleash usage` shows spend by pass, model, provider and program.

## Command reference

| Command | What it does |
|---|---|
| `init` | create the vault, recovery code and config |
| `daemon [--background]` / `stop` | run the daemon / stop it gracefully (refused inside `keyleash run`) |
| `status [--json]` | state, lease, spend vs limits, active passes |
| `unlock [--recovery] [--stdin]` / `lock` | unlock or lock the vault |
| `add <provider> [--label] [--stdin]` | store a key (hidden prompt or stdin) |
| `keys [--json]` / `keys use <id>` / `rm-key <id>` | list (masked, `*` = active), choose a provider's active key, or remove keys |
| `run [flags] -- <cmd…>` | run a command with its own pass |
| `env [--shell] [flags]` | create a named pass and print exports |
| `pass create\|list\|revoke` | manage named passes |
| `limits [--json]` | effective limits and current spend |
| `away --budget --for [--pass]` / `resume` | unattended grant / leave Tripped |
| `usage [--by] [--since] [--json]` | spend by pass, model, provider, process |
| `approvals [approve <id> [--grant --for] [--stdin]\|deny <id>]` | pending step-up requests; approving asks for the passphrase or recovery code |
| `audit verify\|tail` | check or read the audit log |
| `config show\|check\|path` | effective configuration |
| `recovery rotate` | new recovery code, shown once; re-keys the vault (step-up) |
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
| HTTP `423 tripped` | The tripwire or an integrity check fired, or `config.toml` changed. `keyleash status`, `keyleash audit verify`, then `keyleash resume`. |
| `refused: this command runs inside a keyleash run session` (`confined`) | Admin commands other than `status` are refused from inside `keyleash run` (and from processes keyleash cannot identify). Run them from a normal terminal. |
| `too many wrong passphrases or recovery codes` | Approving with a secret is slowed down after five wrong tries. Wait the time shown. |
| HTTP `401 pass_invalid` | Wrong, revoked or expired pass, or a `run` pass used from outside its process tree (e.g. a tool started separately). Use `keyleash run` for that tool or a named pass from `keyleash env`. |
| HTTP `403 budget_exceeded` | A limit is used up. `keyleash limits` shows which; wait for the window, raise it in config, or use `on_exceed = "approve"`. |
| HTTP `403 model_denied` / `approval_denied` / `approval_timeout` | The model is denied or unknown and the step-up was refused or not answered in time. Check `keyleash approvals` while the request waits. |
| HTTP `429 concurrency` | Too many parallel requests for the global or pass limit; SDKs retry. |
| `passes ... away mode` | New passes are refused while away. Touch the keyboard, or use `keyleash away --budget … --for …` first. |
| `no terminal for a hidden prompt` | Standard input is not a console (for example Git Bash's mintty, or a pipe). Use `winpty keyleash …`, PowerShell/cmd, or `--stdin`. |
| A tool still uses the real key | It reads a different variable or a config file. Remove the key from that file, and set the tool's base URL and key to the values from `keyleash env`. |
| Requests go to a corporate proxy | `keyleash run`/`env` add loopback to `NO_PROXY`; tools that ignore `NO_PROXY` need their proxy setting changed. |
| `proxy port … used by another program` | Free port 47114 or set `[proxy] port` and restart. |
| `the vault file is older than the last recorded state` | A backup was restored or the file rolled back (also detected when `vault.prev` is newer than `vault.json`, e.g. an old file restored without `vault.seq`); the message shows the file's write number and the recorded one. If that was you: `keyleash unlock --accept-rollback` (passphrase, recovery code or Hello; it applies to that unlock only, is recorded in the audit log, and the regression is shown again). Review `keyleash keys` and vault slots afterwards. |
| `pass_store` trip / `pass store change: …` | `passes.json` no longer matches what keyleash recorded in the vault (edited, replaced or rolled back). `keyleash resume` revokes the added and changed passes; create new ones. |
| Restoring a backup of the whole data directory | Restoring vault, ledger, audit log and passes.json together to an earlier point cannot be told apart from a deliberate restore: spend recorded since the backup is forgotten and passes revoked since then come back. Keep backups where agents cannot write, and revoke passes after a restore (`keyleash panic`, then unlock). |
| `presence detection is degraded` | Low-level input hooks could not be installed; idle time falls back to `GetLastInputInfo`, which also counts injected input. |
| `approval.method is hello but Windows Hello is unavailable` | Every step-up is denied. Set `approval.method = "passphrase"` in config. |
| Forgot the passphrase | `keyleash unlock --recovery` with the recovery code. |
