# Backlog

## In progress

## Waiting on me

- `upgrades-2026-10-23` proven on the `ubuntu-latest` CI job through a PR, then in or out of v0.1.0 decided; its README, USAGE and CHANGELOG conflict with `polish-2026-10-30`, so merge polish first.
- Dependabot PR #2 (go-winio 0.6.4) merged; its diff is go.mod, go.sum and the upstream code generator only.

## Decided

- 2026-11-06: OpenRouter fallback lists and presets are refused, not checked model by model: the reservation and the approval prompt can only speak for one model.
- 2026-11-06: a screen lock stays "away" in the recommended profile and "lock" in strict; the docs follow the code.
- 2026-11-06: a parent the OS will not reveal ends the process walk instead of counting as confined; job membership covers run-tree descendants.

## Proposed

- Independent security review of the full tree.
- `scan`, `import` and `reveal` commands.
- `panic --revoke-upstream` deactivates keys through the provider admin APIs.
- Idle and screen-lock detection on macOS and Linux, and process identity on macOS.
- `keyleash run --isolate` keeps an agent out of the owner's files.
- `keyleash doctor` lists the models seen in traffic without a price.
- Pricing table refreshed: gpt-6.1-terra and the Mythos models added, gpt-5.6-sol promo end date rechecked before 2026-11-21.
- Fuzz targets for the ledger, audit log and pass store loaders.
- `keyleash doctor` says whether the daemon can identify the calling process.
- `TestRunEndToEnd` runs without reaching the per-user admin pipe, so it neither probes a real daemon nor skips beside one.
- `tmp/` scratch Go packages stay out of `go test ./...` and `go vet ./...`.
- README lead paragraph no longer implies a cryptographic machine binding: "only works on your machine" is loopback plus optional process binding.
