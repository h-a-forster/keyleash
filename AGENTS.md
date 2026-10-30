# Contributor notes

- Language: Go (see `go.mod`), pure Go, no cgo. Allowed dependencies are listed
  in `docs/PLAN.md`; do not add others without discussion.
- Read `docs/SPEC.md` before changing behaviour. The spec is normative; if code
  and spec disagree, fix one of them in the same change.
- Layout: `cmd/keyleash` (CLI), `internal/<package>` (engine). OS-specific code
  goes in `*_windows.go` with a portable fallback in `*_other.go`
  (`//go:build !windows`).
- Money is `money.Micros` (int64 micro-USD). Never use floats for balances.
- Never log, print or put in errors: provider keys, pass secrets, passphrases,
  recovery codes, DEKs. Identify keys by fingerprint and passes by id.
- Fail closed: on uncertainty, deny or charge the reserved amount.
- Checks before sending a change:
  `gofmt -l .` (no output), `go vet ./...`, `go test ./...`.
- Scratch scripts go in `tmp/` (git-ignored).
- Update `CHANGELOG.md` under "Unreleased" with each user-visible change.

## Status and next steps (2026-10-30)

- v0.1.0 is prepared (CHANGELOG, `docs/release-notes-v0.1.0.md`) but not
  tagged. Build phases 1 and 2 of `docs/PLAN.md` are done, plus `panic`,
  `stop` and `recovery rotate`.
- Branch `upgrades-2026-10-23` (Linux process identity, SECURITY.md,
  CITATION.cff, refusing binds to PID 1 or a daemon ancestor) is not merged:
  its Linux code has only been compiled from Windows and must pass the
  `ubuntu-latest` CI job first.
- Open (phase 3): independent security review; `scan`, `import`, `reveal`;
  fuzz tests for the vault, SSE, path-matcher and pass parsers (none yet).
- Open: `panic --revoke-upstream` (flag accepted, not implemented); idle and
  screen-lock detection and process identity on macOS and Linux.
