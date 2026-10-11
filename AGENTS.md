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
