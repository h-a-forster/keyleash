package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/secmem"
)

// maxSecretInput bounds a secret read from a prompt or stdin.
const maxSecretInput = 64 << 10

// minKeyTail is how many characters must follow a known key prefix for an
// argument to be treated as a key ("sk-" alone is not a key).
const minKeyTail = 16

// errInterrupted is returned when the user aborts a prompt.
var errInterrupted = errors.New("interrupted")

var recoveryCodeRE = regexp.MustCompile(`^[0-9A-Za-z]{4}(-[0-9A-Za-z]{4}){7}$`)

// looksLikeSecret reports whether s looks like a provider key, a keyleash
// pass or a recovery code. It errs towards "yes": a false positive costs a
// re-typed command, a false negative leaks a key into shell history.
func looksLikeSecret(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if pass.LooksLikePass(s) || (strings.HasPrefix(s, pass.Prefix) && len(s) > 20) {
		return true
	}
	if recoveryCodeRE.MatchString(s) {
		return true
	}
	if strings.HasPrefix(strings.ToLower(s), "bearer ") {
		return looksLikeSecret(s[len("bearer "):]) || len(s) > 30
	}
	for _, name := range provider.Names() {
		p, _ := provider.Get(name)
		for _, pre := range p.KeyPrefixes {
			if strings.HasPrefix(s, pre) && len(s) >= len(pre)+minKeyTail {
				return true
			}
		}
	}
	return false
}

// rejectSecretArgs fails if any argument before "--" looks like a secret,
// including the value part of --flag=value. Arguments are visible to other
// processes and end up in shell history, so secrets never belong there.
// The offending value is never echoed.
func rejectSecretArgs(args []string) error {
	for i, arg := range args {
		if arg == "--" {
			return nil
		}
		cands := []string{arg}
		if strings.HasPrefix(arg, "-") {
			if _, v, ok := strings.Cut(arg, "="); ok {
				cands = append(cands, v)
			}
			cands = append(cands, strings.TrimLeft(arg, "-"))
		}
		for _, c := range cands {
			if looksLikeSecret(c) {
				return fmt.Errorf("argument %d looks like an API key, pass or recovery code; "+
					"keyleash never takes secrets on the command line (other processes can read "+
					"arguments and shells save them in history). Enter it at the hidden prompt, "+
					"or pipe it in with --stdin. If it was a real key, consider rotating it", i+1)
			}
		}
	}
	return nil
}

// readSecret reads one secret: from a hidden terminal prompt, or from the
// first line of stdin when fromStdin is set. The line ending is removed. The
// caller wipes the result.
func (a *app) readSecret(prompt string, fromStdin bool) ([]byte, error) {
	if fromStdin {
		return readLineBounded(a.stdin)
	}
	if !a.interactive() {
		return nil, errors.New("no terminal for a hidden prompt; pipe the secret in with --stdin")
	}
	return readHidden(a.stdinFile, a.stderr, prompt)
}

// readLineBounded reads up to the first newline (or EOF) from r, without
// buffering past it, and returns the line without its line ending. It
// reads one byte at a time so that a following read from r (a second line)
// still sees its data.
func readLineBounded(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 128)
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			if len(buf) >= maxSecretInput {
				secmem.Wipe(buf)
				return nil, errors.New("input too long")
			}
			if len(buf) == cap(buf) {
				nb := make([]byte, len(buf), 2*cap(buf))
				copy(nb, buf)
				secmem.Wipe(buf)
				buf = nb
			}
			buf = append(buf, b[0])
		}
		if err == io.EOF {
			if len(buf) == 0 {
				return nil, errors.New("no input on stdin")
			}
			break
		}
		if err != nil {
			secmem.Wipe(buf)
			return nil, fmt.Errorf("read input: %w", err)
		}
	}
	buf = bytes.TrimSuffix(buf, []byte{'\r'})
	return buf, nil
}

// trimSecret trims surrounding whitespace in place (for keys, which never
// contain spaces) and returns the trimmed slice of the same array.
func trimSecret(b []byte) []byte {
	return bytes.TrimSpace(b)
}
