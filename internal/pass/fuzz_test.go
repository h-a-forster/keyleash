package pass

import (
	"strings"
	"testing"
)

// FuzzParse: every accepted token is the one canonical text of its id and
// secret, so a pass cannot be presented in a second spelling.
func FuzzParse(f *testing.F) {
	secret := make([]byte, SecretBytes)
	f.Add(formatToken(strings.Repeat("a", IDLen), secret))
	f.Add(Prefix + strings.Repeat("A", TokenLen-len(Prefix)))
	f.Add("klp_")
	f.Fuzz(func(t *testing.T, token string) {
		id, secret, ok := parse(token)
		if !ok {
			return
		}
		if got := formatToken(id, secret); got != token {
			t.Fatalf("token %q re-encodes as %q", token, got)
		}
	})
}
