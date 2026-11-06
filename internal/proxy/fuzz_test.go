package proxy

import (
	"net/url"
	"strings"
	"testing"

	"github.com/h-a-forster/keyleash/internal/provider"
)

// FuzzSplitTarget: an accepted path is canonical and contains nothing a
// server could normalise into a different path, and the allowlist only ever
// matches such a path.
func FuzzSplitTarget(f *testing.F) {
	for _, s := range []string{
		"/anthropic/v1/messages", "/openai/v1/models/gpt-5", "/gemini/v1beta/models/x:generateContent",
		"/anthropic/v1/../v1/messages", "/anthropic//v1/messages", "/anthropic/v1/messages/", "/%61nthropic/v1",
		`/anthropic\v1`, "/anthropic/v1/messages?x=1", "//evil/v1",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		prov, rest, err := splitTarget(raw)
		if err != nil {
			return
		}
		if "/"+prov+rest != raw {
			t.Fatalf("%q split into %q + %q", raw, prov, rest)
		}
		for _, seg := range strings.Split(raw[1:], "/") {
			if seg == "" || seg == "." || seg == ".." {
				t.Fatalf("%q kept segment %q", raw, seg)
			}
		}
		if strings.ContainsAny(raw, "%\\?#;\x00 ") {
			t.Fatalf("%q kept a character that could be reinterpreted", raw)
		}
		if p, ok := provider.Get(prov); ok {
			if _, ok := p.Match("POST", rest); ok && !strings.HasPrefix(rest, "/v1") {
				t.Fatalf("%q matched an endpoint outside the versioned API", raw)
			}
		}
	})
}

// FuzzSplitQuery: no spelling of the key parameter survives into the query
// forwarded upstream, and the forwarded query is stable.
func FuzzSplitQuery(f *testing.F) {
	for _, s := range []string{
		"key=abc", "KEY=abc&alt=sse", "%6Bey=abc", "k%65y=abc&k%45Y=def", "key+=abc", "%20key=abc", "alt=sse", "a=b;key=c", "key", "=&&=",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, q string) {
		fwd, _, err := splitQuery(q)
		if err != nil {
			return
		}
		again, keys, err := splitQuery(fwd)
		if err != nil || again != fwd || len(keys) != 0 {
			t.Fatalf("%q forwarded as %q: resplit %q %v %v", q, fwd, again, keys, err)
		}
		vals, err := url.ParseQuery(fwd)
		if err != nil {
			return // Go's stricter parser; the bytes are forwarded as sent
		}
		for name := range vals {
			if strings.EqualFold(strings.TrimSpace(name), "key") {
				t.Fatalf("%q forwarded a key parameter: %q", q, fwd)
			}
		}
	})
}
