package audit

import (
	"errors"
	"math"
	"strings"
)

// ErrSecret is returned by Append when a field value looks like a credential.
// The error never includes the offending value.
var ErrSecret = errors.New("audit: field value looks like a secret; record rejected")

// secretPrefixes are prefixes of provider keys and passes. A token starting
// with one of these and longer than minPrefixedLen is rejected.
var secretPrefixes = []string{"sk-", "sk-ant-", "sk-proj-", "sk-or-", "AIza", "klp_"}

const minPrefixedLen = 20

// Generic high-entropy detection: tokens at least minEntropyLen long that mix
// upper case, lower case and digits with Shannon entropy ≥ minEntropyBits per
// character. Hex digests and UUIDs (no upper case) never trip this.
const (
	minEntropyLen  = 40
	minEntropyBits = 4.0
)

// nonSecretPrefixes are well-known identifier prefixes (upstream request and
// response ids) that are high-entropy but not credentials.
var nonSecretPrefixes = []string{"chatcmpl-", "req_", "msg_", "resp_", "gen-", "toolu_", "call_", "run_", "batch_", "file-"}

// checkValue walks a normalised value and reports whether any string in it
// (including object keys) looks like a secret.
func checkValue(v any) bool {
	switch x := v.(type) {
	case string:
		return looksSecret(x)
	case []any:
		for _, e := range x {
			if checkValue(e) {
				return true
			}
		}
	case map[string]any:
		for k, e := range x {
			if looksSecret(k) || checkValue(e) {
				return true
			}
		}
	}
	return false
}

func isTokenChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '-' || c == '+'
}

// looksSecret splits s into runs of key-like characters ([A-Za-z0-9_+-]) and
// tests each run, so "key=sk-ant-…" or "Bearer sk-…" are caught too.
func looksSecret(s string) bool {
	start := -1
	for i := 0; i <= len(s); i++ {
		if i < len(s) && isTokenChar(s[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			if tokenLooksSecret(s[start:i]) {
				return true
			}
			start = -1
		}
	}
	return false
}

func tokenLooksSecret(t string) bool {
	for _, p := range secretPrefixes {
		if strings.HasPrefix(t, p) && len(t) > minPrefixedLen {
			return true
		}
	}
	if len(t) < minEntropyLen {
		return false
	}
	for _, p := range nonSecretPrefixes {
		if strings.HasPrefix(t, p) {
			return false
		}
	}
	var upper, lower, digit bool
	var counts [256]int
	for i := 0; i < len(t); i++ {
		c := t[i]
		counts[c]++
		switch {
		case c >= 'A' && c <= 'Z':
			upper = true
		case c >= 'a' && c <= 'z':
			lower = true
		case c >= '0' && c <= '9':
			digit = true
		}
	}
	if !(upper && lower && digit) {
		return false
	}
	var h float64
	n := float64(len(t))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h >= minEntropyBits
}
