// Package glob matches model ids against simple patterns. Unlike path.Match,
// '*' matches any run of characters including '/', so "*opus*" matches the
// OpenRouter id "anthropic/claude-opus-4". Matching is case-insensitive.
package glob

import "strings"

// Valid reports whether pattern is usable: non-empty and free of characters
// that path.Match would treat specially but this package does not ('[', '\').
func Valid(pattern string) bool {
	return pattern != "" && !strings.ContainsAny(pattern, `[]\`)
}

// Match reports whether s matches pattern. '*' matches any sequence
// (including empty and '/'); '?' matches exactly one character; everything
// else matches itself, case-insensitively.
func Match(pattern, s string) bool {
	p := []rune(strings.ToLower(pattern))
	x := []rune(strings.ToLower(s))
	// Iterative wildcard matching with single-star backtracking: O(len(p)*len(x)).
	pi, xi := 0, 0
	star, mark := -1, 0
	for xi < len(x) {
		switch {
		case pi < len(p) && (p[pi] == '?' || p[pi] == x[xi]):
			pi++
			xi++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, xi
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			xi = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}
