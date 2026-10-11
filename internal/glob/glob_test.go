package glob

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		p, s string
		want bool
	}{
		{"*opus*", "claude-opus-5-5", true},
		{"*opus*", "anthropic/claude-opus-4", true},
		{"*", "a/b/c", true},
		{"*", "", true},
		{"gpt-5*", "GPT-5.5-pro", true},
		{"gpt-5*", "gpt-4o", false},
		{"claude-?aiku-*", "claude-haiku-5-5", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
		{"", "", true},
		{"", "x", false},
	}
	for _, tt := range tests {
		if got := Match(tt.p, tt.s); got != tt.want {
			t.Errorf("Match(%q, %q) = %v, want %v", tt.p, tt.s, got, tt.want)
		}
	}
}

func TestValid(t *testing.T) {
	for p, want := range map[string]bool{"*opus*": true, "": false, "[a]": false, `a\b`: false} {
		if Valid(p) != want {
			t.Errorf("Valid(%q) != %v", p, want)
		}
	}
}
