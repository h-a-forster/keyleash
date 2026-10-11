package meter

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

func TestEmbeddedPricingValid(t *testing.T) {
	p := DefaultPricing()
	total := 0
	for _, prov := range []string{"anthropic", "openai", "gemini"} {
		ids := p.Models(prov)
		if len(ids) == 0 {
			t.Fatalf("no models for %s", prov)
		}
		for _, id := range ids {
			pp := p.providers[prov]
			pr, ok := pp.exact[id]
			if !ok {
				continue
			}
			total++
			if !strings.HasPrefix(pr.Source, "https://") || pr.AsOf == "" {
				t.Errorf("%s/%s: missing source/as_of", prov, id)
			}
			if pr.Input <= 0 {
				t.Errorf("%s/%s: non-positive input rate", prov, id)
			}
			if pr.CacheWrite5m > pr.CacheWrite && pr.CacheWrite > 0 {
				t.Errorf("%s/%s: 5m write rate above the stored (highest) write rate", prov, id)
			}
		}
	}
	if total < 30 {
		t.Fatalf("only %d priced models", total)
	}
	// OpenRouter reports its own cost: no table.
	if _, ok := p.Lookup("openrouter", "openai/gpt-5"); ok {
		t.Fatal("openrouter should be unpriced")
	}
}

func TestLookup(t *testing.T) {
	p := DefaultPricing()
	cases := []struct {
		prov, model string
		ok          bool
		input       string
	}{
		{"anthropic", "claude-opus-5-5", true, "$4"},
		{"Anthropic", "CLAUDE-OPUS-5-5", true, "$4"},
		{"anthropic", "claude-sonnet-4-5-20250929", true, "$3"},
		{"anthropic", "claude-haiku-4-5-20251001", true, "$1"},
		{"anthropic", "claude-opus-4-5-20251101", true, "$5"},
		{"anthropic", "claude-opus-4-1", false, ""}, // retired: not priced
		{"anthropic", "claude-opus-5-5x", false, ""},
		{"anthropic", "claude-opus", false, ""},
		{"openai", "gpt-5.4-2026-03-05", true, "$2.50"},
		{"openai", "gpt-4o-2024-08-06", true, "$2.50"},
		{"openai", "gpt-4o-2024-05-13", true, "$5"}, // exact entry beats the family
		{"openai", "gpt-5.5-pro", false, ""},        // long-context price unpublished: omitted
		{"openai", "gpt-5-mini", true, "$0.25"},
		{"openai", "gpt-5-mini-turbo", false, ""}, // no implicit prefix matching
		{"gemini", "models/gemini-2.5-pro", true, "$1.25"},
		{"gemini", "gemini-2.5-pro", true, "$1.25"},
		{"gemini", "", false, ""},
		{"nope", "gpt-5", false, ""},
	}
	for _, c := range cases {
		pr, ok := p.Lookup(c.prov, c.model)
		if ok != c.ok {
			t.Errorf("Lookup(%q,%q) ok=%v want %v", c.prov, c.model, ok, c.ok)
			continue
		}
		if ok {
			want, _ := money.Parse(c.input)
			if pr.Input != money.PerMTok(want) {
				t.Errorf("Lookup(%q,%q).Input = %d want %d", c.prov, c.model, pr.Input, want)
			}
		}
	}
	var nilP *Pricing
	if _, ok := nilP.Lookup("openai", "gpt-5"); ok {
		t.Fatal("nil pricing priced a model")
	}
}

func TestValidUntilExpires(t *testing.T) {
	p, err := LoadPricing("")
	if err != nil {
		t.Fatal(err)
	}
	day := func(s string) func() time.Time {
		return func() time.Time { tm, _ := time.Parse(time.RFC3339, s); return tm }
	}
	p.now = day("2026-12-31T23:59:59Z")
	if _, ok := p.Lookup("gemini", "gemini-3.8-flash"); !ok {
		t.Fatal("promo price should be valid on its last day")
	}
	p.now = day("2027-01-01T00:00:00Z")
	if _, ok := p.Lookup("gemini", "gemini-3.8-flash"); ok {
		t.Fatal("expired promo price must not be returned")
	}
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pricing.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadPricingOverride(t *testing.T) {
	path := writeTemp(t, `{
	  "version": 1,
	  "providers": {
	    "openai": {
	      "models": {
	        "gpt-5": {"input": "$9", "output": "$90"},
	        "gpt-4.1": null,
	        "ft:gpt-4o-mini*": {"input": "$0.30", "output": "$1.20"},
	        "ft:gpt-4o-mini:acme*": {"input": "$0.50", "output": "$2"}
	      }
	    },
	    "openrouter": {
	      "fees": {"web_search_call": "$0.02"},
	      "models": {"openai/gpt-5": {"input": "$1.25", "output": "$10", "source_url": "https://openrouter.ai/openai/gpt-5", "as_of": "2026-10-01"}}
	    }
	  }
	}`)
	p, err := LoadPricing(path)
	if err != nil {
		t.Fatal(err)
	}
	pr, ok := p.Lookup("openai", "gpt-5")
	if !ok || pr.Input != 9_000_000 || pr.CacheRead != 9_000_000 || pr.Source != "user override" {
		t.Fatalf("override not applied: %+v", pr)
	}
	if _, ok := p.Lookup("openai", "gpt-4.1"); ok {
		t.Fatal("null did not remove model")
	}
	if _, ok := p.Lookup("openai", "gpt-5-mini"); !ok {
		t.Fatal("unrelated embedded model lost")
	}
	// Longest declared prefix wins.
	if pr, _ := p.Lookup("openai", "ft:gpt-4o-mini:acme:custom:abc123"); pr.Input != 500_000 {
		t.Fatalf("longest pattern did not win: %d", pr.Input)
	}
	if pr, _ := p.Lookup("openai", "ft:gpt-4o-mini:other:x:1"); pr.Input != 300_000 {
		t.Fatalf("shorter pattern not used: %d", pr.Input)
	}
	if _, ok := p.Lookup("openrouter", "openai/gpt-5"); !ok {
		t.Fatal("new provider from override missing")
	}
	// The shared default table is untouched.
	if pr, _ := DefaultPricing().Lookup("openai", "gpt-5"); pr.Input != 1_250_000 {
		t.Fatal("override leaked into DefaultPricing")
	}
}

func TestLoadPricingRejects(t *testing.T) {
	cases := map[string]string{
		"not json":         `{`,
		"wrong version":    `{"version": 2, "providers": {}}`,
		"unknown field":    `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "$1", "output": "$1", "inptu": "$1"}}}}}`,
		"bad rate":         `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "one dollar", "output": "$1"}}}}}`,
		"zero input":       `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "$0", "output": "$1"}}}}}`,
		"negative":         `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "-$1", "output": "$1"}}}}}`,
		"missing output":   `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "$1"}}}}}`,
		"too precise":      `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "$0.0000001", "output": "$1"}}}}}`,
		"cheap long tier":  `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "$2", "output": "$8", "long_context": {"threshold_tokens": 10, "input": "$1", "output": "$8"}}}}}}`,
		"zero threshold":   `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "$2", "output": "$8", "long_context": {"threshold_tokens": 0, "input": "$3", "output": "$9"}}}}}}`,
		"tier range":       `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "$2", "output": "$8", "tiers": {"fast": 0}}}}}}`,
		"bad valid_until":  `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "$2", "output": "$8", "valid_until": "soon"}}}}}`,
		"bad pattern":      `{"version": 1, "providers": {"openai": {"models": {"*": {"input": "$2", "output": "$8"}}}}}`,
		"inner star":       `{"version": 1, "providers": {"openai": {"models": {"gpt*x*": {"input": "$2", "output": "$8"}}}}}`,
		"unknown fee":      `{"version": 1, "providers": {"openai": {"fees": {"tip": "$1"}, "models": {}}}}`,
		"trailing data":    `{"version": 1, "providers": {}} {}`,
		"negative max out": `{"version": 1, "providers": {"openai": {"models": {"x": {"input": "$2", "output": "$8", "max_output_tokens": -1}}}}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadPricing(writeTemp(t, body)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if _, err := LoadPricing(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Fatal("missing file accepted")
	}
	big := filepath.Join(t.TempDir(), "big.json")
	if err := os.WriteFile(big, []byte(`{"version":1,"providers":{},"x":"`+strings.Repeat("a", maxPricingFileSize)+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPricing(big); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversized override: %v", err)
	}
}

func TestStripSnapshotDate(t *testing.T) {
	for in, want := range map[string]string{
		"claude-sonnet-4-5-20250929": "claude-sonnet-4-5",
		"gpt-5-2025-08-07":           "gpt-5",
		"claude-haiku-4-5@20251001":  "claude-haiku-4-5",
		"gpt-5":                      "gpt-5",
		"model-2025":                 "model-2025",
		"o3-mini":                    "o3-mini",
	} {
		if got := stripSnapshotDate(in); got != want {
			t.Errorf("stripSnapshotDate(%q) = %q want %q", in, got, want)
		}
	}
}
