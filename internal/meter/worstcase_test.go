package meter

import (
	"net/http"
	"testing"

	"github.com/h-a-forster/keyleash/internal/money"
)

const maxRatesTable = `{"version":1,"providers":{"openai":{"models":{
 "cheap":{"input":"1","output":"2","cache_read":"0.1","source_url":"https://example.com","as_of":"2026-01-01"},
 "pricey":{"input":"5","output":"40","cache_write":"8","cache_read":"0.5","tiers":{"priority":200},"regional_premium_pct":10,"source_url":"https://example.com","as_of":"2026-01-01"},
 "longctx":{"input":"3","output":"6","long_context":{"threshold_tokens":1000,"input":"12","output":"50"},"source_url":"https://example.com","as_of":"2026-01-01"}
}}}}`

func TestMaxRates(t *testing.T) {
	p, err := parsePricing([]byte(maxRatesTable), false)
	if err != nil {
		t.Fatal(err)
	}
	mr, ok := p.MaxRates("OpenAI")
	if !ok {
		t.Fatal("no rates")
	}
	// Input: long-context input 12 beats cache write 8; output: long 50.
	want := MaxRates{Input: 12 * money.PerMTok(money.Dollar), Output: 50 * money.PerMTok(money.Dollar), TierPct: 200, RegionalPct: 10}
	if mr != want {
		t.Fatalf("MaxRates = %+v, want %+v", mr, want)
	}
	if _, ok := p.MaxRates("anthropic"); ok {
		t.Fatal("provider without prices has rates")
	}
	var nilP *Pricing
	if _, ok := nilP.MaxRates("openai"); ok {
		t.Fatal("nil pricing has rates")
	}
}

// TestWorstCaseUnpriced reproduces finding 7: an unpriced request used to
// settle at a fixed $2 fallback whatever it really used. The worst case is
// now derived from the provider's most expensive known rates, both for the
// reservation and for settling reported usage.
func TestWorstCaseUnpriced(t *testing.T) {
	p, err := parsePricing([]byte(maxRatesTable), false)
	if err != nil {
		t.Fatal(err)
	}
	m := &Meter{Pricing: p, AssumeMaxOutputTokens: 1000}
	scale := func(v money.Micros) money.Micros { return scalePct(scalePct(v, 200), 110) }

	info := RequestInfo{Model: "gpt-new", InputTokensEstimate: 10_000, MaxOutputTokens: 2_000}
	got, ok := m.WorstCaseEstimate("openai", info)
	want := scale(tokCost(12*money.PerMTok(money.Dollar), 10_000) + tokCost(50*money.PerMTok(money.Dollar), 2_000) + roundingAllowance)
	if !ok || got != want {
		t.Fatalf("estimate = %s %v, want %s", got, ok, want)
	}
	// No declared max: AssumeMaxOutputTokens.
	info.MaxOutputTokens = 0
	got, _ = m.WorstCaseEstimate("openai", info)
	want = scale(tokCost(12*money.PerMTok(money.Dollar), 10_000) + tokCost(50*money.PerMTok(money.Dollar), 1_000) + roundingAllowance)
	if got != want {
		t.Fatalf("estimate (assumed output) = %s, want %s", got, want)
	}
	// Unbounded input and unknown providers cannot be bounded.
	if _, ok := m.WorstCaseEstimate("openai", RequestInfo{InputTokensEstimate: UnboundedInputTokens}); ok {
		t.Fatal("unbounded input bounded")
	}
	if _, ok := m.WorstCaseEstimate("anthropic", RequestInfo{InputTokensEstimate: 1}); ok {
		t.Fatal("provider without prices bounded")
	}

	// Settlement: actual tokens at max rates, not a flat amount.
	u := Usage{Model: "gpt-new", InputTokens: 100, CacheWriteTokens: 50, CacheReadTokens: 50, OutputTokens: 300}
	c, ok := m.WorstCaseCost("openai", u)
	want = scale(tokCost(12*money.PerMTok(money.Dollar), 200) + tokCost(50*money.PerMTok(money.Dollar), 300) + roundingAllowance)
	if !ok || c != want {
		t.Fatalf("cost = %s %v, want %s", c, ok, want)
	}
	if c == 2*money.Dollar {
		t.Fatal("still the flat fallback")
	}
	u.ProviderCostMicros = 7
	if c, ok := m.WorstCaseCost("openai", u); !ok || c != 7 {
		t.Fatalf("provider cost not authoritative: %s", c)
	}
	// The reservation always bounds the settled cost for usage within the
	// request's ceilings.
	est, _ := m.WorstCaseEstimate("openai", RequestInfo{InputTokensEstimate: 200, MaxOutputTokens: 300})
	if c, _ := m.WorstCaseCost("openai", Usage{InputTokens: 100, CacheWriteTokens: 100, OutputTokens: 300}); c > est {
		t.Fatalf("cost %s exceeds estimate %s", c, est)
	}
}

// TestInspectUnpricedBounds: for a model without a price, server-side
// content is unbounded and n completions multiply the output ceiling.
func TestInspectUnpricedBounds(t *testing.T) {
	m := testMeter()
	p, ep := endpointFor(t, "openai", http.MethodPost, "/v1/responses")
	info, err := m.Inspect(p, ep, "/v1/responses", []byte(`{"model":"gpt-unreleased","input":"hi","previous_response_id":"resp_1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if info.InputTokensEstimate != UnboundedInputTokens {
		t.Fatalf("server-side content on an unpriced model: %d", info.InputTokensEstimate)
	}
	p, ep = endpointFor(t, "openai", http.MethodPost, "/v1/chat/completions")
	info, err = m.Inspect(p, ep, "/v1/chat/completions", []byte(`{"model":"gpt-unreleased","n":3,"max_completion_tokens":100,"messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if info.MaxOutputTokens != 300 || info.InputTokensEstimate >= UnboundedInputTokens {
		t.Fatalf("n=3: %+v", info)
	}
	if _, ok := m.WorstCaseEstimate("openai", info); !ok {
		t.Fatal("bounded unpriced request not estimated")
	}
}
