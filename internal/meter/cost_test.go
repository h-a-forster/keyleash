package meter

import (
	"math"
	"sync"
	"testing"

	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
)

func TestTokCostRoundsUpAndSaturates(t *testing.T) {
	cases := []struct {
		rate money.PerMTok
		n    int64
		want money.Micros
	}{
		{1, 1, 1},         // 1e-6 micro -> 1
		{20_000, 9, 1},    // $0.02/MTok * 9 = 0.18 micro -> 1
		{1_000_000, 1, 1}, // exactly 1 micro
		{1_000_000, 2, 2}, // no spurious rounding
		{75_000, 64, 5},   // 4.8 -> 5
		{0, 1000, 0},      // free
		{1000, 0, 0},      // nothing
		{1000, -5, 0},     // negative counts never produce cost
		{math.MaxInt64, math.MaxInt64, maxMicros},
		{600_000_000, math.MaxInt64, maxMicros},
	}
	for _, c := range cases {
		if got := tokCost(c.rate, c.n); got != c.want {
			t.Errorf("tokCost(%d,%d) = %d want %d", c.rate, c.n, got, c.want)
		}
	}
	if scalePct(maxMicros, 200) != maxMicros || scalePct(11, 167) != 19 || scalePct(10, 110) != 11 {
		t.Fatal("scalePct")
	}
	if satAdd(maxMicros, 1) != maxMicros || satAdd(-1, 1) != maxMicros {
		t.Fatal("satAdd")
	}
}

func TestCost(t *testing.T) {
	m := testMeter()
	cases := []struct {
		name string
		prov string
		u    Usage
		want money.Micros
		ok   bool
	}{
		{"provider cost authoritative", "openrouter", Usage{Model: "x/y", InputTokens: 1e6, ProviderCostMicros: 42}, 42, true},
		{"unpriced", "openai", Usage{Model: "gpt-unknown", InputTokens: 10}, 0, false},
		{"no model", "openai", Usage{InputTokens: 10}, 0, false},
		// Reasoning is inside output: 1000 out * $10 = 10000, not 1500 * $10.
		{"reasoning not double counted", "openai", Usage{Model: "gpt-5", OutputTokens: 1000, ReasoningTokens: 500}, 10_000, true},
		// Haiku 5.5: prompt 100,000 exactly stays on base rates...
		{"haiku base tier", "anthropic", Usage{Model: "claude-haiku-5-5", InputTokens: 100_000}, 10_000, true},
		// ...one token more and the whole request is on the long tier,
		// cache reads counting toward the threshold.
		{"haiku long tier", "anthropic", Usage{Model: "claude-haiku-5-5", InputTokens: 100_000, CacheReadTokens: 1, OutputTokens: 1000}, 50_000 + 1 + 2_500, true},
		// Gemini 2.5 Pro over 200k.
		{"gemini long", "gemini", Usage{Model: "gemini-2.5-pro", InputTokens: 200_001, OutputTokens: 10}, tokCost(2_500_000, 200_001) + tokCost(15_000_000, 10), true},
		// Unknown cache-write TTL split is priced at the 1h (higher) rate.
		{"anthropic write at 1h rate", "anthropic", Usage{Model: "claude-opus-5-5", CacheWriteTokens: 1000}, 8_000, true},
		// No published write rate: priced as input.
		{"openai write as input", "openai", Usage{Model: "gpt-5", CacheWriteTokens: 1000}, 1_250, true},
		{"saturates", "openai", Usage{Model: "gpt-5.4-pro", InputTokens: math.MaxInt64, OutputTokens: math.MaxInt64}, maxMicros, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := m.Cost(c.prov, c.u)
			if ok != c.ok || got != c.want {
				t.Fatalf("Cost = %d,%v want %d,%v", got, ok, c.want, c.ok)
			}
		})
	}
}

func TestPriceUsageModifiers(t *testing.T) {
	p := DefaultPricing()
	opus, _ := p.Lookup("anthropic", "claude-opus-5-5")
	base := Usage{Model: "claude-opus-5-5", InputTokens: 1000, OutputTokens: 1000} // 4000 + 20000
	fees := p.fees("anthropic")
	cases := []struct {
		name string
		d    usageDetail
		want money.Micros
	}{
		{"standard", usageDetail{Usage: base}, 24_000},
		{"fast", usageDetail{Usage: base, tier: "fast"}, 48_000},
		{"regional", usageDetail{Usage: base, regional: true}, 26_400},
		{"fast and regional stack", usageDetail{Usage: base, tier: "fast", regional: true}, 52_800},
		{"unknown tier fails closed", usageDetail{Usage: base, tier: "turbo"}, 48_000},
		{"web search fee", usageDetail{Usage: base, webSearchRequests: 3}, 24_000 + 30_000},
		{"5m split", usageDetail{Usage: Usage{CacheWriteTokens: 1000}, split5m: true, cacheWrite5m: 600}, 3_000 + 3_200},
		{"5m split capped", usageDetail{Usage: Usage{CacheWriteTokens: 1000}, split5m: true, cacheWrite5m: 5000}, 5_000},
	}
	for _, c := range cases {
		if got := priceUsage(opus, c.d, fees); got != c.want {
			t.Errorf("%s: %d want %d", c.name, got, c.want)
		}
	}
	// Modalities without a breakdown are priced at the highest rate.
	flash, _ := p.Lookup("gemini", "gemini-2.5-flash")
	unknown := priceUsage(flash, usageDetail{Usage: Usage{InputTokens: 1000}}, Fees{})
	known := priceUsage(flash, usageDetail{Usage: Usage{InputTokens: 1000}, modKnown: true, modIn: map[string]int64{"TEXT": 1000}}, Fees{})
	if unknown != 1000 || known != 300 {
		t.Fatalf("modality pricing: unknown=%d known=%d", unknown, known)
	}
}

func TestEstimate(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing()}
	cases := []struct {
		name   string
		prov   string
		info   RequestInfo
		want   money.Micros
		priced bool
	}{
		{"unpriced model", "openai", RequestInfo{Kind: provider.KindOpenAIChat, Model: "nope", MaxOutputTokens: 1}, 0, false},
		{"no ceiling at all", "openai", RequestInfo{Kind: provider.KindOpenAIChat, Model: "gpt-4o-2024-05-13", InputTokensEstimate: 10}, 0, false},
		{"unbounded input", "openai", RequestInfo{Kind: provider.KindOpenAIResponses, Model: "gpt-5", InputTokensEstimate: UnboundedInputTokens, MaxOutputTokens: 10}, 0, false},
		// Opus 5.5: input at the 1h write rate $8, output $20, +10% regional.
		{"anthropic", "anthropic", RequestInfo{Kind: provider.KindAnthropicMessages, Model: "claude-opus-5-5", InputTokensEstimate: 1000, MaxOutputTokens: 1000}, 30_809, true}, // (28000+8 rounding allowance)*110%
		// Interleaved thinking budget above max_tokens bounds output.
		{"anthropic thinking", "anthropic", RequestInfo{Kind: provider.KindAnthropicMessages, Model: "claude-opus-4-5", MaxOutputTokens: 1000, ThinkingTokens: 3000}, 75_008, true},
		// Model ceiling used when no max declared: 128000 * $10.
		{"model ceiling", "openai", RequestInfo{Kind: provider.KindOpenAIResponses, Model: "gpt-5"}, 1_280_008, true},
		// Long tier always used for estimates (GPT-5.4 long: $5 in, $22.50 out).
		{"long tier", "openai", RequestInfo{Kind: provider.KindOpenAIChat, Model: "gpt-5.4", InputTokensEstimate: 1000, MaxOutputTokens: 1000}, 27_508, true},
		// Gemini adds an explicit thinking budget; embeddings have no output.
		{"gemini thinking", "gemini", RequestInfo{Kind: provider.KindGeminiGenerate, Model: "gemini-2.5-flash", MaxOutputTokens: 100, ThinkingTokens: 100}, 510, true}, // +8, +2 per modality rate
		{"gemini embed uses top modality", "gemini", RequestInfo{Kind: provider.KindGeminiEmbed, Model: "gemini-embedding-2", InputTokensEstimate: 1000}, 12_014, true},
		{"huge request saturates", "openai", RequestInfo{Kind: provider.KindOpenAIChat, Model: "gpt-5.4-pro", InputTokensEstimate: UnboundedInputTokens - 1, MaxOutputTokens: math.MaxInt64}, maxMicros, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := m.Estimate(c.prov, c.info)
			if ok != c.priced || got != c.want {
				t.Fatalf("Estimate = %d,%v want %d,%v", got, ok, c.want, c.priced)
			}
		})
	}
	m.AssumeMaxOutputTokens = 10
	if got, ok := m.Estimate("openai", RequestInfo{Kind: provider.KindOpenAIChat, Model: "gpt-4o-2024-05-13"}); !ok || got != tokCost(15_000_000, 10)+roundingAllowance {
		t.Fatalf("policy ceiling: %d %v", got, ok)
	}
	var nilM *Meter
	if _, ok := nilM.Estimate("openai", RequestInfo{Model: "gpt-5"}); ok {
		t.Fatal("nil meter priced")
	}
}

// Estimate must bound Cost for any usage consistent with the request: the
// same input tokens split any way across cache/uncached/modality, any tier
// the request opted into, and output up to the declared ceiling.
func TestEstimateBoundsCostProperty(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing(), AssumeMaxOutputTokens: 4096}
	p := DefaultPricing()
	for _, prov := range []string{"anthropic", "openai", "gemini"} {
		for _, id := range p.Models(prov) {
			pr, ok := p.Lookup(prov, id)
			if !ok {
				continue
			}
			kind := map[string]string{"anthropic": provider.KindAnthropicMessages, "openai": provider.KindOpenAIChat, "gemini": provider.KindGeminiGenerate}[prov]
			for _, in := range []int64{0, 1, 999, 300_000} {
				info := RequestInfo{Kind: kind, Model: id, InputTokensEstimate: in, MaxOutputTokens: 5000}
				est, ok := m.Estimate(prov, info)
				if !ok {
					t.Fatalf("%s/%s unpriced", prov, id)
				}
				for _, split := range [][3]int64{{in, 0, 0}, {0, in, 0}, {0, 0, in}, {in / 3, in / 3, in - 2*(in/3)}} {
					d := usageDetail{Usage: Usage{Model: id, InputTokens: split[0], CacheReadTokens: split[1], CacheWriteTokens: split[2], OutputTokens: 5000}}
					d.regional = true
					if c := priceUsage(pr, d, Fees{}); c > est {
						t.Fatalf("%s/%s in=%d split=%v: cost %d > estimate %d", prov, id, in, split, c, est)
					}
				}
			}
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	m := testMeter()
	p, ep := endpointFor(t, "anthropic", "POST", "/v1/messages")
	req := readFixture(t, "req_anthropic_opus.json")
	resp := readFixture(t, "resp_anthropic_sonnet_stream.sse")
	want, ok := parseAll(m, "anthropic", ep, true, resp, 0)
	if !ok {
		t.Fatal("baseline not ok")
	}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 32; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				info, err := m.Inspect(p, ep, "/v1/messages", req)
				if err != nil {
					errs <- err.Error()
					return
				}
				if _, ok := m.Estimate("anthropic", info); !ok {
					errs <- "estimate unpriced"
					return
				}
				u, ok := parseAll(m, "anthropic", ep, true, resp, 1+(g+i)%13)
				if !ok || u != want {
					errs <- "usage mismatch"
					return
				}
				if _, ok := m.Cost("anthropic", u); !ok {
					errs <- "cost unpriced"
					return
				}
				_ = DefaultPricing()
			}
		}(g)
	}
	// One parser hammered by concurrent writers and readers must not panic
	// or corrupt state (results are unspecified since order is not).
	shared := m.NewUsageParser(ep, true)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				_, _ = shared.Write(resp[i%len(resp) : i%len(resp)+1])
				_, _ = shared.Final()
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}
