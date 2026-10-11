package meter

import (
	"math"
	"math/bits"
	"sort"
	"strings"

	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// maxMicros is the saturation ceiling for every computed amount. Saturating
// (rather than wrapping) means an absurd request can only ever look more
// expensive, never negative or cheap.
const maxMicros = money.Micros(math.MaxInt64)

// roundingAllowance covers per-component round-up in priceUsage (input,
// cache read, two cache-write rates, output, tier and regional scaling).
const roundingAllowance money.Micros = 8

// rates is one resolved rate set (base or long-context).
type rates struct {
	in, out, cw, cw5, cr money.PerMTok
	modIn, modCR         map[string]money.PerMTok
}

func (p Price) baseRates() rates {
	return rates{in: p.Input, out: p.Output, cw: p.CacheWrite, cw5: p.CacheWrite5m, cr: p.CacheRead,
		modIn: p.ModalityInput, modCR: p.ModalityCacheRead}
}

func (p Price) longRates() rates {
	l := p.LongContext
	if l == nil {
		return p.baseRates()
	}
	return rates{in: l.Input, out: l.Output, cw: l.CacheWrite, cw5: l.CacheWrite5m, cr: l.CacheRead,
		modIn: l.ModalityInput, modCR: l.ModalityCacheRead}
}

// maxInputRate is the highest per-token rate any input token could be billed
// at under this rate set: uncached input in any modality, or a cache write.
func (r rates) maxInputRate() money.PerMTok {
	m := r.in
	if r.cw > m {
		m = r.cw
	}
	if r.cw5 > m {
		m = r.cw5
	}
	for _, v := range r.modIn {
		if v > m {
			m = v
		}
	}
	return m
}

// maxTierPct is the largest multiplier among the model's tiers (at least 100).
func (p Price) maxTierPct() int64 {
	m := int64(100)
	for _, v := range p.Tiers {
		if v > m {
			m = v
		}
	}
	return m
}

// isStandardTier reports whether a tier name means standard pricing.
func isStandardTier(tier string) bool {
	switch strings.ToLower(strings.TrimSpace(tier)) {
	case "", "default", "auto", "standard", "standard_only", "scale", "on_demand":
		return true
	}
	return false
}

// tierPct maps a reported or requested tier name to a multiplier. Names that
// mean the standard tier return 100. An unrecognised name returns the
// model's highest multiplier (fail closed).
func (p Price) tierPct(tier string) int64 {
	if isStandardTier(tier) {
		return 100
	}
	t := strings.ToLower(strings.TrimSpace(tier))
	switch t {
	case "priority":
		// OpenAI renamed "priority" to "fast"; Gemini calls it "priority".
		if v, ok := p.Tiers["priority"]; ok {
			return v
		}
		if v, ok := p.Tiers["fast"]; ok {
			return v
		}
	}
	if v, ok := p.Tiers[t]; ok {
		return v
	}
	return p.maxTierPct()
}

// ---- saturating arithmetic ----

func satAdd(a, b money.Micros) money.Micros {
	if a < 0 || b < 0 {
		return maxMicros // never expected; fail closed
	}
	if a > maxMicros-b {
		return maxMicros
	}
	return a + b
}

// tokCost is rate × tokens / 1e6 rounded up, saturating.
func tokCost(rate money.PerMTok, n int64) money.Micros {
	if n <= 0 || rate <= 0 {
		return 0
	}
	hi, lo := bits.Mul64(uint64(rate), uint64(n))
	if hi >= 1_000_000 { // quotient would not fit in 64 bits
		return maxMicros
	}
	q, r := bits.Div64(hi, lo, 1_000_000)
	if r != 0 {
		q++
	}
	if q > uint64(maxMicros) {
		return maxMicros
	}
	return money.Micros(q)
}

// scalePct returns ceil(v × pct / 100), saturating.
func scalePct(v money.Micros, pct int64) money.Micros {
	if v <= 0 || pct <= 0 {
		return 0
	}
	hi, lo := bits.Mul64(uint64(v), uint64(pct))
	if hi >= 100 {
		return maxMicros
	}
	q, r := bits.Div64(hi, lo, 100)
	if r != 0 {
		q++
	}
	if q > uint64(maxMicros) {
		return maxMicros
	}
	return money.Micros(q)
}

// scaleTokens returns ceil(n × pct / 100) for token counts, saturating.
func scaleTokens(n, pct int64) int64 {
	if n <= 0 || pct <= 0 {
		return 0
	}
	return int64(scalePct(money.Micros(n), pct))
}

func satMulTokens(a, b int64) int64 {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > math.MaxInt64/b {
		return math.MaxInt64
	}
	return a * b
}

func satAddTokens(a, b int64) int64 {
	if a < 0 {
		a = 0
	}
	if b < 0 {
		b = 0
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// ---- Estimate ----

// Estimate returns the worst-case cost of a request (spec §7.3): input tokens
// at the highest input rate that could apply (long-context tier, any
// modality, cache write), output at the output ceiling (declared max, else
// the model's ceiling, else AssumeMaxOutputTokens) plus any thinking budget
// not already inside it, and the regional premium where a model has one.
// Service-tier premiums the request opts into are already folded into info by
// Inspect. priced is false when the model has no price or no output ceiling
// can be determined; the caller must then apply its unknown-model policy.
func (m *Meter) Estimate(provider string, info RequestInfo) (cost money.Micros, priced bool) {
	if m == nil || m.Pricing == nil {
		return 0, false
	}
	pr, ok := m.Pricing.Lookup(provider, info.Model)
	if !ok {
		return 0, false
	}
	out, ok := m.outputCeiling(info, pr)
	if !ok {
		return 0, false
	}
	r := pr.longRates() // the higher tier: it bounds every request
	total := satAdd(tokCost(r.maxInputRate(), info.InputTokensEstimate), tokCost(r.out, out))
	// Cost rounds each component up separately; cover that so the estimate
	// bounds the settled amount exactly, not just to within a few micros.
	total = satAdd(total, roundingAllowance+money.Micros(2*len(r.modIn)))
	if pr.RegionalPremiumPct > 0 {
		total = scalePct(total, 100+pr.RegionalPremiumPct)
	}
	return total, true
}

// outputCeiling is the most output tokens the request can be billed for.
func (m *Meter) outputCeiling(info RequestInfo, pr Price) (int64, bool) {
	base := info.MaxOutputTokens
	if base <= 0 {
		base = pr.MaxOutputTokens
	}
	if base <= 0 {
		base = m.AssumeMaxOutputTokens
	}
	if info.Kind == provider.KindOpenAIEmbeddings || info.Kind == provider.KindGeminiEmbed {
		return 0, true // embeddings produce no output tokens
	}
	if base <= 0 && info.ThinkingTokens <= 0 {
		return 0, false
	}
	switch info.Kind {
	case provider.KindAnthropicMessages:
		// Thinking is part of max_tokens; with interleaved thinking the budget
		// may exceed it, so take the larger.
		if info.ThinkingTokens > base {
			return info.ThinkingTokens, true
		}
		return base, true
	default:
		// Gemini and anything else: add the declared budget (double counting
		// at worst, which only over-reserves).
		return satAddTokens(base, info.ThinkingTokens), true
	}
}

// ---- Cost ----

// Cost returns the actual cost of a response's usage. A positive
// ProviderCostMicros is authoritative (provider-reported, or computed by the
// usage parser when the response carried pricing detail the Usage struct
// cannot express). Otherwise the table is used: uncached input, cache writes,
// cache reads and output each at their rate; ReasoningTokens are already
// inside OutputTokens and are not added again. Usage token counts are the
// normalised ones the usage parsers produce (InputTokens excludes cache reads
// and writes). priced is false when the model has no price.
func (m *Meter) Cost(provider string, u Usage) (money.Micros, bool) {
	if u.ProviderCostMicros > 0 {
		return money.Micros(u.ProviderCostMicros), true
	}
	if m == nil || m.Pricing == nil {
		return 0, false
	}
	pr, ok := m.Pricing.Lookup(provider, u.Model)
	if !ok {
		return 0, false
	}
	return priceUsage(pr, usageDetail{Usage: u}, Fees{}), true
}

// usageDetail is Usage plus response facts that change the price.
type usageDetail struct {
	Usage
	// cacheWrite5m is how many of CacheWriteTokens used the short TTL; -1
	// (or any value when the split was not reported) means unknown.
	cacheWrite5m int64
	split5m      bool
	// tier is the service tier / speed the response reports ("" standard).
	tier string
	// regional is true when the response reports regional (US-only) inference.
	regional bool
	// modIn / modCR are per-modality token counts of uncached input and cache
	// reads (upper-case keys). modKnown is false when the response did not
	// break input down by modality.
	modIn, modCR map[string]int64
	modKnown     bool
	// webSearchRequests (Anthropic) and webSearchCalls (OpenAI) are billable
	// tool invocations.
	webSearchRequests, webSearchCalls int64
}

// needsDetailPricing reports whether d carries facts Cost(Usage) cannot see.
func (d usageDetail) needsDetailPricing(pr Price) bool {
	if pr.tierPct(d.tier) != 100 || (d.regional && pr.RegionalPremiumPct > 0) {
		return true
	}
	if d.webSearchRequests > 0 || d.webSearchCalls > 0 {
		return true
	}
	if d.split5m && d.cacheWrite5m > 0 && pr.CacheWrite5m > 0 && pr.CacheWrite5m != pr.CacheWrite {
		return true
	}
	if len(pr.ModalityInput) > 0 || len(pr.ModalityCacheRead) > 0 {
		return true
	}
	return false
}

// priceUsage prices d under pr. It is fail-safe: unknown splits are priced
// at the higher rate.
func priceUsage(pr Price, d usageDetail, fees Fees) money.Micros {
	u := d.Usage
	r := pr.baseRates()
	prompt := satAddTokens(satAddTokens(u.InputTokens, u.CacheReadTokens), u.CacheWriteTokens)
	if pr.LongContext != nil && prompt > pr.LongContext.ThresholdTokens {
		r = pr.longRates()
	}
	var total money.Micros

	// Uncached input, split by modality where rates differ.
	total = satAdd(total, modalCost(u.InputTokens, r.in, r.modIn, d.modIn, d.modKnown))
	// Cache reads.
	total = satAdd(total, modalCost(u.CacheReadTokens, r.cr, r.modCR, d.modCR, d.modKnown))
	// Cache writes: the cheaper short-TTL rate only for the reported portion.
	cwRate := r.cw
	if cwRate == 0 {
		cwRate = r.in // no published write rate: price as plain input
	}
	cw5 := int64(0)
	if d.split5m && r.cw5 > 0 {
		cw5 = d.cacheWrite5m
		if cw5 > u.CacheWriteTokens {
			cw5 = u.CacheWriteTokens
		}
		if cw5 < 0 {
			cw5 = 0
		}
	}
	total = satAdd(total, tokCost(r.cw5, cw5))
	total = satAdd(total, tokCost(cwRate, u.CacheWriteTokens-cw5))
	// Output (reasoning already included).
	total = satAdd(total, tokCost(r.out, u.OutputTokens))

	if pct := pr.tierPct(d.tier); pct != 100 {
		total = scalePct(total, pct)
	}
	if d.regional && pr.RegionalPremiumPct > 0 {
		total = scalePct(total, 100+pr.RegionalPremiumPct)
	}
	if d.webSearchRequests > 0 {
		total = satAdd(total, mulMicros(fees.WebSearchRequest, d.webSearchRequests))
	}
	if d.webSearchCalls > 0 {
		total = satAdd(total, mulMicros(fees.WebSearchCall, d.webSearchCalls))
	}
	return total
}

func mulMicros(fee money.Micros, n int64) money.Micros {
	if fee <= 0 || n <= 0 {
		return 0
	}
	if int64(fee) > math.MaxInt64/n {
		return maxMicros
	}
	return fee * money.Micros(n)
}

// modalCost prices n tokens where some modalities have their own rate.
// Without a breakdown, every token is priced at the highest applicable rate.
func modalCost(n int64, def money.PerMTok, modRates map[string]money.PerMTok, counts map[string]int64, known bool) money.Micros {
	if n <= 0 {
		return 0
	}
	if len(modRates) == 0 {
		return tokCost(def, n)
	}
	if !known {
		hi := def
		for _, v := range modRates {
			if v > hi {
				hi = v
			}
		}
		return tokCost(hi, n)
	}
	// Highest rate first, so inconsistent counts (sum > n) are capped in the
	// direction that over-charges, deterministically.
	mods := make([]string, 0, len(counts))
	for mod := range counts {
		if _, ok := modRates[mod]; ok {
			mods = append(mods, mod)
		}
	}
	sort.Slice(mods, func(i, j int) bool {
		if modRates[mods[i]] != modRates[mods[j]] {
			return modRates[mods[i]] > modRates[mods[j]]
		}
		return mods[i] < mods[j]
	})
	var total money.Micros
	rest := n
	for _, mod := range mods {
		rate, c := modRates[mod], counts[mod]
		if c <= 0 {
			continue
		}
		if c > rest {
			c = rest
		}
		total = satAdd(total, tokCost(rate, c))
		rest -= c
	}
	return satAdd(total, tokCost(def, rest))
}
