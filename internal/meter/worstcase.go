package meter

import (
	"strings"

	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// MaxRates is the most expensive rate set known for a provider: the highest
// rate any input-side token (uncached input in any modality, cache write of
// either TTL, cache read, long-context variants) and any output token is
// billed at across every model in the provider's table, plus the largest
// service-tier and regional multipliers. It bounds the cost of a model the
// table does not price (spec §7.5) without assuming any particular model.
type MaxRates struct {
	Input, Output money.PerMTok
	// TierPct is the largest tier multiplier in percent (at least 100).
	TierPct int64
	// RegionalPct is the largest regional premium in percent (0: none).
	RegionalPct int64
}

// MaxRates returns the provider's MaxRates. ok is false when the table has
// no priced model for the provider.
func (p *Pricing) MaxRates(prov string) (MaxRates, bool) {
	if p == nil {
		return MaxRates{}, false
	}
	pp, found := p.providers[strings.ToLower(prov)]
	if !found {
		return MaxRates{}, false
	}
	mr := MaxRates{TierPct: 100}
	n := 0
	add := func(pr Price) {
		n++
		for _, r := range []rates{pr.baseRates(), pr.longRates()} {
			mr.Input = max(mr.Input, r.maxInputRate(), r.cr)
			for _, v := range r.modCR {
				mr.Input = max(mr.Input, v)
			}
			mr.Output = max(mr.Output, r.out)
		}
		mr.TierPct = max(mr.TierPct, pr.maxTierPct())
		mr.RegionalPct = max(mr.RegionalPct, pr.RegionalPremiumPct)
	}
	for _, pr := range pp.exact {
		add(pr)
	}
	for _, pat := range pp.patterns {
		add(pat.price)
	}
	if n == 0 || (mr.Input <= 0 && mr.Output <= 0) {
		return MaxRates{}, false
	}
	return mr, true
}

// scale applies the tier and regional multipliers.
func (mr MaxRates) scale(v money.Micros) money.Micros {
	v = scalePct(v, max(mr.TierPct, 100))
	if mr.RegionalPct > 0 {
		v = scalePct(v, 100+mr.RegionalPct)
	}
	return v
}

// WorstCaseEstimate bounds a request to a model the pricing table does not
// price: InputTokensEstimate at the provider's most expensive input rate plus
// the output ceiling (declared max output, else AssumeMaxOutputTokens, plus
// any thinking budget) at its most expensive output rate, times the largest
// tier and regional multipliers. ok is false when the input cannot be
// bounded (UnboundedInputTokens), no output ceiling is known, or the provider
// has no prices at all; the caller must then reserve its per-request limit
// and require approval.
func (m *Meter) WorstCaseEstimate(prov string, info RequestInfo) (money.Micros, bool) {
	if m == nil || m.Pricing == nil || info.InputTokensEstimate >= UnboundedInputTokens {
		return 0, false
	}
	mr, ok := m.Pricing.MaxRates(prov)
	if !ok {
		return 0, false
	}
	out := info.MaxOutputTokens
	if out <= 0 {
		out = m.AssumeMaxOutputTokens
	}
	out = satAddTokens(out, info.ThinkingTokens)
	if info.Kind == provider.KindOpenAIEmbeddings || info.Kind == provider.KindGeminiEmbed {
		out = 0
	} else if out <= 0 {
		return 0, false
	}
	total := satAdd(tokCost(mr.Input, info.InputTokensEstimate), tokCost(mr.Output, out))
	return mr.scale(satAdd(total, roundingAllowance)), true
}

// WorstCaseCost prices reported usage of an unpriced model at the provider's
// most expensive rates (every input-side token at the highest input rate,
// output at the highest output rate, times the largest multipliers). A
// provider-reported cost is authoritative, as in Cost. ok is false when the
// provider has no prices.
func (m *Meter) WorstCaseCost(prov string, u Usage) (money.Micros, bool) {
	if u.ProviderCostMicros > 0 {
		return money.Micros(u.ProviderCostMicros), true
	}
	if m == nil || m.Pricing == nil {
		return 0, false
	}
	mr, ok := m.Pricing.MaxRates(prov)
	if !ok {
		return 0, false
	}
	in := satAddTokens(satAddTokens(u.InputTokens, u.CacheWriteTokens), u.CacheReadTokens)
	total := satAdd(tokCost(mr.Input, in), tokCost(mr.Output, u.OutputTokens))
	return mr.scale(satAdd(total, roundingAllowance)), true
}

// inspectUnpriced finishes Inspect for a model without a price: server-side
// content or a tool whose fees cannot be capped make the input unbounded;
// n > 1 completions multiply the output ceiling; bounded tool fees are folded
// into the input estimate at the provider's highest input rate.
func (m *Meter) inspectUnpriced(prov, kind string, obj *jsonObject, n int64, serverSide bool, info RequestInfo) (RequestInfo, error) {
	if serverSide {
		info.InputTokensEstimate = UnboundedInputTokens
		return info, nil
	}
	var fees Fees
	if m != nil && m.Pricing != nil {
		fees = m.Pricing.fees(prov)
	}
	fee, ok, err := toolFees(kind, obj, fees, n)
	if err != nil {
		return info, err
	}
	if !ok {
		info.InputTokensEstimate = UnboundedInputTokens
		return info, nil
	}
	if n > 1 {
		base := info.MaxOutputTokens
		if base <= 0 && m != nil {
			base = m.AssumeMaxOutputTokens
		}
		info.MaxOutputTokens = satMulTokens(satAddTokens(base, info.ThinkingTokens), n)
		info.ThinkingTokens = 0
	}
	if fee > 0 {
		var rate money.PerMTok
		if m != nil {
			if mr, ok := m.Pricing.MaxRates(prov); ok {
				rate = mr.Input
			}
		}
		if rate <= 0 {
			// No rate to express the fee in tokens: cannot be bounded.
			info.InputTokensEstimate = UnboundedInputTokens
			return info, nil
		}
		info.InputTokensEstimate = satAddTokens(info.InputTokensEstimate, feeTokens(fee, rate))
	}
	if info.InputTokensEstimate >= UnboundedInputTokens {
		info.InputTokensEstimate = UnboundedInputTokens - 1
	}
	return info, nil
}
