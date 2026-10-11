package meter

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

//go:embed pricing.json
var embeddedPricing []byte

// maxPricingFileSize bounds a user override file so a mistaken path (a log,
// a disk image) cannot exhaust memory.
const maxPricingFileSize = 4 << 20

// Price is one model's rates. All rates are per million tokens.
//
// Input, Output, CacheWrite and CacheRead are the standard (short-context)
// rates. CacheWrite is the highest cache-write rate the model has (for
// Anthropic, the 1-hour TTL rate); CacheWrite5m, when non-zero, is the cheaper
// short-TTL rate used only when a response reports that split.
type Price struct {
	Input, Output, CacheWrite, CacheRead money.PerMTok
	// MaxOutputTokens is the model's output ceiling, used when a request does
	// not declare one. 0 means unknown.
	MaxOutputTokens int64
	// Source is the URL the rates were taken from; AsOf the date (YYYY-MM-DD)
	// they were verified.
	Source, AsOf string

	// CacheWrite5m is Anthropic's 5-minute cache-write rate (0: same as
	// CacheWrite).
	CacheWrite5m money.PerMTok
	// ModalityInput and ModalityCacheRead override Input/CacheRead for
	// specific input modalities as named by the provider (Gemini: "AUDIO",
	// "VIDEO", "IMAGE"). Keys are upper case.
	ModalityInput, ModalityCacheRead map[string]money.PerMTok
	// MaxInputTokens is the model's context window, used to bound requests
	// whose input is partly held server-side. 0 means unknown.
	MaxInputTokens int64
	// LongContext, when set, are the rates that apply to the whole request
	// once its prompt exceeds a threshold.
	LongContext *LongContext
	// Tiers maps a service tier / speed name ("fast", "ultrafast", "flex",
	// "priority") to a multiplier in percent applied to the whole request.
	Tiers map[string]int64
	// RegionalPremiumPct is the surcharge in percent for regional (e.g. US-only)
	// inference. Estimates always include it because it can be an account
	// default that the request does not show.
	RegionalPremiumPct int64
	// ValidUntil (YYYY-MM-DD, inclusive) marks a promotional price. After it
	// the entry is treated as unpriced so stale promos fail closed.
	ValidUntil string
	// Note is free-form provenance (tier rules, rounding).
	Note string
	// Fees are model-specific per-call fees. A non-zero field overrides the
	// provider's fee of the same name (see Pricing.feesFor).
	Fees Fees
}

// LongContext is the higher rate set for prompts above ThresholdTokens
// (input + cache read + cache write tokens).
type LongContext struct {
	ThresholdTokens                                    int64
	Input, Output, CacheWrite, CacheWrite5m, CacheRead money.PerMTok
	ModalityInput, ModalityCacheRead                   map[string]money.PerMTok
}

// Fees are per-call charges that are not token based, in micro-USD per call.
// Zero means the fee does not apply (or, on a model, that the provider's
// fee is inherited).
type Fees struct {
	// WebSearchRequest is Anthropic's server-side web search charge.
	WebSearchRequest money.Micros
	// WebSearchCall is OpenAI's Responses API web search tool charge.
	WebSearchCall money.Micros
	// FileSearchCall is OpenAI's Responses API file search tool charge.
	FileSearchCall money.Micros
	// GoogleSearchQuery / GoogleMapsQuery are Gemini 3+ grounding charges
	// per search query the model executes.
	GoogleSearchQuery, GoogleMapsQuery money.Micros
	// GoogleSearchPrompt / GoogleMapsPrompt are Gemini 2.5 grounding
	// charges per grounded prompt (request).
	GoogleSearchPrompt, GoogleMapsPrompt money.Micros
}

// feeNames maps the JSON fee names to their Fees field.
var feeNames = map[string]func(*Fees) *money.Micros{
	"web_search_request":   func(f *Fees) *money.Micros { return &f.WebSearchRequest },
	"web_search_call":      func(f *Fees) *money.Micros { return &f.WebSearchCall },
	"file_search_call":     func(f *Fees) *money.Micros { return &f.FileSearchCall },
	"google_search_query":  func(f *Fees) *money.Micros { return &f.GoogleSearchQuery },
	"google_maps_query":    func(f *Fees) *money.Micros { return &f.GoogleMapsQuery },
	"google_search_prompt": func(f *Fees) *money.Micros { return &f.GoogleSearchPrompt },
	"google_maps_prompt":   func(f *Fees) *money.Micros { return &f.GoogleMapsPrompt },
}

// overlay returns f with every non-zero field of o replacing f's.
func (f Fees) overlay(o Fees) Fees {
	for _, get := range feeNames {
		if v := *get(&o); v != 0 {
			*get(&f) = v
		}
	}
	return f
}

func parseFees(where string, in map[string]string) (Fees, error) {
	var f Fees
	for k, v := range in {
		get, ok := feeNames[k]
		if !ok {
			return f, fmt.Errorf("%s: unknown fee %q", where, k)
		}
		m, err := money.Parse(v)
		if err != nil {
			return f, fmt.Errorf("%s fee %q: %w", where, k, err)
		}
		if m < 0 {
			return f, fmt.Errorf("%s fee %q must not be negative", where, k)
		}
		*get(&f) = m
	}
	return f, nil
}

// Pricing is an immutable pricing table. Safe for concurrent use.
type Pricing struct {
	providers map[string]*providerPrices
	now       func() time.Time
}

type providerPrices struct {
	exact    map[string]Price
	patterns []pattern // sorted longest prefix first
	fees     Fees
}

type pattern struct {
	prefix string
	price  Price
}

var (
	defaultOnce    sync.Once
	defaultPricing *Pricing
	defaultErr     error
)

// DefaultPricing returns the embedded pricing table. It panics if the
// embedded JSON is invalid, which the package tests rule out.
func DefaultPricing() *Pricing {
	defaultOnce.Do(func() {
		defaultPricing, defaultErr = parsePricing(embeddedPricing, true)
	})
	if defaultErr != nil {
		panic("meter: embedded pricing.json is invalid: " + defaultErr.Error())
	}
	return defaultPricing
}

// LoadPricing returns the embedded table merged with the optional user
// override file at overridePath ("" for none). Override entries replace
// embedded entries of the same provider and model id; a model mapped to null
// removes it. Fees present in the override replace embedded fees.
func LoadPricing(overridePath string) (*Pricing, error) {
	base, err := parsePricing(embeddedPricing, true)
	if err != nil {
		return nil, fmt.Errorf("meter: embedded pricing: %w", err)
	}
	if overridePath == "" {
		return base, nil
	}
	f, err := os.Open(overridePath)
	if err != nil {
		return nil, fmt.Errorf("meter: open pricing override: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxPricingFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("meter: read pricing override: %w", err)
	}
	if len(data) > maxPricingFileSize {
		return nil, fmt.Errorf("meter: pricing override larger than %d bytes", maxPricingFileSize)
	}
	over, err := decodePricingFile(data)
	if err != nil {
		return nil, fmt.Errorf("meter: pricing override %s: %w", overridePath, err)
	}
	if err := base.merge(over); err != nil {
		return nil, fmt.Errorf("meter: pricing override %s: %w", overridePath, err)
	}
	return base, nil
}

// Lookup finds the price for a model. Matching is case-insensitive: the exact
// id first, then the id with a trailing snapshot date removed
// ("-20250514", "-2025-08-07", "@20251001"), then declared prefix patterns
// (ids ending in "*"), longest prefix winning. A Gemini "models/" prefix is
// ignored. Expired promotional entries are not returned.
func (p *Pricing) Lookup(provider, model string) (Price, bool) {
	if p == nil {
		return Price{}, false
	}
	pp, ok := p.providers[strings.ToLower(provider)]
	if !ok {
		return Price{}, false
	}
	id := strings.ToLower(strings.TrimSpace(model))
	id = strings.TrimPrefix(id, "models/")
	if id == "" {
		return Price{}, false
	}
	cands := []string{id}
	if s := stripSnapshotDate(id); s != id && s != "" {
		cands = append(cands, s)
	}
	for _, c := range cands {
		if pr, ok := pp.exact[c]; ok {
			return p.checkValid(pr)
		}
	}
	for _, c := range cands {
		for _, pat := range pp.patterns {
			if strings.HasPrefix(c, pat.prefix) {
				return p.checkValid(pat.price)
			}
		}
	}
	return Price{}, false
}

// fees returns the per-call fees for a provider.
func (p *Pricing) fees(provider string) Fees {
	if p == nil {
		return Fees{}
	}
	if pp, ok := p.providers[strings.ToLower(provider)]; ok {
		return pp.fees
	}
	return Fees{}
}

// feesFor returns the provider's fees with the model's own fees on top.
func (p *Pricing) feesFor(provider string, pr Price) Fees {
	return p.fees(provider).overlay(pr.Fees)
}

// Models lists the exact and pattern ids priced for a provider, sorted.
func (p *Pricing) Models(provider string) []string {
	if p == nil {
		return nil
	}
	pp, ok := p.providers[strings.ToLower(provider)]
	if !ok {
		return nil
	}
	out := make([]string, 0, len(pp.exact)+len(pp.patterns))
	for id := range pp.exact {
		out = append(out, id)
	}
	for _, pat := range pp.patterns {
		out = append(out, pat.prefix+"*")
	}
	sort.Strings(out)
	return out
}

func (p *Pricing) checkValid(pr Price) (Price, bool) {
	if pr.ValidUntil == "" {
		return pr, true
	}
	until, err := time.Parse("2006-01-02", pr.ValidUntil)
	if err != nil {
		return Price{}, false
	}
	now := time.Now
	if p.now != nil {
		now = p.now
	}
	// Valid through the end of the ValidUntil day, UTC.
	if !now().UTC().Before(until.AddDate(0, 0, 1)) {
		return Price{}, false
	}
	return pr, true
}

var snapshotDate = regexp.MustCompile(`(?:-\d{8}|-\d{4}-\d{2}-\d{2}|@\d{8})$`)

func stripSnapshotDate(id string) string {
	return snapshotDate.ReplaceAllString(id, "")
}

// ---- JSON file format ----

type pricingFile struct {
	Version   int                          `json:"version"`
	Providers map[string]*providerFileJSON `json:"providers"`
}

type providerFileJSON struct {
	Fees          map[string]string         `json:"fees"`
	FeesSourceURL string                    `json:"fees_source_url"`
	Models        map[string]*priceFileJSON `json:"models"`
}

type priceFileJSON struct {
	Input              string            `json:"input"`
	Output             string            `json:"output"`
	CacheWrite         string            `json:"cache_write"`
	CacheWrite5m       string            `json:"cache_write_5m"`
	CacheRead          string            `json:"cache_read"`
	ModalityInput      map[string]string `json:"modality_input"`
	ModalityCacheRead  map[string]string `json:"modality_cache_read"`
	MaxOutputTokens    int64             `json:"max_output_tokens"`
	MaxInputTokens     int64             `json:"max_input_tokens"`
	LongContext        *longFileJSON     `json:"long_context"`
	Tiers              map[string]int64  `json:"tiers"`
	RegionalPremiumPct int64             `json:"regional_premium_pct"`
	ValidUntil         string            `json:"valid_until"`
	Fees               map[string]string `json:"fees"`
	SourceURL          string            `json:"source_url"`
	AsOf               string            `json:"as_of"`
	Note               string            `json:"note"`
}

type longFileJSON struct {
	ThresholdTokens   int64             `json:"threshold_tokens"`
	Input             string            `json:"input"`
	Output            string            `json:"output"`
	CacheWrite        string            `json:"cache_write"`
	CacheWrite5m      string            `json:"cache_write_5m"`
	CacheRead         string            `json:"cache_read"`
	ModalityInput     map[string]string `json:"modality_input"`
	ModalityCacheRead map[string]string `json:"modality_cache_read"`
}

func decodePricingFile(data []byte) (*pricingFile, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f pricingFile
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON object")
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("unsupported version %d (want 1)", f.Version)
	}
	return &f, nil
}

func parsePricing(data []byte, strict bool) (*Pricing, error) {
	f, err := decodePricingFile(data)
	if err != nil {
		return nil, err
	}
	p := &Pricing{providers: map[string]*providerPrices{}}
	for name, pf := range f.Providers {
		if pf == nil {
			continue
		}
		pp := &providerPrices{exact: map[string]Price{}}
		if err := applyProvider(pp, name, pf, strict); err != nil {
			return nil, err
		}
		p.providers[strings.ToLower(name)] = pp
	}
	return p, nil
}

func (p *Pricing) merge(over *pricingFile) error {
	for name, pf := range over.Providers {
		key := strings.ToLower(name)
		if pf == nil {
			delete(p.providers, key)
			continue
		}
		pp, ok := p.providers[key]
		if !ok {
			pp = &providerPrices{exact: map[string]Price{}}
			p.providers[key] = pp
		}
		if err := applyProvider(pp, name, pf, false); err != nil {
			return err
		}
	}
	return nil
}

func applyProvider(pp *providerPrices, name string, pf *providerFileJSON, strict bool) error {
	if len(pf.Fees) > 0 {
		f, err := parseFees(name, pf.Fees)
		if err != nil {
			return err
		}
		// Each listed fee replaces the previous value, "$0" included.
		for k := range pf.Fees {
			*feeNames[k](&pp.fees) = *feeNames[k](&f)
		}
	}
	for rawID, pj := range pf.Models {
		id := strings.ToLower(strings.TrimSpace(rawID))
		isPattern := strings.HasSuffix(id, "*")
		prefix := strings.TrimSuffix(id, "*")
		if id == "" || prefix == "" || strings.Contains(prefix, "*") {
			return fmt.Errorf("%s: invalid model id %q", name, rawID)
		}
		// Replace any previous entry with this id.
		delete(pp.exact, id)
		pp.removePattern(prefix)
		if pj == nil {
			continue // null removes the model
		}
		pr, err := pj.toPrice(strict)
		if err != nil {
			return fmt.Errorf("%s model %q: %w", name, rawID, err)
		}
		if isPattern {
			pp.patterns = append(pp.patterns, pattern{prefix: prefix, price: pr})
		} else {
			pp.exact[id] = pr
		}
	}
	sort.SliceStable(pp.patterns, func(i, j int) bool {
		if len(pp.patterns[i].prefix) != len(pp.patterns[j].prefix) {
			return len(pp.patterns[i].prefix) > len(pp.patterns[j].prefix)
		}
		return pp.patterns[i].prefix < pp.patterns[j].prefix
	})
	return nil
}

func (pp *providerPrices) removePattern(prefix string) {
	out := pp.patterns[:0]
	for _, p := range pp.patterns {
		if p.prefix != prefix {
			out = append(out, p)
		}
	}
	pp.patterns = out
}

func parseRate(field, s string, required bool) (money.PerMTok, error) {
	if s == "" {
		if required {
			return 0, fmt.Errorf("%s is required", field)
		}
		return 0, nil
	}
	m, err := money.Parse(s)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", field, err)
	}
	return money.PerMTok(m), nil
}

func parseModalities(field string, in map[string]string) (map[string]money.PerMTok, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make(map[string]money.PerMTok, len(in))
	for k, v := range in {
		r, err := parseRate(field+"."+k, v, true)
		if err != nil {
			return nil, err
		}
		key := strings.ToUpper(strings.TrimSpace(k))
		if key == "" {
			return nil, fmt.Errorf("%s: empty modality", field)
		}
		out[key] = r
	}
	return out, nil
}

var dateRe = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func (pj *priceFileJSON) toPrice(strict bool) (Price, error) {
	var pr Price
	var err error
	if pr.Input, err = parseRate("input", pj.Input, true); err != nil {
		return pr, err
	}
	if pr.Input <= 0 {
		return pr, errors.New("input rate must be positive")
	}
	if pr.Output, err = parseRate("output", pj.Output, true); err != nil {
		return pr, err
	}
	if pr.CacheWrite, err = parseRate("cache_write", pj.CacheWrite, false); err != nil {
		return pr, err
	}
	if pr.CacheWrite5m, err = parseRate("cache_write_5m", pj.CacheWrite5m, false); err != nil {
		return pr, err
	}
	// A missing cache-read rate is priced at the full input rate (no
	// discount assumed).
	if pr.CacheRead, err = parseRate("cache_read", pj.CacheRead, false); err != nil {
		return pr, err
	}
	if pj.CacheRead == "" {
		pr.CacheRead = pr.Input
	}
	if pr.ModalityInput, err = parseModalities("modality_input", pj.ModalityInput); err != nil {
		return pr, err
	}
	if pr.ModalityCacheRead, err = parseModalities("modality_cache_read", pj.ModalityCacheRead); err != nil {
		return pr, err
	}
	if pj.MaxOutputTokens < 0 || pj.MaxInputTokens < 0 {
		return pr, errors.New("token limits must not be negative")
	}
	pr.MaxOutputTokens, pr.MaxInputTokens = pj.MaxOutputTokens, pj.MaxInputTokens
	if lc := pj.LongContext; lc != nil {
		l := &LongContext{ThresholdTokens: lc.ThresholdTokens}
		if l.ThresholdTokens <= 0 {
			return pr, errors.New("long_context.threshold_tokens must be positive")
		}
		if l.Input, err = parseRate("long_context.input", lc.Input, true); err != nil {
			return pr, err
		}
		if l.Output, err = parseRate("long_context.output", lc.Output, true); err != nil {
			return pr, err
		}
		if l.CacheWrite, err = parseRate("long_context.cache_write", lc.CacheWrite, false); err != nil {
			return pr, err
		}
		if l.CacheWrite5m, err = parseRate("long_context.cache_write_5m", lc.CacheWrite5m, false); err != nil {
			return pr, err
		}
		if l.CacheRead, err = parseRate("long_context.cache_read", lc.CacheRead, false); err != nil {
			return pr, err
		}
		if lc.CacheRead == "" {
			l.CacheRead = l.Input
		}
		if l.ModalityInput, err = parseModalities("long_context.modality_input", lc.ModalityInput); err != nil {
			return pr, err
		}
		if l.ModalityCacheRead, err = parseModalities("long_context.modality_cache_read", lc.ModalityCacheRead); err != nil {
			return pr, err
		}
		// The long tier must never be cheaper than the base tier: it is used
		// for worst-case estimates.
		if l.Input < pr.Input || l.Output < pr.Output || l.CacheRead < pr.CacheRead || l.CacheWrite < pr.CacheWrite {
			return pr, errors.New("long_context rates must not be lower than base rates")
		}
		pr.LongContext = l
	}
	if len(pj.Tiers) > 0 {
		pr.Tiers = make(map[string]int64, len(pj.Tiers))
		for k, v := range pj.Tiers {
			if v <= 0 || v > 10_000 {
				return pr, fmt.Errorf("tier %q multiplier %d%% out of range", k, v)
			}
			pr.Tiers[strings.ToLower(k)] = v
		}
	}
	if pj.RegionalPremiumPct < 0 || pj.RegionalPremiumPct > 1000 {
		return pr, errors.New("regional_premium_pct out of range")
	}
	pr.RegionalPremiumPct = pj.RegionalPremiumPct
	if pj.ValidUntil != "" {
		if _, err := time.Parse("2006-01-02", pj.ValidUntil); err != nil || !dateRe.MatchString(pj.ValidUntil) {
			return pr, fmt.Errorf("valid_until %q is not YYYY-MM-DD", pj.ValidUntil)
		}
	}
	pr.ValidUntil = pj.ValidUntil
	if pr.Fees, err = parseFees("model", pj.Fees); err != nil {
		return pr, err
	}
	pr.Source, pr.AsOf, pr.Note = pj.SourceURL, pj.AsOf, pj.Note
	if pr.AsOf != "" {
		if _, err := time.Parse("2006-01-02", pr.AsOf); err != nil || !dateRe.MatchString(pr.AsOf) {
			return pr, fmt.Errorf("as_of %q is not YYYY-MM-DD", pr.AsOf)
		}
	}
	if strict {
		if !strings.HasPrefix(pr.Source, "https://") {
			return pr, errors.New("source_url must be an https URL")
		}
		if pr.AsOf == "" {
			return pr, errors.New("as_of is required")
		}
	}
	if pr.Source == "" {
		pr.Source = "user override"
	}
	return pr, nil
}
