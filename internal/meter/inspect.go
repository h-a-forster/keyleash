package meter

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// Meter inspects requests, estimates their worst-case cost and prices their
// actual usage. A Meter is read-only after construction and safe for
// concurrent use.
type Meter struct {
	// Pricing is the rate table. A nil table prices nothing.
	Pricing *Pricing
	// AssumeMaxOutputTokens is the policy output ceiling used when neither the
	// request nor the pricing table gives one. 0 means none (such requests
	// are then unpriced).
	AssumeMaxOutputTokens int64
	// AddStreamUsage makes PrepareBody ask OpenAI-style streams for a final
	// usage chunk (spec §10.3).
	AddStreamUsage bool
}

// imageURLTokens is charged per image referenced by URL (which costs far more
// tokens than the URL's bytes). It is a generous bound on per-image token
// cost across supported providers.
const imageURLTokens = 32_768

// ErrMalformedRequest is wrapped by every Inspect/PrepareBody error caused by
// the request body itself. The proxy denies such requests.
var ErrMalformedRequest = errors.New("meter: malformed request")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformedRequest, fmt.Sprintf(format, args...))
}

// Inspect parses a request for an allowed endpoint. Unmetered endpoints
// return RequestInfo with only Kind set. For metered endpoints the body must
// be a single, well-formed JSON object without duplicate keys (duplicates
// could be read differently upstream); anything else is an error and the
// proxy denies the request.
//
// InputTokensEstimate is ceil(len(body)/3), raised to the model's context
// window when the request pulls in content the body does not contain
// (server-side files, cached content, stored conversations, server tools),
// plus a fixed allowance per image referenced by URL. If the model has no
// known context window, InputTokensEstimate is UnboundedInputTokens and the
// request is unpriced.
//
// When the request multiplies its own cost (OpenAI n>1, Gemini
// candidateCount>1, or a premium service tier / speed), Inspect folds that
// factor into InputTokensEstimate and MaxOutputTokens (which then already
// include any thinking budget, with ThinkingTokens set to 0), so that
// Estimate stays a pure function of RequestInfo. The tier factor is the
// model's highest unless the request names a tier (see estimateTierPct).
//
// Per-call tool fees for declared tools (web search, file search, Gemini
// grounding) are added at their worst case, converted to input tokens at the
// model's highest input rate. A declared tool whose fee cannot be priced or
// whose call count has no cap makes InputTokensEstimate UnboundedInputTokens.
func (m *Meter) Inspect(p *provider.Provider, ep provider.Endpoint, path string, body []byte) (RequestInfo, error) {
	info := RequestInfo{Kind: ep.Kind}
	if !ep.Metered || ep.Kind == provider.KindFree {
		return info, nil
	}
	if p == nil {
		return info, errors.New("meter: nil provider")
	}
	info.InputTokensEstimate = int64((len(body) + 2) / 3)

	obj, err := parseObject(body)
	if err != nil {
		return info, err
	}
	n := int64(1)
	tier := ""
	switch ep.Kind {
	case provider.KindAnthropicMessages:
		if info.Model, err = obj.requiredString("model"); err != nil {
			return info, err
		}
		if info.MaxOutputTokens, _, err = obj.int("max_tokens"); err != nil {
			return info, err
		}
		if info.Stream, err = obj.bool("stream"); err != nil {
			return info, err
		}
		if raw, ok := obj.get("thinking"); ok {
			th, err := parseObject(raw)
			if err != nil {
				return info, malformed("thinking: %v", err)
			}
			if info.ThinkingTokens, _, err = th.int("budget_tokens"); err != nil {
				return info, err
			}
		}
		if tier, err = obj.string("speed"); err != nil {
			return info, err
		}

	case provider.KindOpenAIChat:
		if info.Model, err = obj.requiredString("model"); err != nil {
			return info, err
		}
		a, _, err := obj.int("max_completion_tokens")
		if err != nil {
			return info, err
		}
		b, _, err := obj.int("max_tokens")
		if err != nil {
			return info, err
		}
		info.MaxOutputTokens = max(a, b)
		if info.Stream, err = obj.bool("stream"); err != nil {
			return info, err
		}
		if v, ok, err := obj.int("n"); err != nil {
			return info, err
		} else if ok {
			if v < 1 {
				return info, malformed("n must be at least 1")
			}
			n = v
		}
		if tier, err = obj.string("service_tier"); err != nil {
			return info, err
		}

	case provider.KindOpenAIResponses:
		if info.Model, err = obj.requiredString("model"); err != nil {
			return info, err
		}
		if info.MaxOutputTokens, _, err = obj.int("max_output_tokens"); err != nil {
			return info, err
		}
		if info.Stream, err = obj.bool("stream"); err != nil {
			return info, err
		}
		if tier, err = obj.string("service_tier"); err != nil {
			return info, err
		}

	case provider.KindOpenAIEmbeddings:
		if info.Model, err = obj.requiredString("model"); err != nil {
			return info, err
		}

	case provider.KindGeminiGenerate, provider.KindGeminiEmbed:
		if info.Model, err = geminiModelFromPath(path); err != nil {
			return info, err
		}
		if ep.Kind == provider.KindGeminiEmbed {
			break
		}
		info.Stream = strings.HasSuffix(path, ":streamGenerateContent")
		gcRaw, ok, err := obj.either("generationConfig", "generation_config")
		if err != nil {
			return info, err
		}
		if ok {
			gc, err := parseObject(gcRaw)
			if err != nil {
				return info, malformed("generationConfig: %v", err)
			}
			if info.MaxOutputTokens, _, err = gc.eitherInt("maxOutputTokens", "max_output_tokens"); err != nil {
				return info, err
			}
			if v, ok, err := gc.eitherInt("candidateCount", "candidate_count"); err != nil {
				return info, err
			} else if ok && v > 1 {
				n = v
			}
			if tcRaw, ok, err := gc.either("thinkingConfig", "thinking_config"); err != nil {
				return info, err
			} else if ok {
				tc, err := parseObject(tcRaw)
				if err != nil {
					return info, malformed("thinkingConfig: %v", err)
				}
				tb, err := tc.eitherSignedInt("thinkingBudget", "thinking_budget")
				if err != nil {
					return info, err
				}
				if tb > 0 { // -1 is "dynamic": bounded by maxOutputTokens
					info.ThinkingTokens = tb
				}
			}
		}
		if raw, ok, err := obj.either("serviceTier", "service_tier"); err != nil {
			return info, err
		} else if ok {
			if tier, err = stringValue("service_tier", raw); err != nil {
				return info, err
			}
		}

	default:
		return info, fmt.Errorf("meter: unsupported endpoint kind %q", ep.Kind)
	}

	// Content the body references but does not contain.
	scan, err := scanServerSide(body)
	if err != nil {
		return info, err
	}
	// Token-id arrays (OpenAI embeddings accept them) can pack a token into
	// two bytes ("1,"), beating the bytes/3 rule; one token per number bounds it.
	info.InputTokensEstimate = max(info.InputTokensEstimate, scan.numbers)
	info.InputTokensEstimate = satAddTokens(info.InputTokensEstimate, satMulTokens(scan.imageURLs, imageURLTokens))

	pr, priced := m.lookup(p.Name, info.Model)
	if !priced {
		// Estimate will report the model unpriced; WorstCaseEstimate bounds
		// it at the provider's most expensive rates, so fold in everything
		// that can be bounded and mark the rest unbounded.
		return m.inspectUnpriced(p.Name, ep.Kind, obj, n, scan.serverSide, info)
	}
	if scan.serverSide {
		if pr.MaxInputTokens <= 0 {
			// The stored/fetched content cannot be bounded: unpriced.
			info.InputTokensEstimate = UnboundedInputTokens
			return info, nil
		}
		info.InputTokensEstimate = max(info.InputTokensEstimate, pr.MaxInputTokens)
	}
	fee, ok, err := toolFees(ep.Kind, obj, m.Pricing.feesFor(p.Name, pr), n)
	if err != nil {
		return info, err
	}
	if !ok {
		info.InputTokensEstimate = UnboundedInputTokens
		return info, nil
	}

	pct := estimateTierPct(ep.Kind, tier, pr)
	if n > 1 || pct > 100 {
		if out, ok := m.outputCeiling(info, pr); ok {
			info.MaxOutputTokens = scaleTokens(satMulTokens(out, n), pct)
			info.ThinkingTokens = 0
		}
		info.InputTokensEstimate = scaleTokens(info.InputTokensEstimate, pct)
	}
	if fee > 0 {
		info.InputTokensEstimate = satAddTokens(info.InputTokensEstimate, feeTokens(fee, pr.longRates().maxInputRate()))
	}
	if info.InputTokensEstimate >= UnboundedInputTokens {
		// Saturated arithmetic is still a (huge) bound: keep it priced.
		info.InputTokensEstimate = UnboundedInputTokens - 1
	}
	return info, nil
}

// UnboundedInputTokens as RequestInfo.InputTokensEstimate means the
// request's input or per-call fees cannot be bounded before it is sent
// (server-side context on a model without a known context window, or a
// declared tool whose fee cannot be priced or capped). Estimate then reports
// priced=false so the caller applies its unknown-model policy.
const UnboundedInputTokens int64 = math.MaxInt64

// estimateTierPct is the service-tier multiplier an estimate must assume.
// A request that names a tier gets that tier's multiplier (never below
// standard, so flex does not lower an estimate; unknown names take the
// model's highest). A request that leaves the tier unset (or "auto") may be
// served at a project default the request does not show (OpenAI
// service_tier=auto; Gemini reports the tier only in a response header), so
// it takes the model's highest multiplier. Anthropic is the exception: fast
// mode runs only when the request sets speed="fast"
// (https://platform.claude.com/docs/en/build-with-claude/fast-mode).
func estimateTierPct(kind, tier string, pr Price) int64 {
	t := strings.ToLower(strings.TrimSpace(tier))
	if t == "" || t == "auto" {
		if kind == provider.KindAnthropicMessages {
			return 100
		}
		return pr.maxTierPct()
	}
	return max(pr.tierPct(t), 100)
}

// feeTokens converts a fee to the number of input tokens that cost at least
// as much at rate, so Estimate (a function of RequestInfo only) covers it.
func feeTokens(fee money.Micros, rate money.PerMTok) int64 {
	if fee <= 0 {
		return 0
	}
	if rate <= 0 || int64(fee) > math.MaxInt64/1_000_000 {
		return math.MaxInt64
	}
	num := int64(fee) * 1_000_000
	return num/int64(rate) + 1 // +1 covers the remainder (and is harmless without one)
}

// toolFees is the worst-case per-call fee total for the tools a request
// declares. ok is false when a declared tool (or content that may declare
// tools server-side) has a fee that cannot be priced or bounded; the request
// is then unpriced.
func toolFees(kind string, obj *jsonObject, fees Fees, n int64) (money.Micros, bool, error) {
	var total money.Micros
	tools, err := obj.objectArray("tools")
	if err != nil {
		return 0, false, err
	}
	switch kind {
	case provider.KindAnthropicMessages:
		for _, t := range tools {
			typ, err := t.string("type")
			if err != nil {
				return 0, false, err
			}
			switch {
			case strings.HasPrefix(typ, "web_search"):
				uses, ok, err := t.int("max_uses")
				if err != nil {
					return 0, false, err
				}
				if !ok {
					return 0, false, nil // no cap on searches
				}
				total = satAdd(total, mulMicros(fees.WebSearchRequest, uses))
			case strings.HasPrefix(typ, "code_execution"):
				// Billed per container-hour, not per request.
				return 0, false, nil
			}
		}

	case provider.KindOpenAIChat:
		if _, ok := obj.get("web_search_options"); ok {
			return 0, false, nil // search-model fees are not in the table
		}

	case provider.KindOpenAIResponses:
		if _, ok := obj.get("prompt"); ok {
			// A stored prompt can declare tools the body does not show.
			return 0, false, nil
		}
		var rate money.Micros
		feeTool := false
		for _, t := range tools {
			typ, err := t.string("type")
			if err != nil {
				return 0, false, err
			}
			switch {
			case strings.HasPrefix(typ, "web_search"):
				feeTool, rate = true, max(rate, fees.WebSearchCall)
			case strings.HasPrefix(typ, "file_search"):
				feeTool, rate = true, max(rate, fees.FileSearchCall)
			case strings.HasPrefix(typ, "code_interpreter"), strings.HasPrefix(typ, "image_generation"):
				// Container sessions and image-model tokens are billed
				// outside the response's usage.
				return 0, false, nil
			case typ == "shell":
				_, env := t.get("environment")
				_, ctr := t.get("container")
				if env || ctr {
					return 0, false, nil // hosted container
				}
			}
		}
		if feeTool {
			calls, ok, err := obj.int("max_tool_calls")
			if err != nil {
				return 0, false, err
			}
			if !ok {
				return 0, false, nil // no cap on built-in tool calls
			}
			total = mulMicros(rate, calls)
		}

	case provider.KindGeminiGenerate:
		search, maps := false, false
		for _, t := range tools {
			for _, k := range t.keys {
				if _, ok := t.get(k); !ok {
					continue
				}
				switch k {
				case "googleSearch", "google_search", "googleSearchRetrieval", "google_search_retrieval":
					search = true
				case "googleMaps", "google_maps":
					maps = true
				}
			}
		}
		if _, ok, err := obj.either("cachedContent", "cached_content"); err != nil {
			return 0, false, err
		} else if ok {
			// Cached content can carry its own tools.
			search, maps = true, true
		}
		for _, g := range []struct {
			used          bool
			query, prompt money.Micros
		}{{search, fees.GoogleSearchQuery, fees.GoogleSearchPrompt}, {maps, fees.GoogleMapsQuery, fees.GoogleMapsPrompt}} {
			if !g.used {
				continue
			}
			if g.query > 0 || g.prompt <= 0 {
				// Per-query billing has no request-side cap; no fee at
				// all means the price is unknown.
				return 0, false, nil
			}
			total = satAdd(total, mulMicros(g.prompt, n))
		}
	}
	return total, true, nil
}

func (m *Meter) lookup(prov, model string) (Price, bool) {
	if m == nil || m.Pricing == nil {
		return Price{}, false
	}
	return m.Pricing.Lookup(prov, model)
}

// PrepareBody returns the body to send upstream. When AddStreamUsage is set
// and the request is a streamed OpenAI-style chat completion that has not
// asked for usage, it sets stream_options.include_usage=true, keeping every
// other field's bytes as sent. In every other case body is returned
// unchanged.
func (m *Meter) PrepareBody(ep provider.Endpoint, body []byte, info RequestInfo) ([]byte, error) {
	if m == nil || !m.AddStreamUsage || ep.Kind != provider.KindOpenAIChat || !info.Stream {
		return body, nil
	}
	obj, err := parseObject(body)
	if err != nil {
		return nil, err
	}
	stream, err := obj.bool("stream")
	if err != nil {
		return nil, err
	}
	if !stream {
		return body, nil
	}
	newOpts := []byte(`{"include_usage":true}`)
	if raw, ok := obj.get("stream_options"); ok {
		so, err := parseObject(raw)
		if err != nil {
			return nil, malformed("stream_options: %v", err)
		}
		inc, err := so.bool("include_usage")
		if err != nil {
			return nil, err
		}
		if inc {
			return body, nil
		}
		so.set("include_usage", []byte("true"))
		newOpts = so.encode()
	}
	obj.set("stream_options", newOpts)
	return obj.encode(), nil
}

// ---- strict JSON object helpers ----

// jsonObject is a parsed JSON object that keeps key order and raw values.
type jsonObject struct {
	keys []string
	vals map[string]json.RawMessage
}

// parseObject parses exactly one JSON object. Duplicate keys, trailing data
// and non-object values are errors.
func parseObject(data []byte) (*jsonObject, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, malformed("body is not JSON")
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, malformed("body is not a JSON object")
	}
	o := &jsonObject{vals: map[string]json.RawMessage{}}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, malformed("invalid JSON")
		}
		k, ok := kt.(string)
		if !ok {
			return nil, malformed("invalid JSON key")
		}
		if _, dup := o.vals[k]; dup {
			return nil, malformed("duplicate key %q", k)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, malformed("invalid JSON value for %q", k)
		}
		o.keys = append(o.keys, k)
		o.vals[k] = raw
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, malformed("invalid JSON object")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, malformed("trailing data after JSON object")
	}
	return o, nil
}

// get returns a non-null value.
func (o *jsonObject) get(k string) (json.RawMessage, bool) {
	v, ok := o.vals[k]
	if !ok || isNull(v) {
		return nil, false
	}
	return v, true
}

// either returns the value of exactly one of two alias keys (proto JSON
// accepts both spellings); both present is ambiguous and an error.
func (o *jsonObject) either(a, b string) (json.RawMessage, bool, error) {
	va, oka := o.get(a)
	vb, okb := o.get(b)
	if oka && okb {
		return nil, false, malformed("both %q and %q present", a, b)
	}
	if oka {
		return va, true, nil
	}
	return vb, okb, nil
}

// objectArray returns the elements of an array of objects (nil when the key
// is absent or null).
func (o *jsonObject) objectArray(k string) ([]*jsonObject, error) {
	raw, ok := o.get(k)
	if !ok {
		return nil, nil
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, malformed("%q must be an array", k)
	}
	out := make([]*jsonObject, 0, len(elems))
	for _, e := range elems {
		eo, err := parseObject(e)
		if err != nil {
			return nil, malformed("%q element: %v", k, err)
		}
		out = append(out, eo)
	}
	return out, nil
}

func (o *jsonObject) set(k string, v json.RawMessage) {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

func (o *jsonObject) encode() []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k) // a string always marshals
		b.Write(kb)
		b.WriteByte(':')
		b.Write(o.vals[k])
	}
	b.WriteByte('}')
	return b.Bytes()
}

func isNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

func (o *jsonObject) requiredString(k string) (string, error) {
	s, err := o.string(k)
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", malformed("%q is required", k)
	}
	return s, nil
}

func (o *jsonObject) string(k string) (string, error) {
	raw, ok := o.get(k)
	if !ok {
		return "", nil
	}
	return stringValue(k, raw)
}

func stringValue(k string, raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", malformed("%q must be a string", k)
	}
	return s, nil
}

func (o *jsonObject) bool(k string) (bool, error) {
	raw, ok := o.get(k)
	if !ok {
		return false, nil
	}
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, malformed("%q must be a boolean", k)
}

// int reads a non-negative JSON integer. Fractions, exponents, strings and
// negative numbers are errors (fail closed rather than guess how upstream
// would coerce them).
func (o *jsonObject) int(k string) (int64, bool, error) {
	raw, ok := o.get(k)
	if !ok {
		return 0, false, nil
	}
	v, err := intValue(k, raw, false)
	return v, err == nil, err
}

func (o *jsonObject) eitherInt(a, b string) (int64, bool, error) {
	raw, ok, err := o.either(a, b)
	if err != nil || !ok {
		return 0, false, err
	}
	v, err := intValue(a, raw, false)
	return v, err == nil, err
}

// eitherSignedInt allows negative values (Gemini thinkingBudget -1).
func (o *jsonObject) eitherSignedInt(a, b string) (int64, error) {
	raw, ok, err := o.either(a, b)
	if err != nil || !ok {
		return 0, err
	}
	return intValue(a, raw, true)
}

func intValue(k string, raw json.RawMessage, signed bool) (int64, error) {
	s := string(bytes.TrimSpace(raw))
	if s == "" || strings.ContainsAny(s, ".eE\"") {
		return 0, malformed("%q must be an integer", k)
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		// Out-of-range integers are valid JSON but absurd; refuse.
		return 0, malformed("%q must be an integer in range", k)
	}
	if v < 0 && !signed {
		return 0, malformed("%q must not be negative", k)
	}
	return v, nil
}

// geminiModelFromPath extracts <model> from ".../models/<model>:<method>".
func geminiModelFromPath(path string) (string, error) {
	seg := path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		seg = path[i+1:]
	}
	model, _, ok := strings.Cut(seg, ":")
	if !ok || model == "" {
		return "", malformed("no model in path")
	}
	un, err := url.PathUnescape(model)
	if err != nil || un == "" || strings.ContainsAny(un, "/:") {
		return "", malformed("invalid model in path")
	}
	return un, nil
}

// ---- server-side content scan ----

type scanResult struct {
	serverSide bool  // input will include content not present in the body
	imageURLs  int64 // images referenced by URL
	numbers    int64 // JSON numbers (pre-tokenized input can be ~2 bytes/token)
}

// serverSideKeys are object keys whose presence means the provider will add
// input tokens that are not in the request body.
var serverSideKeys = map[string]bool{
	"file_id": true, "fileData": true, "file_data": true, "fileUri": true, "file_uri": true,
	"file_url": true, "previous_response_id": true, "conversation": true,
	"cachedContent": true, "cached_content": true, "mcp_servers": true,
	"googleSearch": true, "google_search": true, "googleSearchRetrieval": true,
	"google_search_retrieval": true, "urlContext": true, "url_context": true,
	"codeExecution": true, "code_execution": true, "fileSearch": true, "file_search": true,
	"googleMaps": true, "google_maps": true,
}

// serverSideTypes are "type" values (exact, or prefix for versioned server
// tools) that make the provider fetch or generate extra input.
var serverSideTypeExact = map[string]bool{"url": true, "file": true, "mcp": true}
var serverSideTypePrefix = []string{"web_search", "web_fetch", "code_execution", "code_interpreter", "file_search", "tool_search", "image_generation"}

// scanServerSide walks the whole body once (iteratively, no recursion).
func scanServerSide(body []byte) (scanResult, error) {
	var res scanResult
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	type frame struct {
		obj       bool
		expectKey bool
		lastKey   string
	}
	var stack []frame
	afterValue := func() {
		if n := len(stack); n > 0 && stack[n-1].obj {
			stack[n-1].expectKey = true
		}
	}
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return res, nil
		}
		if err != nil {
			return res, malformed("invalid JSON")
		}
		switch t := tok.(type) {
		case json.Delim:
			switch t {
			case '{':
				stack = append(stack, frame{obj: true, expectKey: true})
			case '[':
				stack = append(stack, frame{})
			case '}', ']':
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				afterValue()
			}
			continue
		case string:
			if n := len(stack); n > 0 && stack[n-1].obj && stack[n-1].expectKey {
				stack[n-1].expectKey = false
				stack[n-1].lastKey = t
				if serverSideKeys[t] {
					res.serverSide = true
				}
				if t == "image_url" {
					res.imageURLs++
				}
				continue
			}
			if n := len(stack); n > 0 && stack[n-1].obj && stack[n-1].lastKey == "type" {
				if serverSideTypeExact[t] {
					res.serverSide = true
				}
				for _, p := range serverSideTypePrefix {
					if strings.HasPrefix(t, p) {
						res.serverSide = true
					}
				}
			}
		case json.Number:
			res.numbers++
		}
		afterValue()
	}
}
