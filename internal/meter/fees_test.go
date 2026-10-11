package meter

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// ---- Finding 1: server-side context must be bounded or unpriced ----

// Repro from the security review: a stored conversation on a model that had
// no context window in the table was estimated from the body alone.
func TestServerSideReproGPT52Pro(t *testing.T) {
	m := testMeter()
	body := `{"model":"gpt-5.2-pro","previous_response_id":"resp_abc","input":"continue","max_output_tokens":1000}`
	info, err := inspect(t, m, "openai", "POST", "/v1/responses", body)
	if err != nil {
		t.Fatal(err)
	}
	est, ok := m.Estimate("openai", info)
	if !ok {
		t.Fatal("unpriced")
	}
	// 300k stored-context tokens plus 1000 output tokens.
	cost, _ := m.Cost("openai", Usage{Model: "gpt-5.2-pro", InputTokens: 300_000, OutputTokens: 1000})
	if cost != 6_468_000 || est < cost {
		t.Fatalf("estimate %v does not bound cost %v", est, cost)
	}
}

// serverSideTriggers lists every key and type value that marks content held
// server-side, built from the scanner's own tables so a new trigger is
// covered automatically.
func serverSideTriggers() map[string]string {
	out := map[string]string{}
	keys := make([]string, 0, len(serverSideKeys))
	for k := range serverSideKeys {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out["key "+k] = fmt.Sprintf(`{%q:"x"}`, k)
	}
	for t := range serverSideTypeExact {
		out["type "+t] = fmt.Sprintf(`{"type":%q}`, t)
	}
	for _, p := range serverSideTypePrefix {
		out["type "+p+"*"] = fmt.Sprintf(`{"type":%q}`, p+"_20250101")
	}
	return out
}

// Golden per trigger: with a context window the input is raised to it; without
// one the request is unpriced (never priced from the body alone).
func TestServerSideTriggersGolden(t *testing.T) {
	bounded := testMeter()
	over, err := LoadPricing(writeTemp(t, `{"version":1,"providers":{"openai":{"models":{
		"gpt-5.2-pro":{"input":"$21","output":"$168","max_output_tokens":128000}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	unbounded := &Meter{Pricing: over, AssumeMaxOutputTokens: 4096}
	pr, _ := DefaultPricing().Lookup("openai", "gpt-5.2-pro")
	if pr.MaxInputTokens != 400_000 {
		t.Fatalf("gpt-5.2-pro context window = %d", pr.MaxInputTokens)
	}
	wantMin := tokCost(pr.Input, pr.MaxInputTokens) + tokCost(pr.Output, 1000)
	for name, extra := range serverSideTriggers() {
		t.Run(name, func(t *testing.T) {
			body := `{"model":"gpt-5.2-pro","max_output_tokens":1000,"input":"go on","metadata_x":` + extra + `}`
			info, err := inspect(t, bounded, "openai", "POST", "/v1/responses", body)
			if err != nil {
				t.Fatal(err)
			}
			if info.InputTokensEstimate < pr.MaxInputTokens {
				t.Fatalf("InputTokensEstimate %d < context window", info.InputTokensEstimate)
			}
			if est, ok := bounded.Estimate("openai", info); !ok || est < wantMin {
				t.Fatalf("Estimate %v,%v < %v", est, ok, wantMin)
			}
			info, err = inspect(t, unbounded, "openai", "POST", "/v1/responses", body)
			if err != nil {
				t.Fatal(err)
			}
			if est, ok := unbounded.Estimate("openai", info); ok {
				t.Fatalf("no context window but priced at %v", est)
			}
		})
	}
	// Control: no trigger, no context window needed.
	info, _ := inspect(t, unbounded, "openai", "POST", "/v1/responses", `{"model":"gpt-5.2-pro","max_output_tokens":1000,"input":"hi"}`)
	if _, ok := unbounded.Estimate("openai", info); !ok {
		t.Fatal("plain request unpriced")
	}
}

func TestEveryModelHasContextWindow(t *testing.T) {
	p := DefaultPricing()
	for _, prov := range []string{"anthropic", "openai", "gemini"} {
		for _, id := range p.Models(prov) {
			pr, ok := p.Lookup(prov, id)
			if !ok {
				continue // expired promo
			}
			if pr.MaxInputTokens <= 0 {
				t.Errorf("%s/%s: max_input_tokens missing", prov, id)
			}
		}
	}
}

// ---- Finding 2: an unset service tier may resolve to a premium one ----

// tiersReportable lists every tier name a response could report for a
// request that did not set one.
func tiersReportable(prov string, pr Price) []string {
	if prov == "anthropic" {
		// Fast mode only runs when the request sets speed=fast.
		return []string{"", "standard"}
	}
	out := []string{"", "auto", "default", "standard", "priority", "fast", "flex", "scale", "some-new-tier"}
	for k := range pr.Tiers {
		out = append(out, k)
	}
	return out
}

func requestFor(prov, model, extra string) (path, body string) {
	switch prov {
	case "anthropic":
		return "/v1/messages", `{"model":"` + model + `","max_tokens":5000,` + extra + `"messages":[{"role":"user","content":"hello there"}]}`
	case "openai":
		return "/v1/responses", `{"model":"` + model + `","max_output_tokens":5000,` + extra + `"input":"hello there"}`
	default:
		return "/v1beta/models/" + model + ":generateContent", `{` + extra + `"contents":[{"parts":[{"text":"hello there"}]}],"generationConfig":{"maxOutputTokens":5000}}`
	}
}

func TestEstimateBoundsCostAnyReportedTier(t *testing.T) {
	m := testMeter()
	p := DefaultPricing()
	for _, prov := range []string{"anthropic", "openai", "gemini"} {
		for _, id := range p.Models(prov) {
			pr, ok := p.Lookup(prov, id)
			if !ok || strings.HasPrefix(id, "text-embedding") || strings.HasPrefix(id, "gemini-embedding") {
				continue
			}
			path, body := requestFor(prov, id, "")
			info, err := inspect(t, m, prov, "POST", path, body)
			if err != nil {
				t.Fatalf("%s/%s: %v", prov, id, err)
			}
			est, ok := m.Estimate(prov, info)
			if !ok {
				t.Fatalf("%s/%s unpriced", prov, id)
			}
			in := int64((len(body) + 2) / 3)
			for _, tier := range tiersReportable(prov, pr) {
				for _, split := range [][3]int64{{in, 0, 0}, {0, in, 0}, {0, 0, in}} {
					d := usageDetail{Usage: Usage{Model: id, InputTokens: split[0], CacheReadTokens: split[1], CacheWriteTokens: split[2], OutputTokens: 5000}, tier: tier, regional: true}
					if c := priceUsage(pr, d, Fees{}); c > est {
						t.Fatalf("%s/%s tier %q: cost %v > estimate %v", prov, id, tier, c, est)
					}
				}
			}
		}
	}
}

func TestEstimateTierPinning(t *testing.T) {
	m := testMeter()
	base := func(prov, model, extra string) RequestInfo {
		t.Helper()
		path, body := requestFor(prov, model, extra)
		info, err := inspect(t, m, prov, "POST", path, body)
		if err != nil {
			t.Fatal(err)
		}
		return info
	}
	// gpt-6-astra: fast 200, ultrafast 600, flex 50.
	if got := base("openai", "gpt-6-astra", "").MaxOutputTokens; got != 30_000 {
		t.Fatalf("unset tier not at max (600%%): %d", got)
	}
	if got := base("openai", "gpt-6-astra", `"service_tier":"auto",`).MaxOutputTokens; got != 30_000 {
		t.Fatalf("auto not at max: %d", got)
	}
	for _, pin := range []string{"default", "flex"} {
		if got := base("openai", "gpt-6-astra", `"service_tier":"`+pin+`",`).MaxOutputTokens; got != 5000 {
			t.Fatalf("pinned %s scaled: %d", pin, got)
		}
	}
	if got := base("openai", "gpt-6-astra", `"service_tier":"priority",`).MaxOutputTokens; got != 10_000 {
		t.Fatalf("priority: %d", got)
	}
	// Gemini: unset may be served at priority (reported by header).
	if got := base("gemini", "gemini-2.5-pro", "").MaxOutputTokens; got != 9000 {
		t.Fatalf("gemini unset tier: %d", got)
	}
	if got := base("gemini", "gemini-2.5-pro", `"serviceTier":"standard",`).MaxOutputTokens; got != 5000 {
		t.Fatalf("gemini pinned standard: %d", got)
	}
	// Anthropic: fast mode is opt-in only.
	if got := base("anthropic", "claude-opus-5-5", "").MaxOutputTokens; got != 5000 {
		t.Fatalf("anthropic unset speed scaled: %d", got)
	}
	if got := base("anthropic", "claude-opus-5-5", `"speed":"fast",`).MaxOutputTokens; got != 10_000 {
		t.Fatalf("anthropic fast: %d", got)
	}
}

// ---- Finding 3: per-call tool fees ----

func estimateBody(t *testing.T, m *Meter, prov, path, body string) (money.Micros, bool) {
	t.Helper()
	info, err := inspect(t, m, prov, "POST", path, body)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	return m.Estimate(prov, info)
}

func TestToolFeesInEstimate(t *testing.T) {
	m := testMeter()
	const (
		anth   = "/v1/messages"
		resp   = "/v1/responses"
		chat   = "/v1/chat/completions"
		gem25  = "/v1beta/models/gemini-2.5-pro:generateContent"
		gem3   = "/v1beta/models/gemini-3.1-pro-preview:generateContent"
		gem3fl = "/v1beta/models/gemini-3-flash-preview:generateContent"
	)
	a := func(tools string) string {
		return `{"model":"claude-sonnet-4-5","max_tokens":1000,"tools":[` + tools + `],"messages":[]}`
	}
	o := func(tools, extra string) string {
		return `{"model":"gpt-5.4","service_tier":"default","max_output_tokens":1000,` + extra + `"tools":[` + tools + `],"input":"x"}`
	}
	g := func(tools, extra string) string {
		return `{"serviceTier":"standard",` + extra + `"tools":[` + tools + `],"contents":[],"generationConfig":{"maxOutputTokens":1000}}`
	}
	// Each priced case is compared with a free server-side twin (same
	// context-window input) to isolate the fee.
	priced := []struct {
		name, prov, path, body, twin string
		fee                          money.Micros
	}{
		{"anthropic web search max_uses", "anthropic", anth, a(`{"type":"web_search_20250305","name":"web_search","max_uses":3}`), a(`{"type":"web_fetch_20250910","name":"web_fetch"}`), 3 * 10_000},
		{"anthropic two search tools", "anthropic", anth, a(`{"type":"web_search_20250305","name":"a","max_uses":2},{"type":"web_search_20260209","name":"b","max_uses":5}`), a(`{"type":"web_fetch_20250910","name":"web_fetch"}`), 7 * 10_000},
		{"openai web+file search capped", "openai", resp, o(`{"type":"web_search"},{"type":"file_search","vector_store_ids":["vs_1"]}`, `"max_tool_calls":5,`), o(`{"type":"mcp","server_label":"x"}`, ""), 5 * 25_000},
		{"openai file search capped", "openai", resp, o(`{"type":"file_search","vector_store_ids":["vs_1"]}`, `"max_tool_calls":4,`), o(`{"type":"mcp","server_label":"x"}`, ""), 4 * 2_500},
		{"gemini 2.5 search per prompt", "gemini", gem25, g(`{"googleSearch":{}}`, ""), g(`{"urlContext":{}}`, ""), 35_000},
		{"gemini 2.5 maps per prompt", "gemini", gem25, g(`{"google_maps":{}}`, ""), g(`{"urlContext":{}}`, ""), 25_000},
		{"gemini 2.5 cached content may hold tools", "gemini", gem25, g(``, `"cachedContent":"cachedContents/x",`), g(`{"urlContext":{}}`, ""), 35_000 + 25_000},
		{"openai local shell is free", "openai", resp, o(`{"type":"shell"}`, ""), o(``, ""), 0},
		{"gemini 3 url context and code execution are free", "gemini", gem3, g(`{"urlContext":{}},{"codeExecution":{}}`, ""), g(`{"urlContext":{}}`, ""), 0},
	}
	for _, c := range priced {
		t.Run(c.name, func(t *testing.T) {
			est, ok := estimateBody(t, m, c.prov, c.path, c.body)
			if !ok {
				t.Fatal("unpriced")
			}
			twin, ok := estimateBody(t, m, c.prov, c.path, c.twin)
			if !ok {
				t.Fatal("twin unpriced")
			}
			if est-twin < c.fee {
				t.Fatalf("fee not covered: %v - %v < %v", est, twin, c.fee)
			}
		})
	}
	unpriced := []struct{ name, prov, path, body string }{
		{"anthropic web search without max_uses", "anthropic", anth, a(`{"type":"web_search_20250305","name":"web_search"}`)},
		{"anthropic code execution", "anthropic", anth, a(`{"type":"code_execution_20250825","name":"code_execution"}`)},
		{"openai web search without max_tool_calls", "openai", resp, o(`{"type":"web_search"}`, "")},
		{"openai file search without max_tool_calls", "openai", resp, o(`{"type":"file_search","vector_store_ids":["vs_1"]}`, "")},
		{"openai code interpreter", "openai", resp, o(`{"type":"code_interpreter","container":{"type":"auto"}}`, `"max_tool_calls":1,`)},
		{"openai image generation", "openai", resp, o(`{"type":"image_generation"}`, `"max_tool_calls":1,`)},
		{"openai hosted shell", "openai", resp, o(`{"type":"shell","environment":{"type":"container_auto"}}`, "")},
		{"openai stored prompt", "openai", resp, o(``, `"prompt":{"id":"pmpt_1"},`)},
		{"openai chat web_search_options", "openai", chat, `{"model":"gpt-5","service_tier":"default","max_tokens":10,"web_search_options":{},"messages":[]}`},
		{"gemini 3 search per query", "gemini", gem3, g(`{"googleSearch":{}}`, "")},
		{"gemini 3 maps per query", "gemini", gem3fl, g(`{"googleMaps":{}}`, "")},
		{"gemini 3 cached content", "gemini", gem3, g(``, `"cachedContent":"cachedContents/x",`)},
	}
	for _, c := range unpriced {
		t.Run(c.name, func(t *testing.T) {
			if est, ok := estimateBody(t, m, c.prov, c.path, c.body); ok {
				t.Fatalf("priced at %v", est)
			}
		})
	}
	// A malformed tools list is a malformed request.
	if _, err := inspect(t, m, "anthropic", "POST", anth, `{"model":"claude-sonnet-4-5","max_tokens":1,"tools":{"type":"web_search"},"messages":[]}`); err == nil {
		t.Fatal("tools object accepted")
	}
	if _, err := inspect(t, m, "anthropic", "POST", anth, a(`{"type":"web_search_20250305","max_uses":1,"max_uses":99}`)); err == nil {
		t.Fatal("duplicate max_uses accepted")
	}
}

func TestToolFeesInCost(t *testing.T) {
	m := testMeter()
	_, anth := endpointFor(t, "anthropic", "POST", "/v1/messages")
	_, resp := endpointFor(t, "openai", "POST", "/v1/responses")
	_, gem := endpointFor(t, "gemini", "POST", "/v1beta/models/gemini-2.5-pro:generateContent")
	anthMsg := func(stu string) string {
		return `{"type":"message","model":"claude-sonnet-4-5","usage":{"input_tokens":1000,"output_tokens":100,"server_tool_use":` + stu + `}}`
	}
	oaiResp := func(items string) string {
		return `{"object":"response","model":"gpt-5.4","service_tier":"default","output":[` + items + `],"usage":{"input_tokens":1000,"output_tokens":100}}`
	}
	gemResp := func(model, gm string) string {
		return `{"candidates":[{"index":0,"finishReason":"STOP","groundingMetadata":` + gm + `}],"usageMetadata":{"promptTokenCount":1000,"candidatesTokenCount":100,"promptTokensDetails":[{"modality":"TEXT","tokenCount":1000}]},"modelVersion":"` + model + `"}`
	}
	sonnet := money.Micros(3_000 + 1_500) // 1000*$3 + 100*$15
	gpt54 := money.Micros(2_500 + 1_500)  // 1000*$2.50 + 100*$15
	g25 := money.Micros(1_250 + 1_000)    // 1000*$1.25 + 100*$10
	g31 := money.Micros(2_000 + 1_200)    // 1000*$2 + 100*$12
	g25maps := `{"groundingChunks":[{"maps":{"uri":"https://maps.google.com/x","title":"Cafe"}}]}`
	cases := []struct {
		name string
		ep   provider.Endpoint
		prov string
		body string
		want money.Micros
		ok   bool
	}{
		{"anthropic web search", anth, "anthropic", anthMsg(`{"web_search_requests":2}`), sonnet + 20_000, true},
		{"anthropic web fetch is free", anth, "anthropic", anthMsg(`{"web_search_requests":0,"web_fetch_requests":3}`), sonnet, true},
		{"anthropic code execution unpriced", anth, "anthropic", anthMsg(`{"web_search_requests":0,"code_execution_requests":1}`), 0, false},
		{"anthropic unknown server tool unpriced", anth, "anthropic", anthMsg(`{"teleport_requests":1}`), 0, false},
		{"anthropic unknown server tool unused", anth, "anthropic", anthMsg(`{"teleport_requests":0}`), sonnet, true},
		{"anthropic bad counter", anth, "anthropic", anthMsg(`{"code_execution_requests":"1"}`), 0, false},
		{"openai file and web search", resp, "openai", oaiResp(`{"type":"file_search_call"},{"type":"file_search_call"},{"type":"web_search_call"},{"type":"message"}`), gpt54 + 2*2_500 + 25_000, true},
		{"openai code interpreter unpriced", resp, "openai", oaiResp(`{"type":"code_interpreter_call"}`), 0, false},
		{"openai image generation unpriced", resp, "openai", oaiResp(`{"type":"image_generation_call"}`), 0, false},
		{"openai streamed image generation unpriced", resp, "openai", "data: {\"type\":\"response.completed\",\"response\":" + oaiResp(`{"type":"image_generation_call"}`) + "}\n\n", 0, false},
		{"gemini 2.5 search per prompt", gem, "gemini", gemResp("gemini-2.5-pro", `{"webSearchQueries":["a","b","c"],"searchEntryPoint":{"renderedContent":"x"}}`), g25 + 35_000, true},
		{"gemini 2.5 maps per prompt", gem, "gemini", gemResp("gemini-2.5-pro", g25maps), g25 + 25_000, true},
		{"gemini 2.5 url context only", gem, "gemini", gemResp("gemini-2.5-pro", `{"groundingChunks":[{"web":{"uri":"https://e"}}]}`), g25, true},
		{"gemini 3 search per query", gem, "gemini", gemResp("gemini-3.1-pro-preview", `{"webSearchQueries":["a","b",""],"searchEntryPoint":{"renderedContent":"x"}}`), g31 + 2*14_000, true},
		{"gemini 3 search without query count", gem, "gemini", gemResp("gemini-3.1-pro-preview", `{"searchEntryPoint":{"renderedContent":"x"}}`), 0, false},
		{"gemini 3 maps unpriced", gem, "gemini", gemResp("gemini-3.1-pro-preview", g25maps), 0, false},
		{"gemini 3 maps widget token unpriced", gem, "gemini", gemResp("gemini-3.1-pro-preview", `{"googleMapsWidgetContextToken":"tok"}`), 0, false},
		{"gemini embedding model has no grounding fee", gem, "gemini", gemResp("gemini-embedding-2", `{"webSearchQueries":["a"]}`), 0, false},
		{"gemini unknown model grounded", gem, "gemini", gemResp("gemini-9-ultra", `{"webSearchQueries":["a"]}`), 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, chunk := range []int{0, 1, 7} {
				u, ok := parseAll(m, c.prov, c.ep, false, []byte(c.body), chunk)
				if ok != c.ok {
					t.Fatalf("chunk %d: ok=%v want %v (%+v)", chunk, ok, c.ok, u)
				}
				if !ok {
					continue
				}
				if got, _ := m.Cost(c.prov, u); got != c.want {
					t.Fatalf("chunk %d: cost %v want %v", chunk, got, c.want)
				}
			}
		})
	}
}

// Streamed Gemini chunks repeat grounding metadata; queries are not summed.
func TestGeminiStreamGroundingNotDoubleCounted(t *testing.T) {
	m := testMeter()
	_, ep := endpointFor(t, "gemini", "POST", "/v1beta/models/gemini-3.1-pro-preview:streamGenerateContent")
	gm := `"groundingMetadata":{"webSearchQueries":["a","b"]}`
	body := "data: {\"candidates\":[{\"index\":0," + gm + "}],\"modelVersion\":\"gemini-3.1-pro-preview\"}\n\n" +
		"data: {\"candidates\":[{\"index\":0,\"finishReason\":\"STOP\"," + gm + "}],\"usageMetadata\":{\"promptTokenCount\":1000,\"candidatesTokenCount\":100},\"modelVersion\":\"gemini-3.1-pro-preview\"}\n\n"
	u, ok := parseAll(m, "gemini", ep, true, []byte(body), 0)
	if !ok {
		t.Fatal("not ok")
	}
	if got, _ := m.Cost("gemini", u); got != 3_200+2*14_000 {
		t.Fatalf("cost %v", got)
	}
}

// Estimate bounds Cost when the response uses every call the request allows.
func TestEstimateBoundsToolFees(t *testing.T) {
	m := testMeter()
	cases := []struct {
		prov, path, req, resp string
	}{
		{"anthropic", "/v1/messages",
			`{"model":"claude-opus-5-5","max_tokens":100,"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":4}],"messages":[]}`,
			`{"type":"message","model":"claude-opus-5-5","usage":{"input_tokens":1000000,"output_tokens":100,"inference_geo":"us","server_tool_use":{"web_search_requests":4}}}`},
		{"openai", "/v1/responses",
			`{"model":"gpt-6-astra","max_output_tokens":100,"max_tool_calls":3,"tools":[{"type":"web_search"},{"type":"file_search","vector_store_ids":["v"]}],"input":"x"}`,
			`{"object":"response","model":"gpt-6-astra","service_tier":"ultrafast","output":[{"type":"web_search_call"},{"type":"web_search_call"},{"type":"web_search_call"}],"usage":{"input_tokens":1050000,"input_tokens_details":{"cache_write_tokens":1050000},"output_tokens":100}}`},
		{"gemini", "/v1beta/models/gemini-2.5-flash:generateContent",
			`{"tools":[{"googleSearch":{}},{"googleMaps":{}}],"contents":[],"generationConfig":{"maxOutputTokens":100,"candidateCount":2}}`,
			`{"candidates":[{"index":0,"finishReason":"STOP","groundingMetadata":{"webSearchQueries":["q"],"groundingChunks":[{"maps":{"uri":"u"}}]}},{"index":1,"finishReason":"STOP","groundingMetadata":{"webSearchQueries":["q"],"groundingChunks":[{"maps":{"uri":"u"}}]}}],"usageMetadata":{"promptTokenCount":1048576,"candidatesTokenCount":200},"modelVersion":"gemini-2.5-flash"}`},
	}
	for _, c := range cases {
		t.Run(c.prov, func(t *testing.T) {
			p, ep := endpointFor(t, c.prov, "POST", c.path)
			info, err := m.Inspect(p, ep, c.path, []byte(c.req))
			if err != nil {
				t.Fatal(err)
			}
			est, ok := m.Estimate(c.prov, info)
			if !ok {
				t.Fatal("unpriced")
			}
			u, ok := parseAll(m, c.prov, ep, false, []byte(c.resp), 0)
			if !ok {
				t.Fatal("usage not ok")
			}
			cost, ok := m.Cost(c.prov, u)
			if !ok || cost > est {
				t.Fatalf("cost %v > estimate %v", cost, est)
			}
		})
	}
}

func TestModelFeesParsing(t *testing.T) {
	p, err := LoadPricing(writeTemp(t, `{"version":1,"providers":{"gemini":{"fees":{"google_search_prompt":"$1"},"models":{
		"m1":{"input":"$1","output":"$1","fees":{"google_search_query":"$0.02"}},
		"m2":{"input":"$1","output":"$1"}}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	pr, _ := p.Lookup("gemini", "m1")
	f := p.feesFor("gemini", pr)
	if f.GoogleSearchQuery != 20_000 || f.GoogleSearchPrompt != 1_000_000 {
		t.Fatalf("m1 fees %+v", f)
	}
	pr, _ = p.Lookup("gemini", "m2")
	if f := p.feesFor("gemini", pr); f.GoogleSearchPrompt != 1_000_000 || f.GoogleSearchQuery != 0 {
		t.Fatalf("m2 fees %+v", f)
	}
	for name, body := range map[string]string{
		"unknown model fee":  `{"version":1,"providers":{"openai":{"models":{"x":{"input":"$1","output":"$1","fees":{"tip":"$1"}}}}}}`,
		"negative model fee": `{"version":1,"providers":{"openai":{"models":{"x":{"input":"$1","output":"$1","fees":{"file_search_call":"-$1"}}}}}}`,
		"bad provider fee":   `{"version":1,"providers":{"openai":{"fees":{"file_search_call":"lots"},"models":{}}}}`,
	} {
		if _, err := LoadPricing(writeTemp(t, body)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// An override can zero a provider fee.
	p, err = LoadPricing(writeTemp(t, `{"version":1,"providers":{"openai":{"fees":{"web_search_call":"$0"}}}}`))
	if err != nil || p.fees("openai").WebSearchCall != 0 || p.fees("openai").FileSearchCall != 2_500 {
		t.Fatalf("override fees: %+v %v", p.fees("openai"), err)
	}
}
