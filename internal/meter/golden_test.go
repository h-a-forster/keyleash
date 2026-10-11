package meter

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
)

type golden struct {
	name      string
	provider  string
	method    string
	path      string
	req, resp string
	stream    bool
	want      Usage
	wantCost  money.Micros
	// unpricedEstimate is true where the provider has no table (OpenRouter).
	unpricedEstimate bool
}

var goldens = []golden{
	{
		name: "anthropic non-stream opus 5.5 with 5m cache write", provider: "anthropic",
		method: "POST", path: "/v1/messages",
		req: "req_anthropic_opus.json", resp: "resp_anthropic_opus.json",
		want: Usage{Model: "claude-opus-5-5", InputTokens: 40, OutputTokens: 300, CacheWriteTokens: 60, CacheReadTokens: 50,
			ProviderCostMicros: 6470},
		// 40*$4 + 60*$5 (5m write) + 50*$0.20 + 300*$20 per MTok
		wantCost: 6470,
	},
	{
		name: "anthropic stream sonnet 4.5 snapshot with web search", provider: "anthropic",
		method: "POST", path: "/v1/messages", stream: true,
		req: "req_anthropic_sonnet_stream.json", resp: "resp_anthropic_sonnet_stream.sse",
		want: Usage{Model: "claude-sonnet-4-5-20250929", InputTokens: 25, OutputTokens: 812, ProviderCostMicros: 22255},
		// 25*$3 + 812*$15 per MTok + 1 search * $0.01
		wantCost: 22255,
	},
	{
		name: "openai chat stream with cached prompt", provider: "openai",
		method: "POST", path: "/v1/chat/completions", stream: true,
		req: "req_openai_chat_stream.json", resp: "resp_openai_chat_stream.sse",
		want: Usage{Model: "gpt-5.4-mini-2026-03-17", InputTokens: 56, OutputTokens: 900, CacheReadTokens: 64, ReasoningTokens: 300},
		// 56*$0.75 + ceil(64*$0.075) + 900*$4.50 per MTok
		wantCost: 4097,
	},
	{
		name: "openai chat priority tier", provider: "openai",
		method: "POST", path: "/v1/chat/completions",
		req: "req_openai_chat_priority.json", resp: "resp_openai_chat_priority.json",
		want: Usage{Model: "gpt-4o-mini-2024-07-18", InputTokens: 30, OutputTokens: 9, ProviderCostMicros: 19},
		// (ceil(30*$0.15) + ceil(9*$0.60)) * 167%
		wantCost: 19,
	},
	{
		name: "openai responses stream with cache write and web search", provider: "openai",
		method: "POST", path: "/v1/responses", stream: true,
		req: "req_openai_responses_stream.json", resp: "resp_openai_responses_stream.sse",
		want: Usage{Model: "gpt-6.1-sol", InputTokens: 50, OutputTokens: 700, CacheReadTokens: 100, CacheWriteTokens: 150,
			ReasoningTokens: 500, ProviderCostMicros: 32485},
		// 50*$2 + 100*$0.10 + 150*$2.50 + 700*$10 per MTok + 1 call * $0.025
		wantCost: 32485,
	},
	{
		name: "openai embeddings rounds up", provider: "openai",
		method: "POST", path: "/v1/embeddings",
		req: "req_openai_embeddings.json", resp: "resp_openai_embeddings.json",
		want:     Usage{Model: "text-embedding-3-small", InputTokens: 9},
		wantCost: 1, // 9 * $0.02/MTok = 0.18 micro -> 1
	},
	{
		name: "gemini sse with audio modality and thoughts", provider: "gemini",
		method: "POST", path: "/v1beta/models/gemini-2.5-flash:streamGenerateContent", stream: true,
		req: "req_gemini_flash_stream.json", resp: "resp_gemini_flash_stream.sse",
		want: Usage{Model: "gemini-2.5-flash", InputTokens: 50, OutputTokens: 320, ReasoningTokens: 120, ProviderCostMicros: 822},
		// 40*$0.30 + 10*$1 (audio) + (200+120)*$2.50 per MTok
		wantCost: 822,
	},
	{
		name: "gemini streamed json array", provider: "gemini",
		method: "POST", path: "/v1beta/models/gemini-3.1-pro-preview:streamGenerateContent", stream: true,
		req: "req_gemini_pro.json", resp: "resp_gemini_pro_array.json",
		want:     Usage{Model: "gemini-3.1-pro-preview", InputTokens: 110, OutputTokens: 150, ReasoningTokens: 50},
		wantCost: 2020, // 110*$2 + 150*$12 per MTok
	},
	{
		name: "gemini non-stream", provider: "gemini",
		method: "POST", path: "/v1beta/models/gemini-3.1-pro-preview:generateContent",
		req: "req_gemini_pro.json", resp: "resp_gemini_pro.json",
		want:     Usage{Model: "gemini-3.1-pro-preview", InputTokens: 110, OutputTokens: 150, ReasoningTokens: 50},
		wantCost: 2020,
	},
	{
		name: "openrouter reports cost", provider: "openrouter",
		method: "POST", path: "/v1/chat/completions", stream: true,
		req: "req_openrouter_chat_stream.json", resp: "resp_openrouter_chat_stream.sse",
		want:             Usage{Model: "anthropic/claude-sonnet-4.5", InputTokens: 24, OutputTokens: 8, ProviderCostMicros: 124},
		wantCost:         124, // $0.0001234 -> 123.4 micros, rounded up
		unpricedEstimate: true,
	},
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testMeter() *Meter {
	return &Meter{Pricing: DefaultPricing(), AssumeMaxOutputTokens: 4096, AddStreamUsage: true}
}

func endpointFor(t *testing.T, provName, method, path string) (*provider.Provider, provider.Endpoint) {
	t.Helper()
	p, ok := provider.Get(provName)
	if !ok {
		t.Fatalf("no provider %q", provName)
	}
	ep, ok := p.Match(method, path)
	if !ok {
		t.Fatalf("%s %s not allowed for %s", method, path, provName)
	}
	return p, ep
}

func parseAll(m *Meter, prov string, ep provider.Endpoint, stream bool, body []byte, chunk int) (Usage, bool) {
	up := m.NewProviderUsageParser(prov, ep, stream)
	if chunk <= 0 {
		chunk = len(body)
	}
	for i := 0; i < len(body); i += chunk {
		end := min(i+chunk, len(body))
		n, err := up.Write(body[i:end])
		if err != nil || n != end-i {
			panic("usage parser Write must never fail")
		}
	}
	return up.Final()
}

func TestGoldenFixtures(t *testing.T) {
	m := testMeter()
	for _, g := range goldens {
		t.Run(g.name, func(t *testing.T) {
			p, ep := endpointFor(t, g.provider, g.method, g.path)
			req := readFixture(t, g.req)
			info, err := m.Inspect(p, ep, g.path, req)
			if err != nil {
				t.Fatalf("Inspect: %v", err)
			}
			if info.Stream != g.stream {
				t.Errorf("Stream = %v, want %v", info.Stream, g.stream)
			}
			resp := readFixture(t, g.resp)
			for _, chunk := range []int{0, 1, 2, 7, 64} {
				u, ok := parseAll(m, g.provider, ep, g.stream, resp, chunk)
				if !ok {
					t.Fatalf("chunk %d: Final not ok", chunk)
				}
				if u != g.want {
					t.Fatalf("chunk %d: usage\n got %+v\nwant %+v", chunk, u, g.want)
				}
			}
			u, _ := parseAll(m, g.provider, ep, g.stream, resp, 0)
			cost, ok := m.Cost(g.provider, u)
			if !ok || cost != g.wantCost {
				t.Fatalf("Cost = %v,%v want %v", cost, ok, g.wantCost)
			}
			est, priced := m.Estimate(g.provider, info)
			if g.unpricedEstimate {
				if priced {
					t.Fatalf("Estimate priced for %s", g.provider)
				}
				return
			}
			if !priced {
				t.Fatalf("Estimate unpriced for %q", info.Model)
			}
			if est < cost {
				t.Fatalf("Estimate %v < Cost %v: worst case does not bound actual", est, cost)
			}
		})
	}
}

// Every truncation of a stream before its terminal usage must yield ok=false
// (the caller then charges the reservation) and never panic.
func TestTruncatedStreamsNotOK(t *testing.T) {
	m := testMeter()
	cases := []struct {
		provider, path, resp string
		// cutoff is a marker; any prefix ending before it must be !ok.
		marker string
	}{
		{"anthropic", "/v1/messages", "resp_anthropic_sonnet_stream.sse", `{"type":"message_stop"}`},
		{"openai", "/v1/chat/completions", "resp_openai_chat_stream.sse", `"usage":{"prompt_tokens"`},
		{"openai", "/v1/responses", "resp_openai_responses_stream.sse", `"type":"response.completed"`},
		{"gemini", "/v1beta/models/gemini-2.5-flash:streamGenerateContent", "resp_gemini_flash_stream.sse", `"finishReason": "STOP"`},
		{"gemini", "/v1beta/models/gemini-3.1-pro-preview:streamGenerateContent", "resp_gemini_pro_array.json", "\n]"},
		{"openrouter", "/v1/chat/completions", "resp_openrouter_chat_stream.sse", `"cost":0.0001234`},
	}
	for _, c := range cases {
		t.Run(c.resp, func(t *testing.T) {
			_, ep := endpointFor(t, c.provider, "POST", c.path)
			resp := readFixture(t, c.resp)
			idx := bytes.Index(resp, []byte(c.marker))
			if idx < 0 {
				t.Fatalf("marker %q not in fixture", c.marker)
			}
			// The event carrying the marker ends at the next blank line; any
			// cut before that point loses it.
			for cut := 0; cut < idx+len(c.marker); cut++ {
				if _, ok := parseAll(m, c.provider, ep, true, resp[:cut], 0); ok {
					t.Fatalf("cut at %d/%d: ok=true for truncated stream", cut, len(resp))
				}
			}
		})
	}
}

func TestMalformedResponsesNotOK(t *testing.T) {
	m := testMeter()
	_, anth := endpointFor(t, "anthropic", "POST", "/v1/messages")
	_, chat := endpointFor(t, "openai", "POST", "/v1/chat/completions")
	_, gem := endpointFor(t, "gemini", "POST", "/v1beta/models/gemini-2.5-pro:generateContent")
	_, emb := endpointFor(t, "gemini", "POST", "/v1beta/models/gemini-embedding-2:embedContent")
	cases := []struct {
		name string
		ep   provider.Endpoint
		body string
	}{
		{"empty", anth, ""},
		{"whitespace", anth, "  \n "},
		{"truncated json", anth, `{"type":"message","usage":{"input_tokens":5`},
		{"json without usage", anth, `{"type":"message","model":"claude-opus-5-5"}`},
		{"error body", anth, `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`},
		{"negative tokens", anth, `{"type":"message","model":"claude-opus-5-5","usage":{"input_tokens":-5,"output_tokens":1}}`},
		{"float tokens", chat, `{"model":"gpt-5","usage":{"prompt_tokens":1.5,"completion_tokens":1}}`},
		{"trailing garbage", chat, `{"model":"gpt-5","usage":{"prompt_tokens":1,"completion_tokens":1}} trailing`},
		{"sse error event", anth, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-opus-5-5\",\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\nevent: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"},
		{"sse garbage data", chat, "data: {not json}\n\ndata: {\"model\":\"gpt-5\",\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n"},
		{"chat stream without usage", chat, "data: {\"model\":\"gpt-5\",\"choices\":[],\"usage\":null}\n\ndata: [DONE]\n\n"},
		{"gemini error element", gem, `[{"usageMetadata":{"promptTokenCount":1,"candidatesTokenCount":1},"candidates":[{"finishReason":"STOP"}]},{"error":{"code":500}}]`},
		{"gemini array unbalanced", gem, `[{"usageMetadata":{"promptTokenCount":1}}]]`},
		{"gemini embed without usage", emb, `{"embedding":{"values":[0.1,0.2]}}`},
		{"binary", chat, "\x00\x01\x02\xff"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, chunk := range []int{0, 1, 3} {
				if u, ok := parseAll(m, "", c.ep, true, []byte(c.body), chunk); ok {
					t.Fatalf("chunk %d: ok=true, usage %+v", chunk, u)
				}
			}
		})
	}
}

func TestOversizedInputsNotOK(t *testing.T) {
	m := testMeter()
	_, chat := endpointFor(t, "openai", "POST", "/v1/chat/completions")
	// One SSE line beyond the cap.
	huge := append([]byte("data: "), bytes.Repeat([]byte("x"), maxEventSize+10)...)
	huge = append(huge, "\n\ndata: {\"model\":\"gpt-5\",\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":1}}\n\n"...)
	if _, ok := parseAll(m, "openai", chat, true, huge, 1<<16); ok {
		t.Fatal("oversized SSE line: ok=true")
	}
	// A non-streamed body beyond the cap.
	body := append([]byte(`{"model":"gpt-5","pad":"`), bytes.Repeat([]byte("y"), maxBufferedBody)...)
	body = append(body, `","usage":{"prompt_tokens":1,"completion_tokens":1}}`...)
	if _, ok := parseAll(m, "openai", chat, false, body, 1<<16); ok {
		t.Fatal("oversized JSON body: ok=true")
	}
}

func TestSSELineEndings(t *testing.T) {
	m := testMeter()
	_, ep := endpointFor(t, "anthropic", "POST", "/v1/messages")
	lf := readFixture(t, "resp_anthropic_sonnet_stream.sse")
	lf = bytes.ReplaceAll(lf, []byte("\r\n"), []byte("\n"))
	want, ok := parseAll(m, "anthropic", ep, true, lf, 0)
	if !ok {
		t.Fatal("LF not ok")
	}
	for name, body := range map[string][]byte{
		"CRLF": bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n")),
		"CR":   bytes.ReplaceAll(lf, []byte("\n"), []byte("\r")),
		"BOM":  append([]byte("\xef\xbb\xbf"), lf...),
	} {
		for _, chunk := range []int{0, 1, 5} {
			got, ok := parseAll(m, "anthropic", ep, true, body, chunk)
			if !ok || got != want {
				t.Fatalf("%s chunk %d: got %+v ok=%v", name, chunk, got, ok)
			}
		}
	}
}

func TestGeminiHeaderTier(t *testing.T) {
	m := testMeter()
	_, ep := endpointFor(t, "gemini", "POST", "/v1beta/models/gemini-3.1-pro-preview:generateContent")
	up := m.NewUsageParser(ep, false)
	ho, ok := up.(HeaderObserver)
	if !ok {
		t.Fatal("parser does not implement HeaderObserver")
	}
	h := make(map[string][]string)
	h["X-Gemini-Service-Tier"] = []string{"priority"}
	ho.ObserveResponseHeader(h)
	_, _ = up.Write(readFixture(t, "resp_gemini_pro.json"))
	u, ok := up.Final()
	// 2020 micros standard * 180% priority.
	if !ok || u.ProviderCostMicros != 3636 {
		t.Fatalf("priority header not priced: %+v %v", u, ok)
	}
}

func TestStandardTierWithoutModelStillOK(t *testing.T) {
	m := testMeter()
	_, ep := endpointFor(t, "openai", "POST", "/v1/chat/completions")
	body := "data: {\"service_tier\":\"default\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\n"
	u, ok := parseAll(m, "openai", ep, true, []byte(body), 0)
	if !ok || u.InputTokens != 3 || u.OutputTokens != 4 {
		t.Fatalf("got %+v %v", u, ok)
	}
	// A premium tier without a model cannot be priced: fail closed.
	body = "data: {\"service_tier\":\"priority\",\"choices\":[],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":4}}\n\n"
	if _, ok := parseAll(m, "openai", ep, true, []byte(body), 0); ok {
		t.Fatal("premium tier without model reported ok")
	}
}
