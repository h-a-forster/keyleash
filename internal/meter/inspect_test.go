package meter

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/h-a-forster/keyleash/internal/provider"
)

func inspect(t *testing.T, m *Meter, prov, method, path, body string) (RequestInfo, error) {
	t.Helper()
	p, ep := endpointFor(t, prov, method, path)
	return m.Inspect(p, ep, path, []byte(body))
}

func TestInspectFields(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing()}
	cases := []struct {
		name, prov, path, body string
		want                   RequestInfo
	}{
		{
			name: "anthropic", prov: "anthropic", path: "/v1/messages",
			body: `{"model":"claude-opus-4-6","max_tokens":2000,"stream":true,"thinking":{"type":"enabled","budget_tokens":1500},"messages":[]}`,
			want: RequestInfo{Kind: provider.KindAnthropicMessages, Model: "claude-opus-4-6", Stream: true, MaxOutputTokens: 2000, ThinkingTokens: 1500},
		},
		{
			name: "anthropic null fields", prov: "anthropic", path: "/v1/messages",
			body: `{"model":"claude-opus-4-6","max_tokens":10,"stream":null,"thinking":null,"messages":[]}`,
			want: RequestInfo{Kind: provider.KindAnthropicMessages, Model: "claude-opus-4-6", MaxOutputTokens: 10},
		},
		{
			name: "openai chat takes the larger limit", prov: "openai", path: "/v1/chat/completions",
			body: `{"model":"gpt-5","max_tokens":10,"max_completion_tokens":300,"messages":[]}`,
			want: RequestInfo{Kind: provider.KindOpenAIChat, Model: "gpt-5", MaxOutputTokens: 300},
		},
		{
			name: "openai responses", prov: "openai", path: "/v1/responses",
			body: `{"model":"gpt-5.4","max_output_tokens":777,"stream":false,"input":"hi"}`,
			want: RequestInfo{Kind: provider.KindOpenAIResponses, Model: "gpt-5.4", MaxOutputTokens: 777},
		},
		{
			name: "openai embeddings", prov: "openai", path: "/v1/embeddings",
			body: `{"model":"text-embedding-3-large","input":"hello"}`,
			want: RequestInfo{Kind: provider.KindOpenAIEmbeddings, Model: "text-embedding-3-large"},
		},
		{
			name: "gemini snake case and dynamic thinking", prov: "gemini", path: "/v1beta/models/gemini-2.5-pro:generateContent",
			body: `{"contents":[],"generation_config":{"max_output_tokens":64,"thinking_config":{"thinking_budget":-1}}}`,
			want: RequestInfo{Kind: provider.KindGeminiGenerate, Model: "gemini-2.5-pro", MaxOutputTokens: 64},
		},
		{
			name: "gemini stream from path", prov: "gemini", path: "/v1beta/models/gemini-2.5-pro:streamGenerateContent",
			body: `{"contents":[],"generationConfig":{"maxOutputTokens":64,"thinkingConfig":{"thinkingBudget":32}}}`,
			want: RequestInfo{Kind: provider.KindGeminiGenerate, Model: "gemini-2.5-pro", Stream: true, MaxOutputTokens: 64, ThinkingTokens: 32},
		},
		{
			name: "gemini embed", prov: "gemini", path: "/v1beta/models/gemini-embedding-2:embedContent",
			body: `{"content":{"parts":[{"text":"hi"}]}}`,
			want: RequestInfo{Kind: provider.KindGeminiEmbed, Model: "gemini-embedding-2"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := inspect(t, m, c.prov, "POST", c.path, c.body)
			if err != nil {
				t.Fatal(err)
			}
			c.want.InputTokensEstimate = int64((len(c.body) + 2) / 3)
			if got != c.want {
				t.Fatalf("\n got %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestInspectInputEstimateCeil(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing()}
	for _, pad := range []int{0, 1, 2, 3, 4} {
		body := `{"model":"gpt-5","messages":[],"x":"` + strings.Repeat("a", pad) + `"}`
		info, err := inspect(t, m, "openai", "POST", "/v1/chat/completions", body)
		if err != nil {
			t.Fatal(err)
		}
		if want := int64((len(body) + 2) / 3); info.InputTokensEstimate != want || info.InputTokensEstimate*3 < int64(len(body)) {
			t.Fatalf("len %d: estimate %d", len(body), info.InputTokensEstimate)
		}
	}
}

func TestInspectFreeEndpoints(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing()}
	for _, c := range []struct{ prov, method, path string }{
		{"anthropic", "GET", "/v1/models"},
		{"anthropic", "POST", "/v1/messages/count_tokens"},
		{"openai", "GET", "/v1/models/gpt-5"},
		{"gemini", "POST", "/v1beta/models/gemini-2.5-pro:countTokens"},
	} {
		info, err := inspect(t, m, c.prov, c.method, c.path, "not json at all")
		if err != nil || info.Kind != provider.KindFree || info.Model != "" {
			t.Fatalf("%s %s: %+v %v", c.method, c.path, info, err)
		}
	}
}

func TestInspectRejectsMalformed(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing()}
	cases := []struct{ name, prov, path, body string }{
		{"empty", "openai", "/v1/chat/completions", ``},
		{"array", "openai", "/v1/chat/completions", `[{"model":"gpt-5"}]`},
		{"truncated", "openai", "/v1/chat/completions", `{"model":"gpt-5"`},
		{"trailing", "openai", "/v1/chat/completions", `{"model":"gpt-5"} {"model":"x"}`},
		{"duplicate max_tokens", "anthropic", "/v1/messages", `{"model":"claude-opus-5-5","max_tokens":1,"max_tokens":100000}`},
		{"duplicate via escape", "anthropic", "/v1/messages", `{"model":"claude-opus-5-5","max_tokens":1,"max_tokens":100000}`},
		{"duplicate model", "openai", "/v1/chat/completions", `{"model":"gpt-5-nano","model":"gpt-5.4-pro"}`},
		{"no model", "openai", "/v1/chat/completions", `{"messages":[]}`},
		{"empty model", "openai", "/v1/responses", `{"model":""}`},
		{"model not string", "openai", "/v1/embeddings", `{"model":5}`},
		{"negative max", "anthropic", "/v1/messages", `{"model":"claude-opus-5-5","max_tokens":-1}`},
		{"float max", "anthropic", "/v1/messages", `{"model":"claude-opus-5-5","max_tokens":10.5}`},
		{"exp max", "openai", "/v1/chat/completions", `{"model":"gpt-5","max_tokens":1e9}`},
		{"string max", "openai", "/v1/chat/completions", `{"model":"gpt-5","max_tokens":"100"}`},
		{"huge max", "openai", "/v1/chat/completions", `{"model":"gpt-5","max_tokens":99999999999999999999999}`},
		{"stream not bool", "openai", "/v1/chat/completions", `{"model":"gpt-5","stream":"yes"}`},
		{"n zero", "openai", "/v1/chat/completions", `{"model":"gpt-5","n":0}`},
		{"thinking not object", "anthropic", "/v1/messages", `{"model":"claude-opus-5-5","thinking":"lots"}`},
		{"thinking dup", "anthropic", "/v1/messages", `{"model":"claude-opus-5-5","thinking":{"budget_tokens":1,"budget_tokens":9}}`},
		{"gemini both config spellings", "gemini", "/v1beta/models/gemini-2.5-pro:generateContent", `{"generationConfig":{},"generation_config":{"max_output_tokens":9}}`},
		{"gemini both max spellings", "gemini", "/v1beta/models/gemini-2.5-pro:generateContent", `{"generationConfig":{"maxOutputTokens":1,"max_output_tokens":9000}}`},
		{"gemini bad config", "gemini", "/v1beta/models/gemini-2.5-pro:generateContent", `{"generationConfig":[1]}`},
		{"gemini not json", "gemini", "/v1beta/models/gemini-2.5-pro:generateContent", `contents=hi`},
		{"service tier not string", "openai", "/v1/chat/completions", `{"model":"gpt-5","service_tier":1}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := inspect(t, m, c.prov, "POST", c.path, c.body)
			if err == nil {
				t.Fatal("expected error")
			}
			if !errors.Is(err, ErrMalformedRequest) {
				t.Fatalf("error does not wrap ErrMalformedRequest: %v", err)
			}
		})
	}
}

func TestInspectErrorsDoNotEchoBody(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing()}
	secret := "sk-ant-api03-SECRETSECRETSECRET"
	_, err := inspect(t, m, "anthropic", "POST", "/v1/messages", `{"model":"claude-opus-5-5","max_tokens":"`+secret+`"}`)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks body content: %v", err)
	}
}

func TestGeminiModelFromPath(t *testing.T) {
	for path, want := range map[string]string{
		"/v1beta/models/gemini-2.5-pro:generateContent":      "gemini-2.5-pro",
		"/v1beta/models/gemini-2.5-pro%2Dx:generateContent":  "gemini-2.5-pro-x",
		"/v1beta/models/gemini-3.1-pro-preview:embedContent": "gemini-3.1-pro-preview",
		"/v1beta/models/:generateContent":                    "",
		"/v1beta/models/gemini-2.5-pro":                      "",
		"/v1beta/models/a%2Fb:generateContent":               "",
		"/v1beta/models/a%zz:generateContent":                "",
	} {
		got, err := geminiModelFromPath(path)
		if want == "" {
			if err == nil {
				t.Errorf("%s: expected error, got %q", path, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v", path, got, err)
		}
	}
}

func TestInspectFoldsMultipliers(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing(), AssumeMaxOutputTokens: 4096}
	// n=3 with no declared limit: the model ceiling (128000) times n.
	info, err := inspect(t, m, "openai", "POST", "/v1/chat/completions", `{"model":"gpt-5.4-mini","n":3,"messages":[]}`)
	if err != nil {
		t.Fatal(err)
	}
	if info.MaxOutputTokens != 3*128000 {
		t.Fatalf("n fold: %d", info.MaxOutputTokens)
	}
	// Gemini candidateCount=2 plus an explicit thinking budget.
	info, err = inspect(t, m, "gemini", "POST", "/v1beta/models/gemini-2.5-pro:generateContent",
		`{"generationConfig":{"maxOutputTokens":100,"candidateCount":2,"thinkingConfig":{"thinkingBudget":50}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if info.MaxOutputTokens != 300 || info.ThinkingTokens != 0 {
		t.Fatalf("candidateCount fold: %+v", info)
	}
	// Anthropic fast mode on a model that has it: 2x on input and output.
	body := `{"model":"claude-opus-5-5","max_tokens":1000,"speed":"fast","messages":[]}`
	info, err = inspect(t, m, "anthropic", "POST", "/v1/messages", body)
	if err != nil {
		t.Fatal(err)
	}
	if info.MaxOutputTokens != 2000 || info.InputTokensEstimate != 2*int64((len(body)+2)/3) {
		t.Fatalf("fast fold: %+v", info)
	}
	// Flex never lowers an estimate; an unknown tier takes the model's max.
	info, _ = inspect(t, m, "openai", "POST", "/v1/responses", `{"model":"gpt-6.1-sol","max_output_tokens":100,"service_tier":"flex"}`)
	if info.MaxOutputTokens != 100 {
		t.Fatalf("flex changed estimate: %+v", info)
	}
	info, _ = inspect(t, m, "openai", "POST", "/v1/responses", `{"model":"gpt-6.1-sol","max_output_tokens":100,"service_tier":"warp"}`)
	if info.MaxOutputTokens != 600 {
		t.Fatalf("unknown tier not at max: %+v", info)
	}
	info, _ = inspect(t, m, "openai", "POST", "/v1/responses", `{"model":"gpt-6.1-sol","max_output_tokens":100,"service_tier":"priority"}`)
	if info.MaxOutputTokens != 200 {
		t.Fatalf("priority not mapped to fast: %+v", info)
	}
}

func TestInspectServerSideContent(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing()}
	cases := []struct {
		name, prov, path, body string
		wantMin                int64
	}{
		{"previous_response_id", "openai", "/v1/responses", `{"model":"gpt-5.4","previous_response_id":"resp_1","input":"go on"}`, 1050000},
		{"file_id", "anthropic", "/v1/messages", `{"model":"claude-opus-5-5","max_tokens":5,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"file","file_id":"file_1"}}]}]}`, 1000000},
		{"url source", "anthropic", "/v1/messages", `{"model":"claude-haiku-4-5","max_tokens":5,"messages":[{"role":"user","content":[{"type":"document","source":{"type":"url","url":"https://example.com/a.pdf"}}]}]}`, 200000},
		{"server tool", "anthropic", "/v1/messages", `{"model":"claude-haiku-4-5","max_tokens":5,"tools":[{"type":"web_fetch_20250910","name":"web_fetch"}],"messages":[]}`, 200000},
		{"gemini cached content", "gemini", "/v1beta/models/gemini-2.5-pro:generateContent", `{"cachedContent":"cachedContents/abc","contents":[]}`, 1048576},
		{"gemini search tool", "gemini", "/v1beta/models/gemini-2.5-pro:generateContent", `{"tools":[{"google_search":{}}],"contents":[]}`, 1048576},
		{"image url", "openai", "/v1/chat/completions", `{"model":"gpt-5","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://e/x.png"}}]}]}`, imageURLTokens},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			info, err := inspect(t, m, c.prov, "POST", c.path, c.body)
			if err != nil {
				t.Fatal(err)
			}
			if info.InputTokensEstimate < c.wantMin {
				t.Fatalf("InputTokensEstimate %d < %d", info.InputTokensEstimate, c.wantMin)
			}
		})
	}
	// A plain text field that merely mentions a key name does not trigger.
	info, err := inspect(t, m, "openai", "POST", "/v1/chat/completions", `{"model":"gpt-5","messages":[{"role":"user","content":"what is a file_id or previous_response_id?"}]}`)
	if err != nil || info.InputTokensEstimate > 100 {
		t.Fatalf("false positive: %+v %v", info, err)
	}
}

func TestPrepareBody(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing(), AddStreamUsage: true}
	_, chat := endpointFor(t, "openai", "POST", "/v1/chat/completions")
	_, resp := endpointFor(t, "openai", "POST", "/v1/responses")
	streamInfo := RequestInfo{Kind: provider.KindOpenAIChat, Stream: true}

	unchanged := []struct {
		name string
		m    *Meter
		ep   provider.Endpoint
		info RequestInfo
		body string
	}{
		{"not streaming", m, chat, RequestInfo{Kind: provider.KindOpenAIChat}, `{"model":"gpt-5", "stream":false}`},
		{"already included", m, chat, streamInfo, `{"model":"gpt-5",  "stream":true,"stream_options":{"include_usage":true}}`},
		{"disabled", &Meter{}, chat, streamInfo, `{"model":"gpt-5","stream":true}`},
		{"responses api", m, resp, RequestInfo{Kind: provider.KindOpenAIResponses, Stream: true}, `{"model":"gpt-5","stream":true}`},
	}
	for _, c := range unchanged {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.m.PrepareBody(c.ep, []byte(c.body), c.info)
			if err != nil || !bytes.Equal(got, []byte(c.body)) {
				t.Fatalf("body changed: %q %v", got, err)
			}
		})
	}

	t.Run("adds include_usage and preserves raw values", func(t *testing.T) {
		body := readFixture(t, "req_openai_chat_stream.json")
		got, err := m.PrepareBody(chat, body, streamInfo)
		if err != nil {
			t.Fatal(err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(got, &obj); err != nil {
			t.Fatal(err)
		}
		if string(obj["stream_options"]) != `{"include_usage":true}` {
			t.Fatalf("stream_options = %s", obj["stream_options"])
		}
		// Number bytes survive exactly (no float round trip).
		if string(obj["temperature"]) != "0.70000000000000001" {
			t.Fatalf("temperature re-encoded: %s", obj["temperature"])
		}
		var orig map[string]json.RawMessage
		_ = json.Unmarshal(body, &orig)
		for k, v := range orig {
			if !bytes.Equal(bytes.TrimSpace(obj[k]), bytes.TrimSpace(v)) {
				t.Fatalf("field %q changed: %s -> %s", k, v, obj[k])
			}
		}
		if bytes.Index(got, []byte(`"model"`)) > bytes.Index(got, []byte(`"stream_options"`)) {
			t.Fatal("key order not preserved")
		}
	})

	t.Run("keeps other stream_options", func(t *testing.T) {
		got, err := m.PrepareBody(chat, []byte(`{"model":"gpt-5","stream":true,"stream_options":{"include_obfuscation":false,"include_usage":false}}`), streamInfo)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(got, []byte(`"stream_options":{"include_obfuscation":false,"include_usage":true}`)) {
			t.Fatalf("got %s", got)
		}
	})

	t.Run("null stream_options", func(t *testing.T) {
		got, err := m.PrepareBody(chat, []byte(`{"model":"gpt-5","stream":true,"stream_options":null}`), streamInfo)
		if err != nil || !bytes.Contains(got, []byte(`"stream_options":{"include_usage":true}`)) {
			t.Fatalf("got %s %v", got, err)
		}
	})

	for name, body := range map[string]string{
		"bad stream_options": `{"model":"gpt-5","stream":true,"stream_options":"yes"}`,
		"bad include_usage":  `{"model":"gpt-5","stream":true,"stream_options":{"include_usage":1}}`,
		"duplicate keys":     `{"model":"gpt-5","stream":true,"stream":false}`,
		"not json":           `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := m.PrepareBody(chat, []byte(body), streamInfo); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestInspectTokenIDArrays(t *testing.T) {
	m := &Meter{Pricing: DefaultPricing()}
	body := `{"model":"text-embedding-3-small","input":[` + strings.TrimSuffix(strings.Repeat("1,", 3000), ",") + `]}`
	info, err := inspect(t, m, "openai", "POST", "/v1/embeddings", body)
	if err != nil {
		t.Fatal(err)
	}
	if info.InputTokensEstimate < 3000 {
		t.Fatalf("token-id array underestimated: %d", info.InputTokensEstimate)
	}
}
