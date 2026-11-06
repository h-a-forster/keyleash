package meter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fuzzEndpoints are the metered endpoints with their paths.
var fuzzEndpoints = []struct{ prov, path string }{
	{"anthropic", "/v1/messages"},
	{"openai", "/v1/chat/completions"},
	{"openai", "/v1/responses"},
	{"openai", "/v1/embeddings"},
	{"openrouter", "/v1/chat/completions"},
	{"gemini", "/v1beta/models/gemini-2.5-pro:generateContent"},
	{"gemini", "/v1beta/models/gemini-2.5-pro:streamGenerateContent"},
}

func addTestdata(f *testing.F, prefix string) {
	paths, err := filepath.Glob(filepath.Join("testdata", prefix+"*"))
	if err != nil {
		f.Fatal(err)
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uint8(0), uint16(len(b)/2), b)
	}
}

// FuzzInspect: a body from a client never panics the meter, an accepted one
// never yields a negative bound, and PrepareBody keeps it a valid request
// for the same model.
func FuzzInspect(f *testing.F) {
	addTestdata(f, "req_")
	m := testMeter()
	f.Fuzz(func(t *testing.T, which uint8, _ uint16, body []byte) {
		e := fuzzEndpoints[int(which)%len(fuzzEndpoints)]
		p, ep := endpointFor(t, e.prov, "POST", e.path)
		info, err := m.Inspect(p, ep, e.path, body)
		if err != nil {
			return
		}
		if info.InputTokensEstimate < 0 || info.MaxOutputTokens < 0 || info.ThinkingTokens < 0 {
			t.Fatalf("negative bound: %+v", info)
		}
		if amount, priced := m.Estimate(e.prov, info); priced && amount < 0 {
			t.Fatalf("negative estimate %d", amount)
		}
		if amount, ok := m.WorstCaseEstimate(e.prov, info); ok && amount < 0 {
			t.Fatalf("negative worst case %d", amount)
		}
		out, err := m.PrepareBody(ep, body, info)
		if err != nil {
			return
		}
		again, err := m.Inspect(p, ep, e.path, out)
		if err != nil {
			t.Fatalf("prepared body no longer inspects: %v", err)
		}
		if again.Model != info.Model || again.Stream != info.Stream || again.MaxOutputTokens != info.MaxOutputTokens {
			t.Fatalf("prepared body changed the request: %+v -> %+v", info, again)
		}
	})
}

// FuzzUsageParser: how a body is cut into reads must not change the usage
// found, and Write never fails (the proxy relays the stream regardless).
func FuzzUsageParser(f *testing.F) {
	addTestdata(f, "resp_")
	m := testMeter()
	f.Fuzz(func(t *testing.T, which uint8, chunk uint16, body []byte) {
		e := fuzzEndpoints[int(which)%len(fuzzEndpoints)]
		_, ep := endpointFor(t, e.prov, "POST", e.path)
		for _, stream := range []bool{false, true} {
			whole, wholeOK := parseAll(m, e.prov, ep, stream, body, 0)
			cut, cutOK := parseAll(m, e.prov, ep, stream, body, int(chunk)%64+1)
			if wholeOK != cutOK || whole != cut {
				t.Fatalf("stream=%v chunking changed the usage: %+v %v vs %+v %v", stream, whole, wholeOK, cut, cutOK)
			}
			if whole.InputTokens < 0 || whole.OutputTokens < 0 || whole.CacheReadTokens < 0 || whole.CacheWriteTokens < 0 {
				t.Fatalf("negative usage: %+v", whole)
			}
		}
	})
}

// FuzzParseObject: anything parseObject accepts is valid JSON with no
// duplicate key in any spelling, and encode (which PrepareBody forwards)
// stays valid JSON.
func FuzzParseObject(f *testing.F) {
	f.Add([]byte(`{"a":1,"b":{"c":[true,null]}}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		o, err := parseObject(data)
		if err != nil {
			return
		}
		var std map[string]json.RawMessage
		if err := json.Unmarshal(data, &std); err != nil {
			t.Fatalf("parseObject accepted what encoding/json refuses: %v", err)
		}
		if len(std) != len(o.keys) {
			t.Fatalf("key count %d vs %d (duplicate slipped through)", len(o.keys), len(std))
		}
		enc := o.encode()
		if !json.Valid(enc) {
			t.Fatalf("encode is not valid JSON: %q", enc)
		}
		if _, err := parseObject(enc); err != nil {
			t.Fatalf("encode does not parse: %v", err)
		}
	})
}
