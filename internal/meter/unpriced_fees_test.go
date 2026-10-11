package meter

import "testing"

// TestUnpricedModelToolFeesChargeReservation replays finding E: a model the
// table does not price, asked to run web search up to 200 times, reports
// 200 searches. The request cannot be bounded (search results enter the
// context), so the daemon reserves its per-request limit and asks for
// approval; the fees cannot be priced for this model, so usage must not be
// "ok" (which would settle the 200 searches at $0): the caller then charges
// the full reservation.
func TestUnpricedModelToolFeesChargeReservation(t *testing.T) {
	m := testMeter()
	_, anth := endpointFor(t, "anthropic", "POST", "/v1/messages")
	_, resp := endpointFor(t, "openai", "POST", "/v1/responses")

	req := `{"model":"claude-future-9","max_tokens":100,"tools":[{"type":"web_search_20250305","name":"web_search","max_uses":200}],"messages":[]}`
	info, err := inspect(t, m, "anthropic", "POST", "/v1/messages", req)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m.WorstCaseEstimate("anthropic", info); ok {
		t.Fatal("unpriced web search request was bounded")
	}
	body := `{"type":"message","model":"claude-future-9","stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":10,"server_tool_use":{"web_search_requests":200}}}`
	for _, chunk := range []int{0, 1, 7} {
		if u, ok := parseAll(m, "anthropic", anth, false, []byte(body), chunk); ok {
			t.Fatalf("chunk %d: unpriced model with 200 searches settled as usage %+v (fees at $0)", chunk, u)
		}
	}
	oai := `{"object":"response","model":"gpt-future-9","output":[{"type":"web_search_call"},{"type":"message"}],"usage":{"input_tokens":10,"output_tokens":10}}`
	if u, ok := parseAll(m, "openai", resp, false, []byte(oai), 0); ok {
		t.Fatalf("unpriced openai model with a web search settled as usage %+v", u)
	}
	// Without tool fees an unpriced model still reports usage.
	plain := `{"type":"message","model":"claude-future-9","stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":10}}`
	if _, ok := parseAll(m, "anthropic", anth, false, []byte(plain), 0); !ok {
		t.Fatal("plain unpriced usage rejected")
	}
}
