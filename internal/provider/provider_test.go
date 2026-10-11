package provider

import (
	"net/http"
	"testing"
)

func TestMatch(t *testing.T) {
	anth, _ := Get("anthropic")
	gem, _ := Get("gemini")
	tests := []struct {
		p      *Provider
		method string
		path   string
		ok     bool
		kind   string
	}{
		{anth, http.MethodPost, "/v1/messages", true, KindAnthropicMessages},
		{anth, http.MethodGet, "/v1/messages", false, ""},
		{anth, http.MethodPost, "/v1/messages/batches", false, ""},
		{anth, http.MethodGet, "/v1/models/claude-x", true, KindFree},
		{anth, http.MethodGet, "/v1/models/a/b", false, ""},
		{anth, http.MethodPost, "/v1//messages", false, ""},
		{anth, http.MethodPost, "/v1/../v1/messages", false, ""},
		{anth, http.MethodPost, "/v1/./messages", false, ""},
		{anth, http.MethodPost, "/v1/messages/..", false, ""},
		{gem, http.MethodPost, "/v1beta/models/gemini-pro:generateContent", true, KindGeminiGenerate},
		{gem, http.MethodPost, "/v1beta/models/:generateContent", false, ""},
		{gem, http.MethodPost, "/v1beta/models/x:streamGenerateContent", true, KindGeminiGenerate},
		{gem, http.MethodPost, "/v1beta/models/x:deleteEverything", false, ""},
		{gem, http.MethodGet, "/v1beta/models", true, KindFree},
	}
	for _, tt := range tests {
		ep, ok := tt.p.Match(tt.method, tt.path)
		if ok != tt.ok {
			t.Errorf("%s %s %s: ok = %v, want %v", tt.p.Name, tt.method, tt.path, ok, tt.ok)
			continue
		}
		if ok && ep.Kind != tt.kind {
			t.Errorf("%s %s: kind = %q, want %q", tt.method, tt.path, ep.Kind, tt.kind)
		}
	}
}

func TestRegistry(t *testing.T) {
	for _, n := range Names() {
		p, ok := Get(n)
		if !ok || p.Name != n || p.Host == "" {
			t.Fatalf("bad registry entry %q", n)
		}
		if p.Auth == AuthHeader && p.AuthHeader == "" {
			t.Errorf("%s: header auth without header name", n)
		}
		for _, e := range p.Endpoints {
			if e.Metered && e.Kind == KindFree {
				t.Errorf("%s %s: metered endpoint with free kind", n, e.Pattern)
			}
		}
	}
	if _, ok := Get("ANTHROPIC"); !ok {
		t.Error("lookup should be case-insensitive")
	}
	if or, _ := Get("openrouter"); or.UpstreamPath("/v1/models") != "/api/v1/models" {
		t.Error("openrouter path prefix not applied")
	}
}
