// Package provider is the registry of upstream LLM providers keyleash can
// broker: where requests go, how they authenticate, and which endpoints are
// allowed through. Upstream hosts come only from this registry, never from a
// client request.
package provider

import (
	"net/http"
	"sort"
	"strings"
)

// AuthStyle is how a provider expects its API key to be presented.
type AuthStyle int

const (
	// AuthHeader puts the raw key in a named header (e.g. x-api-key).
	AuthHeader AuthStyle = iota
	// AuthBearer sends "Authorization: Bearer <key>".
	AuthBearer
)

// Endpoint is one allowed method + path pattern. Path patterns match
// segment-by-segment; a segment of "*" matches any single segment, and a
// segment containing "*" (e.g. "*:generateContent") matches by suffix/prefix
// around the star. Paths are relative to the provider root, starting with "/".
type Endpoint struct {
	Method  string
	Pattern string
	// Metered is true when the endpoint can cost money and must go through
	// budget reservation. Unmetered endpoints (model listing, token counting)
	// still require a valid pass.
	Metered bool
	// Kind tells the meter which request/response schema to expect.
	Kind string
}

// Endpoint kinds understood by the meter.
const (
	KindAnthropicMessages = "anthropic.messages"
	KindOpenAIChat        = "openai.chat"
	KindOpenAIResponses   = "openai.responses"
	KindOpenAIEmbeddings  = "openai.embeddings"
	KindGeminiGenerate    = "gemini.generate"
	KindGeminiEmbed       = "gemini.embed"
	KindFree              = "free"
)

// Provider describes one upstream.
type Provider struct {
	// Name is the routing prefix: requests to /<Name>/... go to this provider.
	Name string
	// Host is the only upstream host requests may reach (HTTPS, port 443).
	Host string
	// PathPrefix is prepended upstream (e.g. "/api" for OpenRouter when the
	// client-facing root should mirror the provider's documented base URL).
	PathPrefix string
	Auth       AuthStyle
	// AuthHeader is the header name for AuthHeader style.
	AuthHeader string
	Endpoints  []Endpoint
	// KeyEnv is the environment variable SDKs read the key from.
	KeyEnv string
	// BaseURLEnv is the environment variable SDKs read the base URL from, if
	// any, and BaseURLSuffix is appended to the proxy root to build its value
	// (e.g. "/v1" for OpenAI SDKs, which expect the version in the base URL).
	BaseURLEnv    string
	BaseURLSuffix string
	// KeyPrefixes are known prefixes of real keys, used by scan.
	KeyPrefixes []string
	// ExtraForward lists provider-specific request headers that must be
	// forwarded (everything not on the hop-by-hop/credential strip list is
	// forwarded anyway; this documents the ones that matter).
	ExtraForward []string
}

// CredentialHeaders is every header any supported provider uses to carry a
// credential. The proxy strips all of them from inbound requests before
// setting the real one, so a client can never smuggle its own credential (or
// a pass) upstream.
var CredentialHeaders = []string{
	"Authorization",
	"Proxy-Authorization",
	"X-Api-Key",
	"X-Goog-Api-Key",
	"Api-Key",
	"Cookie",
}

var registry = map[string]*Provider{
	"anthropic": {
		Name:       "anthropic",
		Host:       "api.anthropic.com",
		Auth:       AuthHeader,
		AuthHeader: "X-Api-Key",
		Endpoints: []Endpoint{
			{Method: http.MethodPost, Pattern: "/v1/messages", Metered: true, Kind: KindAnthropicMessages},
			{Method: http.MethodPost, Pattern: "/v1/messages/count_tokens", Kind: KindFree},
			{Method: http.MethodGet, Pattern: "/v1/models", Kind: KindFree},
			{Method: http.MethodGet, Pattern: "/v1/models/*", Kind: KindFree},
		},
		KeyEnv:       "ANTHROPIC_API_KEY",
		BaseURLEnv:   "ANTHROPIC_BASE_URL",
		KeyPrefixes:  []string{"sk-ant-api", "sk-ant-admin"},
		ExtraForward: []string{"Anthropic-Version", "Anthropic-Beta"},
	},
	"openai": {
		Name: "openai",
		Host: "api.openai.com",
		Auth: AuthBearer,
		Endpoints: []Endpoint{
			{Method: http.MethodPost, Pattern: "/v1/chat/completions", Metered: true, Kind: KindOpenAIChat},
			{Method: http.MethodPost, Pattern: "/v1/responses", Metered: true, Kind: KindOpenAIResponses},
			{Method: http.MethodPost, Pattern: "/v1/embeddings", Metered: true, Kind: KindOpenAIEmbeddings},
			{Method: http.MethodGet, Pattern: "/v1/models", Kind: KindFree},
			{Method: http.MethodGet, Pattern: "/v1/models/*", Kind: KindFree},
		},
		KeyEnv:        "OPENAI_API_KEY",
		BaseURLEnv:    "OPENAI_BASE_URL",
		BaseURLSuffix: "/v1",
		KeyPrefixes:   []string{"sk-proj-", "sk-svcacct-", "sk-admin-", "sk-"},
		ExtraForward:  []string{"OpenAI-Organization", "OpenAI-Project"},
	},
	"openrouter": {
		Name:       "openrouter",
		Host:       "openrouter.ai",
		PathPrefix: "/api",
		Auth:       AuthBearer,
		Endpoints: []Endpoint{
			{Method: http.MethodPost, Pattern: "/v1/chat/completions", Metered: true, Kind: KindOpenAIChat},
			{Method: http.MethodPost, Pattern: "/v1/responses", Metered: true, Kind: KindOpenAIResponses},
			{Method: http.MethodGet, Pattern: "/v1/models", Kind: KindFree},
		},
		KeyEnv:        "OPENROUTER_API_KEY",
		BaseURLSuffix: "/v1",
		KeyPrefixes:   []string{"sk-or-v1-", "sk-or-"},
		ExtraForward:  []string{"HTTP-Referer", "X-Title"},
	},
	"gemini": {
		Name:       "gemini",
		Host:       "generativelanguage.googleapis.com",
		Auth:       AuthHeader,
		AuthHeader: "X-Goog-Api-Key",
		Endpoints: []Endpoint{
			{Method: http.MethodPost, Pattern: "/v1beta/models/*:generateContent", Metered: true, Kind: KindGeminiGenerate},
			{Method: http.MethodPost, Pattern: "/v1beta/models/*:streamGenerateContent", Metered: true, Kind: KindGeminiGenerate},
			{Method: http.MethodPost, Pattern: "/v1beta/models/*:embedContent", Metered: true, Kind: KindGeminiEmbed},
			{Method: http.MethodPost, Pattern: "/v1beta/models/*:countTokens", Kind: KindFree},
			{Method: http.MethodGet, Pattern: "/v1beta/models", Kind: KindFree},
			{Method: http.MethodGet, Pattern: "/v1beta/models/*", Kind: KindFree},
		},
		KeyEnv:      "GEMINI_API_KEY",
		KeyPrefixes: []string{"AIza"},
	},
}

// Get returns the provider with the given routing name.
func Get(name string) (*Provider, bool) {
	p, ok := registry[strings.ToLower(name)]
	return p, ok
}

// Names lists registered providers in a stable order.
func Names() []string {
	out := make([]string, 0, len(registry))
	for n := range registry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Match finds the allowed endpoint for method and path (path relative to the
// provider root, without query string). ok is false when the request is not
// on the allowlist.
func (p *Provider) Match(method, path string) (Endpoint, bool) {
	for _, e := range p.Endpoints {
		if e.Method == method && matchPath(e.Pattern, path) {
			return e, true
		}
	}
	return Endpoint{}, false
}

// UpstreamPath returns the path to request upstream for a client path.
func (p *Provider) UpstreamPath(path string) string {
	return p.PathPrefix + path
}

func matchPath(pattern, path string) bool {
	if strings.Contains(path, "//") || strings.Contains(path, "/../") || strings.HasSuffix(path, "/..") ||
		strings.Contains(path, "/./") || strings.HasSuffix(path, "/.") {
		return false
	}
	ps := strings.Split(strings.Trim(pattern, "/"), "/")
	xs := strings.Split(strings.Trim(path, "/"), "/")
	if len(ps) != len(xs) {
		return false
	}
	for i := range ps {
		if !matchSegment(ps[i], xs[i]) {
			return false
		}
	}
	return true
}

func matchSegment(pat, seg string) bool {
	if seg == "" {
		return false
	}
	star := strings.IndexByte(pat, '*')
	if star < 0 {
		return pat == seg
	}
	pre, suf := pat[:star], pat[star+1:]
	if len(seg) < len(pre)+len(suf)+1 {
		return false
	}
	return strings.HasPrefix(seg, pre) && strings.HasSuffix(seg, suf)
}
