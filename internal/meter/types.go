// Package meter inspects LLM requests and responses: which model, how much it
// could cost at worst, and how much it actually cost.
package meter

import "io"

// RequestInfo is what the meter learns from a request before it is sent.
type RequestInfo struct {
	// Kind is the provider.Endpoint kind the request was parsed as.
	Kind string
	// Model is the requested model id ("" if the endpoint has none).
	Model string
	// Stream is true when the client asked for a streamed (SSE) response.
	Stream bool
	// MaxOutputTokens is the output ceiling the request declares, or 0 when
	// absent (the estimate then falls back to the model or policy ceiling).
	MaxOutputTokens int64
	// ThinkingTokens is an explicit reasoning/thinking budget, if declared.
	ThinkingTokens int64
	// InputTokensEstimate is a deliberately pessimistic input token count.
	InputTokensEstimate int64
}

// Usage is what a provider reported a request actually consumed.
type Usage struct {
	// Model as reported by the provider (may differ from the requested alias).
	Model            string
	InputTokens      int64
	OutputTokens     int64
	CacheWriteTokens int64
	CacheReadTokens  int64
	// ReasoningTokens is informational; providers already count it in
	// OutputTokens, so it must not be added again when pricing.
	ReasoningTokens int64
	// ProviderCostMicros is a cost the provider itself reported (e.g.
	// OpenRouter), in micro-USD, or 0 when not reported. When present it is
	// authoritative over the pricing table.
	ProviderCostMicros int64
}

// UsageParser consumes a response body as it streams past (raw bytes, SSE or
// JSON) and reports the usage it found. It must never block or fail the
// stream: malformed input simply yields ok=false from Final.
type UsageParser interface {
	io.Writer
	// Final returns the usage once the body is complete. ok is false when
	// usage could not be determined (the caller then charges the reservation).
	Final() (u Usage, ok bool)
}
