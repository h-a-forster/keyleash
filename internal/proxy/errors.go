package proxy

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/h-a-forster/keyleash/internal/provider"
)

// Reasons carried in the x-keyleash-reason header (spec §10.4). The first
// group is the spec's list; the second covers checks the proxy makes before a
// request reaches policy.
const (
	ReasonLocked          = "locked"
	ReasonAwayLimit       = "away_limit"
	ReasonBudgetExceeded  = "budget_exceeded"
	ReasonConcurrency     = "concurrency"
	ReasonTripped         = "tripped"
	ReasonModelDenied     = "model_denied"
	ReasonEndpointDenied  = "endpoint_denied"
	ReasonPassInvalid     = "pass_invalid"
	ReasonPassExpired     = "pass_expired"
	ReasonApprovalDenied  = "approval_denied"
	ReasonApprovalTimeout = "approval_timeout"

	ReasonUpstream        = "upstream"
	ReasonNonLoopback     = "non_loopback"
	ReasonHostDenied      = "host_denied"
	ReasonOriginDenied    = "origin_denied"
	ReasonUnknownProvider = "unknown_provider"
	ReasonBadRequest      = "bad_request"
	ReasonBodyTooLarge    = "body_too_large"
	ReasonInternal        = "internal"
)

// ReasonHeader is the response header naming why keyleash refused a request.
const ReasonHeader = "X-Keyleash-Reason"

// RequestIDHeader carries the proxy's request id on every proxied response.
const RequestIDHeader = "X-Keyleash-Request-Id"

// Denial is a policy refusal with the HTTP status and reason to report.
// Message is shown to the client and must never contain secrets; when empty a
// default message for the reason is used.
type Denial struct {
	Status  int
	Reason  string
	Message string
}

// Error implements error.
func (d *Denial) Error() string {
	return "keyleash: " + d.Reason + ": " + d.message()
}

func (d *Denial) message() string {
	if d.Message != "" {
		return d.Message
	}
	if m, ok := defaultMessages[d.Reason]; ok {
		return m
	}
	return "keyleash refused this request"
}

func (d *Denial) status() int {
	if d.Status >= 400 && d.Status <= 599 {
		return d.Status
	}
	return http.StatusForbidden
}

var defaultMessages = map[string]string{
	ReasonLocked:          "keyleash is locked — run `keyleash unlock`",
	ReasonAwayLimit:       "keyleash is in away mode and this request exceeds the away limits — return to the machine or run `keyleash away --budget …`",
	ReasonBudgetExceeded:  "keyleash spend limit reached — see `keyleash status`",
	ReasonConcurrency:     "too many concurrent requests for this keyleash pass — retry shortly",
	ReasonTripped:         "keyleash spend tripwire fired — run `keyleash status` and approve to resume",
	ReasonModelDenied:     "this model is not allowed by keyleash policy for this pass",
	ReasonEndpointDenied:  "this endpoint is not allowed through keyleash",
	ReasonPassInvalid:     "invalid or missing keyleash pass — use the pass from `keyleash env` or `keyleash run`",
	ReasonPassExpired:     "this keyleash pass has expired — create a new one with `keyleash pass create`",
	ReasonApprovalDenied:  "the keyleash approval for this request was denied",
	ReasonApprovalTimeout: "the keyleash approval for this request timed out",
	ReasonUpstream:        "keyleash could not reach the provider",
	ReasonNonLoopback:     "keyleash only accepts connections from this machine",
	ReasonHostDenied:      "keyleash rejected the Host header (use 127.0.0.1 or localhost with the proxy port)",
	ReasonOriginDenied:    "keyleash does not accept requests from this web origin",
	ReasonUnknownProvider: "unknown provider — use /<provider>/… e.g. /anthropic/v1/messages",
	ReasonBadRequest:      "keyleash could not parse this request",
	ReasonBodyTooLarge:    "request body exceeds the keyleash size limit",
	ReasonInternal:        "keyleash internal error",
}

// writeError writes d in the error shape of p (nil p → neutral shape).
func writeError(w http.ResponseWriter, p *provider.Provider, d *Denial) {
	status := d.status()
	msg := sanitizeMessage(d.message())
	var body any
	name := ""
	if p != nil {
		name = p.Name
	}
	switch name {
	case "anthropic":
		body = map[string]any{"type": "error", "error": map[string]any{"type": anthropicType(status), "message": msg}}
	case "openai", "openrouter":
		body = map[string]any{"error": map[string]any{"message": msg, "type": openAIType(status), "code": d.Reason}}
	case "gemini":
		body = map[string]any{"error": map[string]any{"code": status, "message": msg, "status": googleStatus(status)}}
	default:
		body = map[string]any{"error": map[string]any{"type": d.Reason, "message": msg}}
	}
	b, err := json.Marshal(body)
	if err != nil {
		b = []byte(`{"error":{"message":"keyleash error"}}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set(ReasonHeader, d.Reason)
	if status == http.StatusTooManyRequests {
		h.Set("Retry-After", "1")
	}
	h.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	w.Write(b)
}

// sanitizeMessage drops control characters and caps the length so a gate or
// authenticator message cannot inject odd bytes into client output.
func sanitizeMessage(s string) string {
	const max = 300
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > max {
		s = strings.ToValidUTF8(s[:max], "")
	}
	return s
}

func anthropicType(status int) string {
	switch status {
	case 400:
		return "invalid_request_error"
	case 401:
		return "authentication_error"
	case 403, 423:
		return "permission_error"
	case 404:
		return "not_found_error"
	case 413:
		return "request_too_large"
	case 429:
		return "rate_limit_error"
	}
	return "api_error"
}

func openAIType(status int) string {
	switch status {
	case 400, 404, 413:
		return "invalid_request_error"
	case 401:
		return "authentication_error"
	case 403, 423:
		return "permission_error"
	case 429:
		return "rate_limit_error"
	}
	return "server_error"
}

func googleStatus(status int) string {
	switch status {
	case 400, 413:
		return "INVALID_ARGUMENT"
	case 401:
		return "UNAUTHENTICATED"
	case 403:
		return "PERMISSION_DENIED"
	case 404:
		return "NOT_FOUND"
	case 423:
		return "FAILED_PRECONDITION"
	case 429:
		return "RESOURCE_EXHAUSTED"
	case 502, 503:
		return "UNAVAILABLE"
	case 504:
		return "DEADLINE_EXCEEDED"
	}
	return "INTERNAL"
}
