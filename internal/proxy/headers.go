package proxy

import (
	"net/http"
	"net/textproto"
	"strings"

	"github.com/h-a-forster/keyleash/internal/provider"
)

// hopByHop are connection-level headers that are never forwarded in either
// direction (RFC 9110 §7.6.1), by canonical name.
var hopByHop = map[string]bool{
	"Connection":          true,
	"Proxy-Connection":    true,
	"Keep-Alive":          true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
}

// requestDrop are request headers keyleash never forwards upstream, besides
// hop-by-hop and provider.CredentialHeaders:
//   - Host: set from the registry.
//   - Origin, Referer: describe a local page/tool; upstream does not need
//     them and they can leak local URLs. (OpenRouter's attribution header is
//     the distinct HTTP-Referer, which is forwarded.)
//   - Accept-Encoding: forced to "identity" upstream so the usage parser sees
//     plaintext; if upstream compresses anyway the bytes are relayed as-is and
//     usage is reported as unknown (reservation charged, fail-safe).
//   - Forwarding headers, Expect, Content-Length (recomputed), and anything
//     keyleash-specific.
var requestDrop = map[string]bool{
	"Host":              true,
	"Origin":            true,
	"Referer":           true,
	"Accept-Encoding":   true,
	"Forwarded":         true,
	"Via":               true,
	"X-Real-Ip":         true,
	"Expect":            true,
	"Content-Length":    true,
	"X-Keyleash-Reason": true,
}

// responseDrop are upstream response headers not relayed to the client.
var responseDrop = map[string]bool{
	"Set-Cookie":  true,
	"Set-Cookie2": true,
	"Alt-Svc":     true,
}

// connectionTokens returns the canonical header names listed in Connection.
func connectionTokens(h http.Header) map[string]bool {
	out := map[string]bool{}
	for _, v := range h.Values("Connection") {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				out[textproto.CanonicalMIMEHeaderKey(t)] = true
			}
		}
	}
	return out
}

var credentialSet = func() map[string]bool {
	m := map[string]bool{}
	for _, h := range provider.CredentialHeaders {
		m[textproto.CanonicalMIMEHeaderKey(h)] = true
	}
	return m
}()

// outboundHeader copies the inbound request headers that may go upstream.
// The provider auth header is set separately, after this filter, so nothing
// a client sends can remove or replace it.
func outboundHeader(in http.Header) http.Header {
	listed := connectionTokens(in)
	out := make(http.Header, len(in))
	for k, vs := range in {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if hopByHop[ck] || listed[ck] || credentialSet[ck] || requestDrop[ck] ||
			strings.HasPrefix(ck, "Proxy-") || strings.HasPrefix(ck, "X-Forwarded-") ||
			strings.HasPrefix(ck, "X-Keyleash-") {
			continue
		}
		out[ck] = append([]string(nil), vs...)
	}
	out.Set("Accept-Encoding", "identity")
	return out
}

// copyResponseHeader copies relayable upstream response headers into dst.
func copyResponseHeader(dst, src http.Header) {
	listed := connectionTokens(src)
	for k, vs := range src {
		ck := textproto.CanonicalMIMEHeaderKey(k)
		if hopByHop[ck] || listed[ck] || responseDrop[ck] || strings.HasPrefix(ck, "Proxy-") ||
			strings.HasPrefix(ck, "X-Keyleash-") {
			continue
		}
		dst[ck] = append([]string(nil), vs...)
	}
}

// validKey reports whether key can be sent as a header value without
// corrupting the request (no control characters or surrounding space).
func validKey(key []byte) bool {
	if len(key) == 0 || len(key) > 4096 {
		return false
	}
	for _, c := range key {
		if c <= 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}
