package proxy

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// peerAddrs returns the connection's local and remote endpoints.
func peerAddrs(r *http.Request) (local, remote netip.AddrPort, ok bool) {
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return local, remote, false
	}
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && la != nil {
		if ap, err := netip.ParseAddrPort(la.String()); err == nil {
			local = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
		}
	}
	return local, remote, true
}

// hostAllowed reports whether the Host header names this proxy by a loopback
// name with the listening port (DNS rebinding defence). Only
// 127.0.0.1:<port>, localhost:<port> and [::1]:<port> are accepted.
func hostAllowed(host string, port uint16) bool {
	if port == 0 {
		return false
	}
	h, p, err := net.SplitHostPort(host)
	if err != nil || p != strconv.Itoa(int(port)) {
		return false
	}
	switch strings.ToLower(h) {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	return false
}

// errBadPath is returned for request targets the proxy will not route.
var errBadPath = errors.New("disallowed request path")

// splitTarget validates the raw request path and splits it into the provider
// name and the provider-relative path. The raw path is checked as sent:
// percent-encoding, backslashes, empty segments ("//", trailing "/"), and
// "." / ".." segments are rejected outright, so nothing is ever normalised
// into an allowed path. Only [A-Za-z0-9-._~:] may appear in segments.
func splitTarget(rawPath string) (prov, rest string, err error) {
	if !strings.HasPrefix(rawPath, "/") || len(rawPath) > 2048 {
		return "", "", errBadPath
	}
	segs := strings.Split(rawPath[1:], "/")
	if len(segs) < 2 {
		return "", "", errBadPath
	}
	for _, s := range segs {
		if s == "" || s == "." || s == ".." {
			return "", "", errBadPath
		}
		for i := 0; i < len(s); i++ {
			if !pathByte(s[i]) {
				return "", "", errBadPath
			}
		}
	}
	return segs[0], "/" + strings.Join(segs[1:], "/"), nil
}

func pathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '.', c == '_', c == '~', c == ':':
		return true
	}
	return false
}

// rawRequestPath returns the path exactly as the client sent it.
func rawRequestPath(r *http.Request) string {
	if r.RequestURI != "" {
		p := r.RequestURI
		if i := strings.IndexAny(p, "?#"); i >= 0 {
			p = p[:i]
		}
		return p
	}
	return r.URL.EscapedPath()
}

// splitQuery removes every "key" parameter from rawQuery (the Gemini
// ?key= credential location) and returns the remaining query in its original
// order and encoding, plus the decoded key values. Queries containing ';',
// control characters or invalid escapes are rejected.
func splitQuery(rawQuery string) (forward string, keys []string, err error) {
	if rawQuery == "" {
		return "", nil, nil
	}
	for i := 0; i < len(rawQuery); i++ {
		c := rawQuery[i]
		if c == ';' || c == '#' || c < 0x21 || c == 0x7f {
			return "", nil, errors.New("disallowed query")
		}
	}
	var kept []string
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		dn, err := url.QueryUnescape(name)
		if err != nil {
			return "", nil, errors.New("disallowed query")
		}
		dv, err := url.QueryUnescape(val)
		if err != nil {
			return "", nil, errors.New("disallowed query")
		}
		if strings.EqualFold(strings.TrimSpace(dn), "key") {
			if dv != "" {
				keys = append(keys, dv)
			}
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "&"), keys, nil
}

// errAmbiguousCredential means the request carried more than one distinct
// credential; the proxy refuses rather than guess which one is the pass.
var errAmbiguousCredential = errors.New("more than one credential presented")

// errNoCredential means no pass was presented.
var errNoCredential = errors.New("no credential presented")

// presentedToken extracts the pass from every location SDKs use: X-Api-Key,
// Authorization: Bearer, X-Goog-Api-Key and ?key= (already extracted into
// queryKeys). Identical values in several places are fine; distinct values,
// or a non-Bearer Authorization, are refused.
func presentedToken(h http.Header, queryKeys []string) (string, error) {
	var vals []string
	for _, name := range []string{"X-Api-Key", "X-Goog-Api-Key"} {
		for _, v := range h.Values(name) {
			if v = strings.TrimSpace(v); v != "" {
				vals = append(vals, v)
			}
		}
	}
	for _, v := range h.Values("Authorization") {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		scheme, tok, ok := strings.Cut(v, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(tok) == "" {
			return "", errAmbiguousCredential
		}
		vals = append(vals, strings.TrimSpace(tok))
	}
	vals = append(vals, queryKeys...)
	if len(vals) == 0 {
		return "", errNoCredential
	}
	for _, v := range vals[1:] {
		if v != vals[0] {
			return "", errAmbiguousCredential
		}
	}
	return vals[0], nil
}
