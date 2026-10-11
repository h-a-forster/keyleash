package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/h-a-forster/keyleash/internal/meter"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// Errors reported in Outcome.UpstreamErr for proxy-enforced timeouts.
var (
	ErrResponseHeaderTimeout = errors.New("proxy: upstream response header timeout")
	ErrStreamIdleTimeout     = errors.New("proxy: upstream stream idle timeout")
)

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req_unknown"
	}
	return "req_" + hex.EncodeToString(b[:])
}

func (s *Server) logf(format string, args ...any) { s.cfg.ErrorLog.Printf(format, args...) }

func deny(status int, reason string) *Denial { return &Denial{Status: status, Reason: reason} }

// serveHTTP is the request flow of spec §10.1–§10.4.
func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	reqID := newRequestID()
	w.Header().Set(RequestIDHeader, reqID)

	// 1. Loopback peer.
	local, remote, ok := peerAddrs(r)
	if !ok || !remote.Addr().IsLoopback() {
		writeError(w, nil, deny(http.StatusForbidden, ReasonNonLoopback))
		return
	}
	// 2. Host header must name this proxy by a loopback name.
	port := local.Port()
	if !local.IsValid() {
		port = s.cfgPort
	}
	if r.URL.IsAbs() || r.URL.Host != "" || r.Method == http.MethodConnect || !hostAllowed(r.Host, port) {
		writeError(w, nil, deny(http.StatusForbidden, ReasonHostDenied))
		return
	}
	// 3. Origin: refuse browser-originated requests unless allowlisted.
	if origins, present := r.Header["Origin"]; present {
		if len(origins) != 1 || !s.origins[origins[0]] {
			writeError(w, nil, deny(http.StatusForbidden, ReasonOriginDenied))
			return
		}
	}
	// 4. Route /<provider>/<path>.
	provName, path, err := splitTarget(rawRequestPath(r))
	if err != nil {
		writeError(w, nil, deny(http.StatusForbidden, ReasonEndpointDenied))
		return
	}
	p, ok := provider.Get(provName)
	if !ok {
		writeError(w, nil, deny(http.StatusNotFound, ReasonUnknownProvider))
		return
	}
	// 5. Endpoint allowlist on the validated, un-normalised path.
	ep, ok := p.Match(r.Method, path)
	if !ok {
		writeError(w, p, deny(http.StatusForbidden, ReasonEndpointDenied))
		return
	}
	// 6. Presented pass (and ?key= removal from the forwarded query).
	fwdQuery, queryKeys, err := splitQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, p, deny(http.StatusBadRequest, ReasonBadRequest))
		return
	}
	token, err := presentedToken(r.Header, queryKeys)
	if err != nil {
		msg := ""
		if errors.Is(err, errAmbiguousCredential) {
			msg = "keyleash found more than one credential on this request — send only the keyleash pass"
		}
		writeError(w, p, &Denial{Status: http.StatusUnauthorized, Reason: ReasonPassInvalid, Message: msg})
		return
	}
	client := ClientInfo{Remote: remote}
	if s.peers != nil {
		client = s.peers(local, remote)
		client.Remote = remote
	}
	principal, err := s.auth.Authenticate(r.Context(), p.Name, token, client)
	token = ""
	if err != nil {
		var d *Denial
		if !errors.As(err, &d) {
			d = deny(http.StatusUnauthorized, ReasonPassInvalid)
		}
		writeError(w, p, d)
		return
	}
	// 7. Body, bounded.
	body, err := s.readBody(w, r)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, p, deny(http.StatusRequestEntityTooLarge, ReasonBodyTooLarge))
		} else {
			writeError(w, p, deny(http.StatusBadRequest, ReasonBadRequest))
		}
		return
	}
	// 8. Inspect; any parse failure is denied (fail closed).
	info, err := s.meter.Inspect(p, ep, path, body)
	if err != nil {
		writeError(w, p, deny(http.StatusBadRequest, ReasonBadRequest))
		return
	}
	outBody, err := s.meter.PrepareBody(ep, body, info)
	if err != nil {
		writeError(w, p, deny(http.StatusBadRequest, ReasonBadRequest))
		return
	}
	// 9. Admission (may block for approval).
	ticket, err := s.gate.Admit(r.Context(), Admission{
		Principal: principal, Provider: p, Endpoint: ep, Info: info, Client: client, RequestID: reqID,
	})
	if err != nil {
		var d *Denial
		if !errors.As(err, &d) {
			if r.Context().Err() != nil {
				return // client went away while waiting
			}
			s.logf("keyleash proxy %s: gate error (%T)", reqID, err)
			d = deny(http.StatusInternalServerError, ReasonInternal)
		}
		writeError(w, p, d)
		return
	}
	if ticket == nil {
		s.logf("keyleash proxy %s: gate returned no ticket", reqID)
		writeError(w, p, deny(http.StatusInternalServerError, ReasonInternal))
		return
	}

	out := Outcome{}
	var finishOnce sync.Once
	defer finishOnce.Do(func() { ticket.Finish(out) })

	s.forward(w, r, reqID, p, ep, principal, path, fwdQuery, outBody, info.Stream, &out)
}

func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(bodyReadTimeout))
	defer rc.SetReadDeadline(time.Time{})
	return io.ReadAll(http.MaxBytesReader(w, r.Body, s.cfg.BodyLimit))
}

// watchdog cancels the upstream request when a deadline passes without a
// kick, recording which timeout fired.
type watchdog struct {
	mu     sync.Mutex
	t      *time.Timer
	cancel context.CancelFunc
	cause  error
	fired  error
}

func newWatchdog(d time.Duration, cause error, cancel context.CancelFunc) *watchdog {
	w := &watchdog{cancel: cancel, cause: cause}
	w.t = time.AfterFunc(d, w.fire)
	return w
}

func (w *watchdog) fire() {
	w.mu.Lock()
	w.fired = w.cause
	w.mu.Unlock()
	w.cancel()
}

// rearm resets the deadline with a (possibly new) cause; false if already fired.
func (w *watchdog) rearm(d time.Duration, cause error) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired != nil {
		return false
	}
	w.t.Stop()
	w.cause = cause
	w.t.Reset(d)
	return true
}

func (w *watchdog) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.t.Stop()
}

func (w *watchdog) err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fired
}

// forward sends the request upstream with the real key and relays the
// response, filling out. out is read by the deferred Finish.
func (s *Server) forward(w http.ResponseWriter, r *http.Request, reqID string, p *provider.Provider,
	ep provider.Endpoint, principal Principal, path, fwdQuery string, body []byte, stream bool, out *Outcome) {

	base := s.cfg.Upstream(p)
	if base == nil || base.Host == "" || (base.Scheme != "https" && base.Scheme != "http") {
		s.logf("keyleash proxy %s: no upstream for provider %s", reqID, p.Name)
		out.Status = http.StatusInternalServerError
		writeError(w, p, deny(http.StatusInternalServerError, ReasonInternal))
		return
	}
	target := &url.URL{
		Scheme:   base.Scheme,
		Host:     base.Host,
		Path:     base.Path + p.UpstreamPath(path),
		RawQuery: fwdQuery,
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	var sent atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { sent.Store(true) },
	})

	var outReq *http.Request
	keyErr := s.keys.WithKey(principal.EntryID, func(key []byte) error {
		if !validKey(key) {
			return errors.New("stored key is not a valid header value")
		}
		req, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bodyReader(body))
		if err != nil {
			return errors.New("could not build upstream request")
		}
		req.Header = outboundHeader(r.Header)
		req.Host = target.Host
		req.ContentLength = int64(len(body))
		// The key becomes a Go string here; unavoidable (spec §5.5).
		switch p.Auth {
		case provider.AuthBearer:
			req.Header.Set("Authorization", "Bearer "+string(key))
		case provider.AuthHeader:
			req.Header.Set(p.AuthHeader, string(key))
		default:
			return errors.New("unsupported provider auth style")
		}
		outReq = req
		return nil
	})
	if keyErr != nil || outReq == nil {
		var d *Denial
		if !errors.As(keyErr, &d) {
			s.logf("keyleash proxy %s: key unavailable for provider %s", reqID, p.Name)
			d = &Denial{Status: http.StatusInternalServerError, Reason: ReasonInternal,
				Message: "keyleash could not load the key for this provider"}
		}
		out.Status = d.status()
		writeError(w, p, d)
		return
	}

	start := s.cfg.Now()
	wd := newWatchdog(s.cfg.ResponseHeaderTimeout, ErrResponseHeaderTimeout, cancel)
	defer wd.stop()
	resp, err := s.client.Do(outReq)
	outReq = nil // drop the only reference to the header holding the key
	out.Sent = sent.Load()
	if err != nil {
		out.Latency = s.cfg.Now().Sub(start)
		if r.Context().Err() != nil {
			out.ClientAborted = true
			out.UpstreamErr = r.Context().Err()
			out.Status = 499
			return
		}
		if fe := wd.err(); fe != nil {
			out.UpstreamErr = fe
		} else {
			out.UpstreamErr = errors.New("proxy: upstream request failed")
		}
		s.logf("keyleash proxy %s: upstream %s failed: %v", reqID, p.Name, scrubErr(err))
		out.Status = http.StatusBadGateway
		writeError(w, p, deny(http.StatusBadGateway, ReasonUpstream))
		return
	}
	defer resp.Body.Close()
	out.Status = resp.StatusCode
	wd.rearm(s.cfg.StreamIdleTimeout, ErrStreamIdleTimeout)

	var parser meter.UsageParser = nopParser{}
	if mp := s.meter.NewUsageParser(p, ep, stream); mp != nil {
		parser = mp
	}
	if ho, ok := parser.(headerObserver); ok {
		ho.ObserveResponseHeader(resp.Header.Clone())
	}

	copyResponseHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	flush := stream || isEventStream(resp.Header.Get("Content-Type"))
	if flush {
		_ = rc.Flush()
	}

	buf := make([]byte, 32<<10)
	complete := false
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			wd.rearm(s.cfg.StreamIdleTimeout, ErrStreamIdleTimeout)
			parser.Write(buf[:n])
			wn, werr := w.Write(buf[:n])
			out.BytesOut += int64(wn)
			if werr == nil && flush {
				werr = rc.Flush()
			}
			if werr != nil {
				out.ClientAborted = true
				break
			}
		}
		if rerr == io.EOF {
			complete = true
			break
		}
		if rerr != nil {
			if r.Context().Err() != nil {
				out.ClientAborted = true
			} else if fe := wd.err(); fe != nil {
				out.UpstreamErr = fe
			} else {
				out.UpstreamErr = errors.New("proxy: upstream body read failed")
				s.logf("keyleash proxy %s: upstream %s body: %v", reqID, p.Name, scrubErr(rerr))
			}
			break
		}
	}
	if r.Context().Err() != nil {
		out.ClientAborted = true
	}
	out.Latency = s.cfg.Now().Sub(start)
	u, ok := parser.Final()
	out.Usage = u
	out.UsageOK = ok && complete && !out.ClientAborted
	if !complete && !out.ClientAborted {
		// Upstream broke mid-body: abort the client connection instead of
		// ending the response cleanly, so the client cannot mistake a
		// truncated body for a complete one. Deferred Finish still runs.
		panic(http.ErrAbortHandler)
	}
}

// nopParser is used if the Meter returns no parser: usage is never known.
type nopParser struct{}

func (nopParser) Write(p []byte) (int, error) { return len(p), nil }
func (nopParser) Final() (meter.Usage, bool)  { return meter.Usage{}, false }

func bodyReader(b []byte) io.Reader {
	if len(b) == 0 {
		return http.NoBody
	}
	return bytes.NewReader(b)
}

func isEventStream(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	return err == nil && mt == "text/event-stream"
}

// scrubErr reduces an upstream error to its type plus a fixed message for
// url.Error, whose text includes the request URL. The URL never carries a key
// (the ?key= parameter is removed and the key travels only in a header), but
// keeping logs to error classes is cheap defence in depth.
func scrubErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() {
			return ue.Op + ": timeout"
		}
		return ue.Op + ": " + scrubInner(ue.Err)
	}
	return scrubInner(err)
}

func scrubInner(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline exceeded"
	}
	return sanitizeMessage(err.Error())
}
