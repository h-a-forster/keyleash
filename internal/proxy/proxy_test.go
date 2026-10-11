package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/meter"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// Fake secrets. None of these may ever appear in a response body produced by
// keyleash or in its log output.
const (
	passTok   = "klp_abcdefghjk_PASSSECRETpasssecretPASSSECRETpasssecret0"
	otherPass = "klp_zzzzzzzzzz_OTHERSECRETothersecretOTHERSECRETother00"
	smuggled  = "sk-SMUGGLED-client-supplied-credential-0000"
)

var realKeys = map[string]string{
	"e-anthropic":  "sk-ant-api03-FAKEREALKEY-anthropic-000000000000",
	"e-openai":     "sk-proj-FAKEREALKEY-openai-0000000000000000",
	"e-openrouter": "sk-or-v1-FAKEREALKEY-openrouter-000000000000",
	"e-gemini":     "AIzaFAKEREALKEY-gemini-000000000000000",
}

func allSecrets() []string {
	out := []string{passTok, otherPass, smuggled}
	for _, k := range realKeys {
		out = append(out, k)
	}
	return out
}

// ---- fakes ----

type fakeAuth struct{ calls atomic.Int64 }

func (a *fakeAuth) Authenticate(_ context.Context, prov, token string, _ ClientInfo) (Principal, error) {
	a.calls.Add(1)
	if token != passTok {
		return Principal{}, &Denial{Status: 401, Reason: ReasonPassInvalid}
	}
	return Principal{PassID: "p1", PassName: "test", EntryID: "e-" + prov}, nil
}

type fakeTicket struct {
	n    atomic.Int64
	mu   sync.Mutex
	out  Outcome
	done chan struct{}
}

func (t *fakeTicket) Finish(o Outcome) {
	t.mu.Lock()
	t.out = o
	t.mu.Unlock()
	if t.n.Add(1) == 1 {
		close(t.done)
	}
}

func (t *fakeTicket) wait(tb testing.TB) Outcome {
	tb.Helper()
	select {
	case <-t.done:
	case <-time.After(5 * time.Second):
		tb.Fatal("Finish was not called")
	}
	time.Sleep(20 * time.Millisecond) // catch a second Finish
	if n := t.n.Load(); n != 1 {
		tb.Fatalf("Finish called %d times, want 1", n)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.out
}

type fakeGate struct {
	mu      sync.Mutex
	deny    error
	tickets []*fakeTicket
	adms    []Admission
}

func (g *fakeGate) Admit(_ context.Context, a Admission) (Ticket, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.adms = append(g.adms, a)
	if g.deny != nil {
		return nil, g.deny
	}
	t := &fakeTicket{done: make(chan struct{})}
	g.tickets = append(g.tickets, t)
	return t, nil
}

func (g *fakeGate) ticket(tb testing.TB) *fakeTicket {
	tb.Helper()
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.tickets) != 1 {
		tb.Fatalf("got %d tickets, want 1", len(g.tickets))
	}
	return g.tickets[0]
}

func (g *fakeGate) admitted() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.adms)
}

type fakeKeys struct{ err error }

func (k *fakeKeys) WithKey(entryID string, fn func([]byte) error) error {
	if k.err != nil {
		return k.err
	}
	v, ok := realKeys[entryID]
	if !ok {
		return errors.New("no entry")
	}
	b := []byte(v)
	defer func() {
		for i := range b {
			b[i] = 0
		}
	}()
	return fn(b)
}

type recParser struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	header http.Header
}

func (p *recParser) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.Write(b)
}

func (p *recParser) Final() (meter.Usage, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if bytes.Contains(p.buf.Bytes(), []byte(`"usage"`)) {
		return meter.Usage{InputTokens: 1, OutputTokens: 2}, true
	}
	return meter.Usage{}, false
}

func (p *recParser) ObserveResponseHeader(h http.Header) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.header = h
}

func (p *recParser) bytes() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.buf.Bytes()...)
}

type fakeMeter struct {
	mu      sync.Mutex
	parsers []*recParser
	provs   []string
}

func (m *fakeMeter) Inspect(_ *provider.Provider, ep provider.Endpoint, path string, body []byte) (meter.RequestInfo, error) {
	info := meter.RequestInfo{Kind: ep.Kind}
	if !ep.Metered {
		return info, nil
	}
	var v struct {
		Model  string `json:"model"`
		Stream bool   `json:"stream"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return info, errors.New("malformed")
	}
	info.Model, info.Stream = v.Model, v.Stream
	if strings.HasSuffix(path, ":streamGenerateContent") {
		info.Stream = true
	}
	return info, nil
}

func (m *fakeMeter) PrepareBody(_ provider.Endpoint, body []byte, _ meter.RequestInfo) ([]byte, error) {
	return body, nil
}

func (m *fakeMeter) NewUsageParser(p *provider.Provider, _ provider.Endpoint, _ bool) meter.UsageParser {
	m.mu.Lock()
	defer m.mu.Unlock()
	rp := &recParser{}
	m.parsers = append(m.parsers, rp)
	m.provs = append(m.provs, p.Name)
	return rp
}

func (m *fakeMeter) parser(tb testing.TB) *recParser {
	tb.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.parsers) != 1 {
		tb.Fatalf("got %d parsers, want 1", len(m.parsers))
	}
	return m.parsers[0]
}

// ---- harness ----

type upReq struct {
	Method, Path, RawQuery, Host string
	Header                       http.Header
	Body                         []byte
}

type env struct {
	t      *testing.T
	up     *httptest.Server
	upMu   sync.Mutex
	upReqs []upReq
	front  *httptest.Server
	srv    *Server
	auth   *fakeAuth
	gate   *fakeGate
	keys   *fakeKeys
	meter  *fakeMeter
	logBuf *syncBuf
	bodies []string
	client *http.Client
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newEnv(t *testing.T, upHandler http.HandlerFunc, mod func(*Config)) *env {
	t.Helper()
	e := &env{t: t, auth: &fakeAuth{}, gate: &fakeGate{}, keys: &fakeKeys{}, meter: &fakeMeter{}, logBuf: &syncBuf{}}
	if upHandler == nil {
		upHandler = jsonOK
	}
	e.up = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		e.upMu.Lock()
		e.upReqs = append(e.upReqs, upReq{r.Method, r.URL.Path, r.URL.RawQuery, r.Host, r.Header.Clone(), b})
		e.upMu.Unlock()
		upHandler(w, r)
	}))
	t.Cleanup(e.up.Close)
	upURL, _ := url.Parse(e.up.URL)
	cfg := Config{
		Addr:      "127.0.0.1:47114",
		Upstream:  func(*provider.Provider) *url.URL { u := *upURL; return &u },
		Transport: e.up.Client().Transport,
		ErrorLog:  log.New(e.logBuf, "", 0),
	}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := New(cfg, e.auth, e.gate, e.keys, e.meter, nil)
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	e.front = httptest.NewUnstartedServer(srv.Handler())
	e.front.Config.ErrorLog = log.New(e.logBuf, "", 0)
	e.front.Start()
	t.Cleanup(e.front.Close)
	e.client = &http.Client{
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	t.Cleanup(func() {
		all := strings.Join(e.bodies, "\n") + "\n" + e.logBuf.String()
		for _, s := range allSecrets() {
			if strings.Contains(all, s) {
				t.Errorf("secret %.12s… leaked into a response body or log", s)
			}
		}
	})
	return e
}

func jsonOK(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, `{"id":"x","usage":{"input_tokens":1,"output_tokens":2}}`)
}

func (e *env) upstreamReqs() []upReq {
	e.upMu.Lock()
	defer e.upMu.Unlock()
	return append([]upReq(nil), e.upReqs...)
}

func (e *env) newReq(method, path string, body string) *http.Request {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, e.front.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	return req
}

func (e *env) do(req *http.Request) (*http.Response, string) {
	e.t.Helper()
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	e.bodies = append(e.bodies, string(b))
	return resp, string(b)
}

const chatBody = `{"model":"m-1","messages":[{"role":"user","content":"hi"}]}`

// ---- tests ----

func TestHappyPathAuthStyles(t *testing.T) {
	cases := []struct {
		name       string
		path       string
		setAuth    func(*http.Request)
		wantPath   string
		wantHeader string
		wantValue  string
		wantQuery  string
	}{
		{"anthropic x-api-key", "/anthropic/v1/messages", func(r *http.Request) { r.Header.Set("x-api-key", passTok) },
			"/v1/messages", "X-Api-Key", realKeys["e-anthropic"], ""},
		{"anthropic bearer", "/anthropic/v1/messages", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+passTok) },
			"/v1/messages", "X-Api-Key", realKeys["e-anthropic"], ""},
		{"openai bearer", "/openai/v1/chat/completions", func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+passTok) },
			"/v1/chat/completions", "Authorization", "Bearer " + realKeys["e-openai"], ""},
		{"openrouter prefix", "/openrouter/v1/chat/completions", func(r *http.Request) { r.Header.Set("Authorization", "bearer "+passTok) },
			"/api/v1/chat/completions", "Authorization", "Bearer " + realKeys["e-openrouter"], ""},
		{"gemini header", "/gemini/v1beta/models/gemini-x:generateContent", func(r *http.Request) { r.Header.Set("x-goog-api-key", passTok) },
			"/v1beta/models/gemini-x:generateContent", "X-Goog-Api-Key", realKeys["e-gemini"], ""},
		{"gemini query key", "/gemini/v1beta/models/gemini-x:streamGenerateContent?alt=sse&key=" + url.QueryEscape(passTok) + "&x=1",
			func(*http.Request) {},
			"/v1beta/models/gemini-x:streamGenerateContent", "X-Goog-Api-Key", realKeys["e-gemini"], "alt=sse&x=1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil, nil)
			req := e.newReq("POST", tc.path, chatBody)
			req.Header.Set("Anthropic-Version", "2023-06-01")
			req.Header.Set("Accept-Encoding", "gzip")
			tc.setAuth(req)
			resp, body := e.do(req)
			if resp.StatusCode != 200 {
				t.Fatalf("status %d body %s", resp.StatusCode, body)
			}
			if !strings.Contains(body, `"usage"`) {
				t.Fatalf("body not relayed: %s", body)
			}
			if resp.Header.Get(RequestIDHeader) == "" {
				t.Error("missing request id header")
			}
			ups := e.upstreamReqs()
			if len(ups) != 1 {
				t.Fatalf("upstream got %d requests", len(ups))
			}
			u := ups[0]
			if u.Path != tc.wantPath {
				t.Errorf("upstream path %q, want %q", u.Path, tc.wantPath)
			}
			if u.RawQuery != tc.wantQuery {
				t.Errorf("upstream query %q, want %q", u.RawQuery, tc.wantQuery)
			}
			if got := u.Header.Values(tc.wantHeader); len(got) != 1 || got[0] != tc.wantValue {
				t.Errorf("upstream %s = %d values, want exactly the real key", tc.wantHeader, len(got))
			}
			for k, vs := range u.Header {
				for _, v := range vs {
					if strings.Contains(v, passTok) {
						t.Errorf("pass forwarded upstream in %s", k)
					}
				}
				if k != tc.wantHeader && credentialSet[k] {
					t.Errorf("unexpected credential header %s upstream", k)
				}
			}
			if got := u.Header.Get("Accept-Encoding"); got != "identity" {
				t.Errorf("Accept-Encoding upstream %q, want identity", got)
			}
			if got := u.Header.Get("Anthropic-Version"); got != "2023-06-01" {
				t.Errorf("Anthropic-Version not forwarded: %q", got)
			}
			if string(u.Body) != chatBody {
				t.Errorf("body not forwarded byte-for-byte")
			}
			out := e.gate.ticket(t).wait(t)
			if !out.Sent || !out.UsageOK || out.Status != 200 || out.ClientAborted || out.UpstreamErr != nil {
				t.Errorf("outcome %+v", out)
			}
			if out.BytesOut != int64(len(body)) {
				t.Errorf("BytesOut %d, want %d", out.BytesOut, len(body))
			}
		})
	}
}

func TestHeaderSmugglingStripped(t *testing.T) {
	e := newEnv(t, nil, nil)
	req := e.newReq("POST", "/openai/v1/chat/completions", chatBody)
	req.Header = http.Header{
		"Authorization":       {"Bearer " + passTok},
		"Api-Key":             {smuggled},
		"Cookie":              {"session=" + smuggled},
		"Proxy-Authorization": {"Basic " + smuggled},
		"Connection":          {"X-Custom, Authorization"},
		"X-Custom":            {"listed-in-connection"},
		"X-Forwarded-For":     {"1.2.3.4"},
		"Forwarded":           {"for=1.2.3.4"},
		"Referer":             {"http://localhost/secret-page"},
		"Openai-Organization": {"org-1"},
		"Te":                  {"trailers"},
	}
	resp, body := e.do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d %s", resp.StatusCode, body)
	}
	u := e.upstreamReqs()[0]
	if got := u.Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+realKeys["e-openai"] {
		t.Errorf("Authorization upstream wrong (%d values)", len(got))
	}
	for _, h := range []string{"Api-Key", "Cookie", "Proxy-Authorization", "X-Custom", "X-Forwarded-For", "Forwarded", "Referer", "Te"} {
		if _, ok := u.Header[h]; ok {
			t.Errorf("%s forwarded upstream", h)
		}
	}
	if u.Header.Get("Openai-Organization") != "org-1" {
		t.Error("OpenAI-Organization not forwarded")
	}
	for k, vs := range u.Header {
		for _, v := range vs {
			if strings.Contains(v, smuggled) {
				t.Errorf("smuggled credential forwarded in %s", k)
			}
		}
	}
}

func TestConnectionListsAuthHeader(t *testing.T) {
	e := newEnv(t, nil, nil)
	req := e.newReq("POST", "/anthropic/v1/messages", chatBody)
	req.Header.Set("x-api-key", passTok)
	req.Header.Set("Connection", "x-api-key")
	resp, _ := e.do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	u := e.upstreamReqs()[0]
	if got := u.Header.Values("X-Api-Key"); len(got) != 1 || got[0] != realKeys["e-anthropic"] {
		t.Errorf("real key missing upstream after Connection trick (%d values)", len(got))
	}
}

func TestCredentialAmbiguity(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		header http.Header
		status int
	}{
		{"mixed-case identical duplicates", "/anthropic/v1/messages",
			http.Header{"x-api-key": {passTok}, "X-API-KEY": {passTok}}, 200},
		{"mixed-case distinct duplicates", "/anthropic/v1/messages",
			http.Header{"x-api-key": {passTok}, "X-API-KEY": {smuggled}}, 401},
		{"two authorization values", "/openai/v1/chat/completions",
			http.Header{"Authorization": {"Bearer " + passTok, "Bearer " + smuggled}}, 401},
		{"bearer plus x-api-key distinct", "/openai/v1/chat/completions",
			http.Header{"Authorization": {"Bearer " + passTok}, "X-Api-Key": {smuggled}}, 401},
		{"basic auth", "/openai/v1/chat/completions",
			http.Header{"Authorization": {"Basic " + passTok}}, 401},
		{"no credential", "/openai/v1/chat/completions", http.Header{}, 401},
		{"wrong pass", "/openai/v1/chat/completions", http.Header{"Authorization": {"Bearer " + otherPass}}, 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil, nil)
			req := e.newReq("POST", tc.path, chatBody)
			req.Header = tc.header
			resp, body := e.do(req)
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d want %d (%s)", resp.StatusCode, tc.status, body)
			}
			if tc.status != 200 {
				if resp.Header.Get(ReasonHeader) != ReasonPassInvalid {
					t.Errorf("reason %q", resp.Header.Get(ReasonHeader))
				}
				if len(e.upstreamReqs()) != 0 || e.gate.admitted() != 0 {
					t.Error("refused request reached gate or upstream")
				}
			} else if got := e.upstreamReqs()[0].Header.Values("X-Api-Key"); len(got) != 1 || got[0] != realKeys["e-anthropic"] {
				t.Errorf("upstream X-Api-Key has %d values", len(got))
			}
		})
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	var otherHits atomic.Int64
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { otherHits.Add(1) }))
	defer other.Close()
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusFound)
	}, nil)
	req := e.newReq("POST", "/openai/v1/chat/completions", chatBody)
	req.Header.Set("Authorization", "Bearer "+passTok)
	resp, _ := e.do(req)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d, want 302 relayed", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != other.URL+"/steal" {
		t.Errorf("Location %q", loc)
	}
	if n := otherHits.Load(); n != 0 {
		t.Fatalf("redirect target received %d requests", n)
	}
	out := e.gate.ticket(t).wait(t)
	if !out.Sent || out.Status != 302 {
		t.Errorf("outcome %+v", out)
	}
}

func TestInboundRejections(t *testing.T) {
	e := newEnv(t, nil, func(c *Config) { c.AllowedOrigins = []string{"http://localhost:3000"} })
	port := e.front.Listener.Addr().(*net.TCPAddr).Port
	cases := []struct {
		name   string
		host   string
		origin []string
		status int
		reason string
	}{
		{"evil host", "evil.example:" + fmt.Sprint(port), nil, 403, ReasonHostDenied},
		{"evil host no port", "evil.example", nil, 403, ReasonHostDenied},
		{"loopback wrong port", "127.0.0.1:1", nil, 403, ReasonHostDenied},
		{"localhost ok", "localhost:" + fmt.Sprint(port), nil, 200, ""},
		{"LOCALHOST ok", "LOCALHOST:" + fmt.Sprint(port), nil, 200, ""},
		{"evil origin", "", []string{"https://evil.example"}, 403, ReasonOriginDenied},
		{"null origin", "", []string{"null"}, 403, ReasonOriginDenied},
		{"empty origin", "", []string{""}, 403, ReasonOriginDenied},
		{"allowed origin", "", []string{"http://localhost:3000"}, 200, ""},
		{"two origins", "", []string{"http://localhost:3000", "https://evil.example"}, 403, ReasonOriginDenied},
	}
	admitted := 0
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := e.newReq("POST", "/anthropic/v1/messages", chatBody)
			req.Header.Set("x-api-key", passTok)
			if tc.host != "" {
				req.Host = tc.host
			}
			if tc.origin != nil {
				req.Header["Origin"] = tc.origin
			}
			resp, _ := e.do(req)
			if resp.StatusCode != tc.status {
				t.Fatalf("status %d want %d", resp.StatusCode, tc.status)
			}
			if tc.status == 200 {
				admitted++
			} else if got := resp.Header.Get(ReasonHeader); got != tc.reason {
				t.Errorf("reason %q want %q", got, tc.reason)
			}
			if e.gate.admitted() != admitted {
				t.Errorf("gate admitted %d want %d", e.gate.admitted(), admitted)
			}
		})
	}

	t.Run("non-loopback peer", func(t *testing.T) {
		for _, ra := range []string{"192.0.2.10:5555", "[2001:db8::1]:5555", "garbage"} {
			r := httptest.NewRequest("POST", "/anthropic/v1/messages", strings.NewReader(chatBody))
			r.RemoteAddr = ra
			r.Host = "127.0.0.1:47114"
			r.Header.Set("x-api-key", passTok)
			rec := httptest.NewRecorder()
			e.srv.Handler().ServeHTTP(rec, r)
			if rec.Code != 403 || rec.Header().Get(ReasonHeader) != ReasonNonLoopback {
				t.Errorf("%s: status %d reason %q", ra, rec.Code, rec.Header().Get(ReasonHeader))
			}
			e.bodies = append(e.bodies, rec.Body.String())
		}
	})
	if e.auth.calls.Load() != int64(admitted) {
		t.Errorf("authenticator called %d times for %d admitted requests", e.auth.calls.Load(), admitted)
	}
}

// rawRequest sends target verbatim on the request line.
func rawRequest(t *testing.T, e *env, method, target, extra string) int {
	t.Helper()
	conn, err := net.Dial("tcp", e.front.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	host := e.front.Listener.Addr().String()
	fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nX-Api-Key: %s\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n%sConnection: close\r\n\r\n%s",
		method, target, host, passTok, passTok, len(chatBody), extra, chatBody)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	e.bodies = append(e.bodies, string(b))
	return resp.StatusCode
}

func TestPathRejections(t *testing.T) {
	e := newEnv(t, nil, nil)
	cases := []struct {
		method, target string
		status         int
	}{
		{"POST", "/anthropic/v1/../v1/messages", 403},
		{"POST", "/anthropic/v1/%2e%2e/v1/messages", 403},
		{"POST", "/anthropic/v1/%2E%2E/v1/messages", 403},
		{"POST", "/anthropic/v1%2Fmessages", 403},
		{"POST", "/anthropic/v1%2fmessages", 403},
		{"POST", "/anthropic/%761/messages", 403},
		{"POST", "/anthropic//v1/messages", 403},
		{"POST", "//anthropic/v1/messages", 403},
		{"POST", "/anthropic/v1/messages/", 403},
		{"POST", "/anthropic/v1/./messages", 403},
		{"POST", "/anthropic/v1/messages/..", 403},
		{"POST", "/anthropic/v1/complete", 403},
		{"GET", "/anthropic/v1/messages", 403},
		{"POST", "/anthropic/v1/models/../messages", 403},
		{"POST", "/unknown/v1/messages", 404},
		{"POST", "/anthropic", 403},
		{"POST", "http://api.anthropic.com/anthropic/v1/messages", 403},
		{"POST", "/gemini/v1beta/models/x:generateContent?key=a;b", 400},
	}
	for _, tc := range cases {
		got := rawRequest(t, e, tc.method, tc.target, "")
		if got != tc.status {
			t.Errorf("%s %s: status %d, want %d", tc.method, tc.target, got, tc.status)
		}
	}
	if n := len(e.upstreamReqs()); n != 0 {
		t.Fatalf("upstream received %d requests", n)
	}
	if e.gate.admitted() != 0 {
		t.Fatal("gate admitted a rejected path")
	}
	// Sanity: the same raw sender works for an allowed path.
	if got := rawRequest(t, e, "POST", "/anthropic/v1/messages", ""); got != 200 {
		t.Fatalf("allowed path status %d", got)
	}
}

func TestSSEStreamsIncrementally(t *testing.T) {
	release := make(chan struct{})
	first := "event: message_start\ndata: {\"type\":\"message_start\"}\n\n"
	rest := "event: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n"
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Set-Cookie", "tracking=1")
		w.Header().Set("Connection", "X-Hop")
		w.Header().Set("X-Hop", "1")
		w.Header().Set("X-Gemini-Service-Tier", "standard")
		io.WriteString(w, first)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
		io.WriteString(w, rest)
	}, nil)
	req := e.newReq("POST", "/anthropic/v1/messages", `{"model":"m","stream":true}`)
	req.Header.Set("x-api-key", passTok)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Set-Cookie") != "" || resp.Header.Get("X-Hop") != "" {
		t.Error("Set-Cookie or Connection-listed header relayed to client")
	}
	got := make([]byte, len(first))
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(resp.Body, got); done <- err }()
	select {
	case err := <-done:
		if err != nil || string(got) != first {
			t.Fatalf("first event: %v %q", err, got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("first event not flushed before upstream finished")
	}
	close(release)
	tail, _ := io.ReadAll(resp.Body)
	if string(tail) != rest {
		t.Fatalf("tail %q", tail)
	}
	out := e.gate.ticket(t).wait(t)
	if !out.UsageOK || out.BytesOut != int64(len(first)+len(rest)) {
		t.Errorf("outcome %+v", out)
	}
	p := e.meter.parser(t)
	if string(p.bytes()) != first+rest {
		t.Errorf("parser saw %q", p.bytes())
	}
	if p.header.Get("X-Gemini-Service-Tier") != "standard" {
		t.Error("parser did not observe response headers")
	}
	if e.meter.provs[0] != "anthropic" {
		t.Errorf("parser built for provider %q", e.meter.provs[0])
	}
}

func TestClientAbortFinishesOnce(t *testing.T) {
	upDone := make(chan struct{})
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		defer close(upDone)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	req := e.newReq("POST", "/anthropic/v1/messages", `{"model":"m","stream":true}`).WithContext(ctx)
	req.Header.Set("x-api-key", passTok)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 10)
	io.ReadFull(resp.Body, buf)
	cancel()
	resp.Body.Close()
	out := e.gate.ticket(t).wait(t)
	if !out.ClientAborted || out.UsageOK || !out.Sent {
		t.Errorf("outcome %+v", out)
	}
	select {
	case <-upDone:
	case <-time.After(3 * time.Second):
		t.Error("upstream request not cancelled after client abort")
	}
}

func TestUpstreamFailure(t *testing.T) {
	e := newEnv(t, nil, func(c *Config) {
		c.Upstream = func(*provider.Provider) *url.URL { return &url.URL{Scheme: "https", Host: "127.0.0.1:1"} }
	})
	for _, prov := range []string{"anthropic", "openai", "gemini"} {
		e.gate.tickets = nil
		path := map[string]string{"anthropic": "/anthropic/v1/messages", "openai": "/openai/v1/chat/completions",
			"gemini": "/gemini/v1beta/models/g:generateContent"}[prov]
		req := e.newReq("POST", path, chatBody)
		req.Header.Set("Authorization", "Bearer "+passTok)
		resp, body := e.do(req)
		if resp.StatusCode != 502 || resp.Header.Get(ReasonHeader) != ReasonUpstream {
			t.Fatalf("%s: status %d reason %q", prov, resp.StatusCode, resp.Header.Get(ReasonHeader))
		}
		if !json.Valid([]byte(body)) {
			t.Errorf("%s: invalid JSON error body", prov)
		}
		out := e.gate.ticket(t).wait(t)
		if out.Sent || out.UpstreamErr == nil || out.Status != 502 {
			t.Errorf("%s: outcome %+v", prov, out)
		}
	}
}

func TestStreamIdleTimeout(t *testing.T) {
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {}\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}, func(c *Config) { c.StreamIdleTimeout = 150 * time.Millisecond })
	req := e.newReq("POST", "/anthropic/v1/messages", `{"model":"m","stream":true}`)
	req.Header.Set("x-api-key", passTok)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, rerr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if rerr == nil {
		t.Error("client saw a clean end of a truncated stream")
	}
	out := e.gate.ticket(t).wait(t)
	if !errors.Is(out.UpstreamErr, ErrStreamIdleTimeout) || out.UsageOK {
		t.Errorf("outcome %+v", out)
	}
}

func TestResponseHeaderTimeout(t *testing.T) {
	e := newEnv(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}, func(c *Config) { c.ResponseHeaderTimeout = 150 * time.Millisecond })
	req := e.newReq("POST", "/anthropic/v1/messages", chatBody)
	req.Header.Set("x-api-key", passTok)
	resp, _ := e.do(req)
	if resp.StatusCode != 502 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	out := e.gate.ticket(t).wait(t)
	if !errors.Is(out.UpstreamErr, ErrResponseHeaderTimeout) || !out.Sent {
		t.Errorf("outcome %+v", out)
	}
}

func TestGateAndKeyDenials(t *testing.T) {
	t.Run("gate denial", func(t *testing.T) {
		e := newEnv(t, nil, nil)
		e.gate.deny = &Denial{Status: 423, Reason: ReasonLocked}
		req := e.newReq("POST", "/anthropic/v1/messages", chatBody)
		req.Header.Set("x-api-key", passTok)
		resp, body := e.do(req)
		if resp.StatusCode != 423 || resp.Header.Get(ReasonHeader) != ReasonLocked {
			t.Fatalf("status %d reason %q", resp.StatusCode, resp.Header.Get(ReasonHeader))
		}
		var v struct {
			Type  string
			Error struct{ Type, Message string }
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil || v.Type != "error" || !strings.Contains(v.Error.Message, "keyleash unlock") {
			t.Errorf("body %s", body)
		}
		if len(e.upstreamReqs()) != 0 {
			t.Error("denied request reached upstream")
		}
	})
	t.Run("concurrency 429", func(t *testing.T) {
		e := newEnv(t, nil, nil)
		e.gate.deny = fmt.Errorf("wrapped: %w", &Denial{Status: 429, Reason: ReasonConcurrency})
		req := e.newReq("POST", "/openai/v1/chat/completions", chatBody)
		req.Header.Set("Authorization", "Bearer "+passTok)
		resp, _ := e.do(req)
		if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	t.Run("gate generic error", func(t *testing.T) {
		e := newEnv(t, nil, nil)
		e.gate.deny = errors.New("boom " + smuggled)
		req := e.newReq("POST", "/openai/v1/chat/completions", chatBody)
		req.Header.Set("Authorization", "Bearer "+passTok)
		resp, _ := e.do(req)
		if resp.StatusCode != 500 {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	t.Run("key source denial after admit", func(t *testing.T) {
		e := newEnv(t, nil, nil)
		e.keys.err = &Denial{Status: 423, Reason: ReasonLocked}
		req := e.newReq("POST", "/anthropic/v1/messages", chatBody)
		req.Header.Set("x-api-key", passTok)
		resp, _ := e.do(req)
		if resp.StatusCode != 423 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		out := e.gate.ticket(t).wait(t)
		if out.Sent || out.Status != 423 {
			t.Errorf("outcome %+v", out)
		}
		if len(e.upstreamReqs()) != 0 {
			t.Error("reached upstream")
		}
	})
	t.Run("key source generic error", func(t *testing.T) {
		e := newEnv(t, nil, nil)
		e.keys.err = errors.New("vault says " + realKeys["e-anthropic"])
		req := e.newReq("POST", "/anthropic/v1/messages", chatBody)
		req.Header.Set("x-api-key", passTok)
		resp, _ := e.do(req)
		if resp.StatusCode != 500 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if out := e.gate.ticket(t).wait(t); out.Sent {
			t.Error("Sent=true without upstream")
		}
	})
}

func TestBodyLimitAndMalformed(t *testing.T) {
	e := newEnv(t, nil, func(c *Config) { c.BodyLimit = 64 })
	req := e.newReq("POST", "/anthropic/v1/messages", `{"model":"m","pad":"`+strings.Repeat("x", 1000)+`"}`)
	req.Header.Set("x-api-key", passTok)
	resp, _ := e.do(req)
	if resp.StatusCode != 413 || resp.Header.Get(ReasonHeader) != ReasonBodyTooLarge {
		t.Fatalf("status %d reason %q", resp.StatusCode, resp.Header.Get(ReasonHeader))
	}
	req = e.newReq("POST", "/anthropic/v1/messages", `{"model":`)
	req.Header.Set("x-api-key", passTok)
	resp, _ = e.do(req)
	if resp.StatusCode != 400 || resp.Header.Get(ReasonHeader) != ReasonBadRequest {
		t.Fatalf("malformed: status %d", resp.StatusCode)
	}
	if e.gate.admitted() != 0 || len(e.upstreamReqs()) != 0 {
		t.Error("rejected body reached gate/upstream")
	}
}

func TestFreeEndpointGET(t *testing.T) {
	e := newEnv(t, nil, nil)
	req := e.newReq("GET", "/openai/v1/models", "")
	req.Header.Set("Authorization", "Bearer "+passTok)
	resp, _ := e.do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	u := e.upstreamReqs()[0]
	if u.Method != "GET" || len(u.Body) != 0 {
		t.Errorf("upstream %s body %d", u.Method, len(u.Body))
	}
	e.gate.ticket(t).wait(t)
}

func TestErrorShapes(t *testing.T) {
	cases := []struct {
		prov  string
		check func(map[string]any) bool
	}{
		{"anthropic", func(m map[string]any) bool {
			e, _ := m["error"].(map[string]any)
			return m["type"] == "error" && e["type"] == "permission_error" && e["message"] != ""
		}},
		{"openai", func(m map[string]any) bool {
			e, _ := m["error"].(map[string]any)
			return e["code"] == ReasonBudgetExceeded && e["type"] != nil && e["message"] != ""
		}},
		{"openrouter", func(m map[string]any) bool {
			e, _ := m["error"].(map[string]any)
			return e["code"] == ReasonBudgetExceeded
		}},
		{"gemini", func(m map[string]any) bool {
			e, _ := m["error"].(map[string]any)
			return e["code"] == float64(403) && e["status"] == "PERMISSION_DENIED"
		}},
		{"", func(m map[string]any) bool {
			e, _ := m["error"].(map[string]any)
			return e["type"] == ReasonBudgetExceeded
		}},
	}
	for _, tc := range cases {
		var p *provider.Provider
		if tc.prov != "" {
			p, _ = provider.Get(tc.prov)
		}
		rec := httptest.NewRecorder()
		writeError(rec, p, &Denial{Status: 403, Reason: ReasonBudgetExceeded, Message: "limit day $20\x1b[31m"})
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("%s: %v", tc.prov, err)
		}
		if rec.Code != 403 || rec.Header().Get(ReasonHeader) != ReasonBudgetExceeded || !tc.check(m) {
			t.Errorf("%s: bad shape %s", tc.prov, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "\x1b") {
			t.Errorf("%s: control char in message", tc.prov)
		}
	}
	d := &Denial{Status: 999, Reason: ReasonLocked}
	if d.status() != 403 || !strings.Contains(d.Error(), "keyleash unlock") {
		t.Errorf("denial fallback: %d %q", d.status(), d.Error())
	}
}

func TestSplitQuery(t *testing.T) {
	cases := []struct {
		in, fwd string
		keys    []string
		err     bool
	}{
		{"", "", nil, false},
		{"alt=sse", "alt=sse", nil, false},
		{"key=abc&alt=sse", "alt=sse", []string{"abc"}, false},
		{"alt=sse&k%65y=abc", "alt=sse", []string{"abc"}, false},
		{"KEY=abc", "", []string{"abc"}, false},
		{"%24alt=json%3Benum-encoding%3Dint&key=a", "%24alt=json%3Benum-encoding%3Dint", []string{"a"}, false},
		{"a=1;key=x", "", nil, true},
		{"a=%zz", "", nil, true},
		{"a=1 2", "", nil, true},
	}
	for _, tc := range cases {
		fwd, keys, err := splitQuery(tc.in)
		if (err != nil) != tc.err || fwd != tc.fwd || fmt.Sprint(keys) != fmt.Sprint(tc.keys) {
			t.Errorf("%q: got %q %v %v", tc.in, fwd, keys, err)
		}
	}
}

func TestOutboundHeaderFilter(t *testing.T) {
	in := http.Header{
		"Connection":        {"keep-alive, X-A"},
		"X-A":               {"1"},
		"Keep-Alive":        {"timeout=5"},
		"Proxy-Foo":         {"x"},
		"Transfer-Encoding": {"chunked"},
		"Upgrade":           {"h2c"},
		"Trailer":           {"X-T"},
		"X-Goog-Api-Key":    {"k"},
		"Host":              {"evil"},
		"Origin":            {"x"},
		"X-Keyleash-Reason": {"x"},
		"Content-Type":      {"application/json"},
		"Anthropic-Beta":    {"b"},
		"Http-Referer":      {"https://app.example"},
	}
	out := outboundHeader(in)
	want := map[string]bool{"Content-Type": true, "Anthropic-Beta": true, "Http-Referer": true, "Accept-Encoding": true}
	for k := range out {
		if !want[k] {
			t.Errorf("header %s forwarded", k)
		}
	}
	for k := range want {
		if out.Get(k) == "" {
			t.Errorf("header %s dropped", k)
		}
	}
}

func TestNewValidation(t *testing.T) {
	ok := func(c Config) error {
		_, err := New(c, &fakeAuth{}, &fakeGate{}, &fakeKeys{}, &fakeMeter{}, nil)
		return err
	}
	if err := ok(Config{}); err != nil {
		t.Errorf("default config: %v", err)
	}
	for _, addr := range []string{"0.0.0.0:47114", "192.168.1.1:1", "localhost:47114", ":47114"} {
		if ok(Config{Addr: addr}) == nil {
			t.Errorf("%s accepted", addr)
		}
	}
	if ok(Config{Addr: "[::1]:47114"}) != nil {
		t.Error("[::1] rejected")
	}
	if _, err := New(Config{}, nil, &fakeGate{}, &fakeKeys{}, &fakeMeter{}, nil); err == nil {
		t.Error("nil authenticator accepted")
	}
}

func TestServeLifecycle(t *testing.T) {
	srv, err := New(Config{Addr: "127.0.0.1:0"}, &fakeAuth{}, &fakeGate{}, &fakeKeys{}, &fakeMeter{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx, ln) }()
	addr := ln.Addr().String()
	deadline := time.Now().Add(3 * time.Second)
	for srv.Addr() != addr && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Get("http://" + addr + "/nope/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("status %d", resp.StatusCode)
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestServeRejectsNonLoopbackListener(t *testing.T) {
	srv, _ := New(Config{}, &fakeAuth{}, &fakeGate{}, &fakeKeys{}, &fakeMeter{}, nil)
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Skip("cannot listen on all interfaces:", err)
	}
	if err := srv.Serve(context.Background(), ln); err == nil {
		t.Fatal("Serve accepted a non-loopback listener")
	}
}

func TestPeerResolverUsed(t *testing.T) {
	e := newEnv(t, nil, nil)
	var called atomic.Bool
	e.srv.peers = func(local, remote netip.AddrPort) ClientInfo {
		called.Store(local.IsValid() && remote.Addr().IsLoopback())
		return ClientInfo{PID: 42, Image: "agent.exe"}
	}
	req := e.newReq("POST", "/anthropic/v1/messages", chatBody)
	req.Header.Set("x-api-key", passTok)
	e.do(req)
	if !called.Load() {
		t.Fatal("peer resolver not called with valid endpoints")
	}
	e.gate.mu.Lock()
	c := e.gate.adms[0].Client
	e.gate.mu.Unlock()
	if c.PID != 42 || !c.Remote.IsValid() {
		t.Errorf("client info %+v", c)
	}
}
