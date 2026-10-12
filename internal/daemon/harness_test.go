package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/approval"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/proxy"
	"github.com/h-a-forster/keyleash/internal/vault"
)

func TestMain(m *testing.M) {
	restore := vault.SetTestKDFParams()
	code := m.Run()
	restore()
	os.Exit(code)
}

var (
	testPassphrase = []byte("correct horse battery staple")
	anthropicKey   = "sk-ant-api03-REAL-ANTHROPIC-KEY-0123456789abcdef"
	openaiKey      = "sk-proj-REAL-OPENAI-KEY-0123456789abcdefghijkl"
)

// ---- fakes -----------------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 10, 11, 12, 0, 0, 0, time.Local)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fakePresence struct {
	mu     sync.Mutex
	idle   time.Duration
	locked bool
}

func (p *fakePresence) IdleFor() (time.Duration, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.idle, nil
}

func (p *fakePresence) ScreenLocked() (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.locked, nil
}

func (p *fakePresence) set(idle time.Duration, locked bool) {
	p.mu.Lock()
	p.idle, p.locked = idle, locked
	p.mu.Unlock()
}

// switchApprover answers with the current value of approve. Setup step-ups
// (pass_create, key_add) are approved while strictSetup is false, so tests
// that only need a pass or a key do not depend on approve; they are not
// counted in calls.
type switchApprover struct {
	approve     atomic.Bool
	strictSetup atomic.Bool
	calls       atomic.Int32
	mu          sync.Mutex
	reqs        []approval.Request
}

func (a *switchApprover) Approve(ctx context.Context, req approval.Request) (bool, error) {
	a.mu.Lock()
	a.reqs = append(a.reqs, req)
	a.mu.Unlock()
	if !a.strictSetup.Load() && (req.Kind == "pass_create" || req.Kind == "key_add") {
		return true, nil
	}
	a.calls.Add(1)
	return a.approve.Load(), nil
}

// requests returns the requests seen so far.
func (a *switchApprover) requests() []approval.Request {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]approval.Request(nil), a.reqs...)
}

func (a *switchApprover) Method() string { return "test" }

// memListener is an in-memory net.Listener for the admin API.
type memListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newMemListener() *memListener {
	return &memListener{ch: make(chan net.Conn), closed: make(chan struct{})}
}

func (l *memListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *memListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *memListener) Addr() net.Addr { return memAddr{} }

func (l *memListener) Dial(ctx context.Context) (net.Conn, error) {
	a, b := net.Pipe()
	select {
	case l.ch <- b:
		return a, nil
	case <-l.closed:
		return nil, net.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type memAddr struct{}

func (memAddr) Network() string { return "mem" }
func (memAddr) String() string  { return "mem" }

// ---- fake upstream ---------------------------------------------------------

type upstream struct {
	srv    *httptest.Server
	hits   atomic.Int32
	held   chan struct{} // signalled when a held request arrives
	relea  chan struct{} // closed to release held requests
	mu     sync.Mutex
	bodies []string
}

const anthropicJSON = `{"id":"msg_01","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"Hello."}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":12,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":34,"service_tier":"standard"}}`

const anthropicSSE = "event: message_start\n" +
	`data: {"type":"message_start","message":{"id":"msg_02","type":"message","role":"assistant","content":[],"model":"claude-sonnet-4-5","stop_reason":null,"stop_sequence":null,"usage":{"input_tokens":25,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":1}}}` + "\n\n" +
	"event: content_block_start\n" + `data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}` + "\n\n" +
	"event: content_block_delta\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Hi"}}` + "\n\n" +
	"event: content_block_stop\n" + `data: {"type":"content_block_stop","index":0}` + "\n\n" +
	"event: message_delta\n" + `data: {"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":80}}` + "\n\n" +
	"event: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"

const openaiSSE = `data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1694268190,"model":"gpt-5.4-mini","service_tier":"default","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}],"usage":null}` + "\n\n" +
	`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1694268190,"model":"gpt-5.4-mini","service_tier":"default","choices":[{"index":0,"delta":{"content":"Hi."},"finish_reason":"stop"}],"usage":null}` + "\n\n" +
	`data: {"id":"chatcmpl-1","object":"chat.completion.chunk","created":1694268190,"model":"gpt-5.4-mini","service_tier":"default","choices":[],"usage":{"prompt_tokens":40,"completion_tokens":60,"total_tokens":100,"prompt_tokens_details":{"cached_tokens":0},"completion_tokens_details":{"reasoning_tokens":0}}}` + "\n\n" +
	"data: [DONE]\n\n"

func newUpstream(t *testing.T) *upstream {
	u := &upstream{held: make(chan struct{}, 16), relea: make(chan struct{})}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.bodies = append(u.bodies, string(body))
		u.mu.Unlock()
		if r.Header.Get("X-Test-Hold") != "" {
			u.held <- struct{}{}
			<-u.relea
		}
		switch r.URL.Path {
		case "/v1/messages":
			if r.Header.Get("X-Api-Key") != anthropicKey || r.Header.Get("Authorization") != "" {
				w.WriteHeader(401)
				io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
				return
			}
			if bytes.Contains(body, []byte(`"stream":true`)) {
				w.Header().Set("Content-Type", "text/event-stream")
				io.WriteString(w, anthropicSSE)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, anthropicJSON)
		case "/v1/chat/completions":
			if r.Header.Get("Authorization") != "Bearer "+openaiKey {
				w.WriteHeader(401)
				io.WriteString(w, `{"error":{"message":"bad key","type":"invalid_request_error"}}`)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, openaiSSE)
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":[]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(func() {
		select {
		case <-u.relea:
		default:
			close(u.relea)
		}
		u.srv.Close()
	})
	return u
}

// ---- environment -----------------------------------------------------------

type env struct {
	t        *testing.T
	dir      string
	recovery string
	cfg      *config.Config
	clk      *fakeClock
	pres     *fakePresence
	appr     *switchApprover
	up       *upstream
	peerPID  atomic.Int64
	// adminPID is the verified PID the daemon sees for admin calls (default:
	// the parent of the test process, so a run pass bound to the test
	// process does not confine the test's own admin calls); 0 = unknown.
	adminPID atomic.Int64
	approver approval.Approver // overrides appr when set
	// noApprover starts the daemon without Options.Approver, so the
	// configured approval methods are used (console reads consoleIn).
	noApprover bool
	consoleIn  io.Reader
	consoleOut io.Writer
	// jobs stands in for the Windows job objects (the in-process daemon
	// binds run passes to the test process itself).
	jobs    *fakeJobs
	adminLn net.Listener // overrides the in-memory admin listener

	d     *Daemon
	c     *client.Client
	http  *http.Client
	logs  *bytes.Buffer
	logMu sync.Mutex
}

// testConfig returns the recommended profile with test-friendly approvals.
func testConfig(t *testing.T) *config.Config {
	cfg, err := config.Default("recommended")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Approval.Timeout = config.Duration{Duration: 5 * time.Second}
	return cfg
}

func newEnv(t *testing.T, mutate func(*config.Config)) *env {
	t.Helper()
	e := &env{t: t, dir: t.TempDir(), clk: newFakeClock(), pres: &fakePresence{}, appr: &switchApprover{}, jobs: newFakeJobs()}
	e.peerPID.Store(int64(os.Getpid()))
	e.adminPID.Store(int64(os.Getppid()))
	e.cfg = testConfig(t)
	if mutate != nil {
		mutate(e.cfg)
	}
	code, err := Init(e.dir, InitOptions{Method: "passphrase", Passphrase: testPassphrase})
	if err != nil {
		t.Fatal(err)
	}
	e.recovery = code
	e.up = newUpstream(t)
	e.start()
	return e
}

type syncWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (e *env) start() {
	e.t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	admin := newMemListener()
	var adminLn net.Listener = admin
	if e.adminLn != nil {
		adminLn, e.adminLn = e.adminLn, nil
	}
	upURL, _ := url.Parse(e.up.srv.URL)
	if e.logs == nil {
		e.logs = &bytes.Buffer{}
	}
	var appr approval.Approver = e.appr
	if e.approver != nil {
		appr = e.approver
	}
	if e.noApprover {
		appr = nil
	}
	var jobs JobManager
	if e.jobs != nil {
		jobs = e.jobs
	}
	opts := Options{
		DataDir:        e.dir,
		Config:         e.cfg,
		Clock:          e.clk,
		PresenceSource: e.pres,
		Approver:       appr,
		Jobs:           jobs,
		ConsoleIn:      e.consoleIn,
		ConsoleOut:     e.consoleOut,
		HelloAvailable: func() (bool, string) { return false, "test" },
		Upstream:       func(*provider.Provider) *url.URL { u := *upURL; return &u },
		Transport:      e.up.srv.Client().Transport,
		ProxyListener:  ln,
		AdminListener:  adminLn,
		Logger:         slog.New(slog.NewTextHandler(syncWriter{&e.logMu, e.logs}, &slog.HandlerOptions{Level: slog.LevelDebug})),
		AdminPeerPID: func(c net.Conn) (int, error) {
			switch p := int(e.adminPID.Load()); {
			case p > 0:
				return p, nil
			case p == 0:
				return connPeerPID(c) // the real lookup (pipe tests)
			}
			return 0, errors.New("unknown peer")
		},
		PeerResolver: func(local, remote netip.AddrPort) proxy.ClientInfo {
			return proxy.ClientInfo{PID: int(e.peerPID.Load()), Image: `C:\tools\agent.exe`}
		},
		manualPresence:     true,
		manualHousekeeping: true,
	}
	d, err := Start(context.Background(), opts)
	if err != nil {
		e.t.Fatal(err)
	}
	e.d = d
	e.c = client.New(admin.Dial)
	e.http = &http.Client{Transport: &http.Transport{Proxy: nil}}
	e.t.Cleanup(e.stop)
	// Initial presence poll: the owner is active.
	d.stepPresence()
}

func (e *env) stop() {
	if e.d == nil {
		return
	}
	if err := e.d.Close(); err != nil {
		e.t.Errorf("close: %v", err)
	}
	e.c.Close()
	e.http.CloseIdleConnections()
	e.d = nil
}

func (e *env) restart() {
	e.stop()
	e.start()
}

func (e *env) ctx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	e.t.Cleanup(cancel)
	return ctx
}

func (e *env) unlock() {
	e.t.Helper()
	st, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, testPassphrase)
	if err != nil {
		e.t.Fatalf("unlock: %v", err)
	}
	if st.State != client.StateUnlocked {
		e.t.Fatalf("state after unlock = %s (%s)", st.State, st.TripReason)
	}
}

// withOwner runs call, approving any pass_create or key_add step-up it triggers the way
// the owner would: with the vault passphrase over the admin API.
func (e *env) withOwner(call func(ctx context.Context) error) error {
	e.t.Helper()
	ctx := e.ctx()
	done := make(chan error, 1)
	go func() { done <- call(ctx) }()
	decided := map[string]bool{}
	for {
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Millisecond):
		}
		list, err := e.c.Approvals(ctx)
		if err != nil {
			continue
		}
		for _, ap := range list {
			if !decided[ap.ID] && (ap.Kind == "pass_create" || ap.Kind == "key_add") {
				decided[ap.ID] = true
				_ = e.c.Decide(ctx, ap.ID, client.DecideRequest{Approved: true, Secret: append([]byte(nil), testPassphrase...)})
			}
		}
	}
}

func (e *env) addKeys() {
	e.t.Helper()
	for _, k := range [][2]string{{"anthropic", anthropicKey}, {"openai", openaiKey}} {
		if err := e.withOwner(func(ctx context.Context) error {
			_, err := e.c.AddKey(ctx, k[0], "main", []byte(k[1]))
			return err
		}); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) newPass(req client.PassCreateRequest) string {
	e.t.Helper()
	if req.Name == "" {
		req.Name = "test"
	}
	if len(req.Providers) == 0 {
		req.Providers = []string{"*"}
	}
	var r client.PassCreateResponse
	err := e.withOwner(func(ctx context.Context) error {
		var err error
		r, err = e.c.CreatePass(ctx, req)
		return err
	})
	if err != nil {
		e.t.Fatalf("create pass: %v", err)
	}
	return r.Token
}

type result struct {
	status int
	reason string
	body   string
}

func (e *env) post(prov, path, token, body string, hdr ...string) result {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+e.d.ProxyAddr()+"/"+prov+path, strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if prov == "anthropic" {
		req.Header.Set("X-Api-Key", token)
		req.Header.Set("Anthropic-Version", "2023-06-01")
	} else {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := e.http.Do(req)
	if err != nil {
		e.t.Fatalf("proxy request: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return result{status: resp.StatusCode, reason: resp.Header.Get(proxy.ReasonHeader), body: string(b)}
}

const anthropicReq = `{"model":"claude-sonnet-4-5","max_tokens":256,"messages":[{"role":"user","content":"Say hello."}]}`
const anthropicStreamReq = `{"model":"claude-sonnet-4-5","max_tokens":256,"stream":true,"messages":[{"role":"user","content":"Say hi."}]}`
const openaiStreamReq = `{"model":"gpt-5.4-mini","max_completion_tokens":200,"stream":true,"messages":[{"role":"user","content":"Say hi."}]}`

func (e *env) anthropic(token string, hdr ...string) result {
	return e.post("anthropic", "/v1/messages", token, anthropicReq, hdr...)
}

// expectedCost prices a response body exactly as the daemon does.
func (e *env) expectedCost(prov, path, reqBody, respBody string) money.Micros {
	e.t.Helper()
	p, _ := provider.Get(prov)
	ep, ok := p.Match(http.MethodPost, path)
	if !ok {
		e.t.Fatal("no endpoint")
	}
	info, err := e.d.meter.Inspect(p, ep, path, []byte(reqBody))
	if err != nil {
		e.t.Fatal(err)
	}
	up := e.d.meter.NewProviderUsageParser(prov, ep, info.Stream)
	up.Write([]byte(respBody))
	u, ok := up.Final()
	if !ok {
		e.t.Fatal("fixture usage not parsed")
	}
	if u.Model == "" {
		u.Model = info.Model
	}
	c, priced := e.d.meter.Cost(prov, u)
	if !priced {
		e.t.Fatal("fixture not priced")
	}
	return c
}

func (e *env) estimate(prov, path, reqBody string) money.Micros {
	e.t.Helper()
	p, _ := provider.Get(prov)
	ep, _ := p.Match(http.MethodPost, path)
	info, err := e.d.meter.Inspect(p, ep, path, []byte(reqBody))
	if err != nil {
		e.t.Fatal(err)
	}
	c, ok := e.d.meter.Estimate(prov, info)
	if !ok {
		e.t.Fatal("not priced")
	}
	return c
}

func (e *env) status() client.Status {
	e.t.Helper()
	s, err := e.c.Status(e.ctx())
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func limitSettled(s client.Status, scope, window string) (money.Micros, bool) {
	for _, l := range s.Limits {
		if l.Scope == scope && l.Window == window {
			return l.Settled, true
		}
	}
	return 0, false
}

func (e *env) logText() string {
	e.logMu.Lock()
	defer e.logMu.Unlock()
	return e.logs.String()
}

// assertNoSecrets checks that no secret ever reached logs or audit records.
func (e *env) assertNoSecrets(extra ...string) {
	e.t.Helper()
	secrets := append([]string{anthropicKey, openaiKey, string(testPassphrase), e.recovery}, extra...)
	recs, err := e.c.AuditTail(e.ctx(), 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	raw, _ := json.Marshal(recs)
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(e.logText(), s) {
			e.t.Errorf("secret leaked into logs")
		}
		if bytes.Contains(raw, []byte(s)) {
			e.t.Errorf("secret leaked into audit")
		}
	}
}

// tripBySpend sends one request that settles over a tiny tripwire threshold
// (the tripwire counts settled spend only), then waits until the next
// request is refused as tripped.
func (e *env) tripBySpend(tok string) {
	e.t.Helper()
	wantReason(e.t, e.anthropic(tok), 200, "")
	for i := 0; i < 100; i++ {
		r := e.anthropic(tok)
		if r.status == 423 {
			wantReason(e.t, r, 423, proxy.ReasonTripped)
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatal("tripwire did not fire after settled spend")
}

func wantReason(t *testing.T, r result, status int, reason string) {
	t.Helper()
	if r.status != status || r.reason != reason {
		t.Fatalf("got %d %q (%s), want %d %q", r.status, r.reason, r.body, status, reason)
	}
}

func isAPI(err error, status int, code string) bool {
	var ae *client.APIError
	return errors.As(err, &ae) && ae.Status == status && ae.Code == code
}

// blockingApprover never decides; it waits for cancellation.
type blockingApprover struct{}

func (blockingApprover) Approve(ctx context.Context, _ approval.Request) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
}

// helloLike reports method "hello" (the Windows Hello approver's name).
type helloLike struct{}

func (helloLike) Approve(ctx context.Context, _ approval.Request) (bool, error) { return false, nil }
func (helloLike) Method() string                                                { return "hello" }

type netConn = net.Conn

// waitPending waits for a pending approval of kind and returns its id.
func (e *env) waitPending(kind string) string {
	e.t.Helper()
	for i := 0; i < 500; i++ {
		list, _ := e.c.Approvals(e.ctx())
		for _, ap := range list {
			if ap.Kind == kind {
				return ap.ID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	e.t.Fatalf("no pending %s approval", kind)
	return ""
}

// ownerSecret is the passphrase as a fresh slice (Decide wipes its copy).
func ownerSecret() []byte { return append([]byte(nil), testPassphrase...) }

// setAdminPID changes the PID the daemon sees for admin calls. The PID is
// fixed per connection (as with a real pipe), so idle connections are
// dropped first.
func (e *env) setAdminPID(pid int) {
	e.c.Close()
	e.adminPID.Store(int64(pid))
}

// fakeJobs is a JobManager for the in-process tests: a job's members are
// its bound process plus pids added with add (processes that outlive their
// pass); a released job is dropped once none of the added pids is alive.
type fakeJobs struct {
	mu       sync.Mutex
	members  map[string]map[int]bool
	extra    map[string]map[int]bool
	dead     map[int]bool
	fail     error
	confined []string
	closed   bool
}

func newFakeJobs() *fakeJobs {
	return &fakeJobs{members: map[string]map[int]bool{}, extra: map[string]map[int]bool{}, dead: map[int]bool{}}
}

func (j *fakeJobs) Confine(id string, pid int, _ int64) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.fail != nil {
		return j.fail
	}
	j.members[id] = map[int]bool{pid: true}
	j.extra[id] = map[int]bool{}
	j.confined = append(j.confined, id)
	return nil
}

// add makes pid a member of job id (a descendant the job caught).
func (j *fakeJobs) add(id string, pid int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.members[id][pid] = true
	j.extra[id][pid] = true
}

func (j *fakeJobs) kill(pid int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.dead[pid] = true
}

func (j *fakeJobs) Member(id string, pid int) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	m, ok := j.members[id]
	if !ok {
		return false, errors.New("no job")
	}
	return m[pid] && !j.dead[pid], nil
}

func (j *fakeJobs) MemberOfAny(pid int) (bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for _, m := range j.members {
		if m[pid] && !j.dead[pid] {
			return true, nil
		}
	}
	return false, nil
}

func (j *fakeJobs) Sweep(active func(string) bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	for id := range j.members {
		if active(id) {
			continue
		}
		alive := false
		for pid := range j.extra[id] {
			alive = alive || !j.dead[pid]
		}
		if !alive {
			delete(j.members, id)
			delete(j.extra, id)
		}
	}
}

func (j *fakeJobs) Close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.closed = true
	j.members = map[string]map[int]bool{}
	j.extra = map[string]map[int]bool{}
}

func (j *fakeJobs) held() int {
	j.mu.Lock()
	defer j.mu.Unlock()
	return len(j.members)
}
