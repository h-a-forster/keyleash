package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/approval"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/daemon"
	"github.com/h-a-forster/keyleash/internal/provider"
	"github.com/h-a-forster/keyleash/internal/vault"
)

const testPassphrase = "correct horse battery staple"

// Realistic upstream responses (usage is what the meter prices).
const (
	anthropicResponse = `{"id":"msg_01","type":"message","role":"assistant","model":"claude-sonnet-4-5","content":[{"type":"text","text":"Hello."}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":12,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":34,"service_tier":"standard"}}`
	anthropicRequest  = `{"model":"claude-sonnet-4-5","max_tokens":64,"messages":[{"role":"user","content":"hi"}]}`
)

// fakePresence reports an owner who is always at the keyboard.
type fakePresence struct{}

func (fakePresence) IdleFor() (time.Duration, error) { return 0, nil }
func (fakePresence) ScreenLocked() (bool, error)     { return false, nil }

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// testDaemon is an in-process daemon with a fake TLS upstream that accepts
// only fakeAnthropicKey.
type testDaemon struct {
	t         *testing.T
	dir       string
	d         *daemon.Daemon
	adminAddr string // "" when the default admin pipe/socket is used
	logs      *syncBuffer
	upHits    atomic.Int32
}

// startTestDaemon initialises a vault (cheap KDF) and starts a daemon.
// With tcpAdmin the admin API listens on a loopback TCP port (so tests do
// not touch the per-user pipe); otherwise the default admin channel is used.
func startTestDaemon(t *testing.T, tcpAdmin bool) *testDaemon {
	t.Helper()
	restore := vault.SetTestKDFParams()
	t.Cleanup(restore)
	td := &testDaemon{t: t, dir: t.TempDir(), logs: &syncBuffer{}}
	if _, err := daemon.Init(td.dir, daemon.InitOptions{Method: "passphrase", Passphrase: []byte(testPassphrase)}); err != nil {
		t.Fatal(err)
	}
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		td.upHits.Add(1)
		io.Copy(io.Discard, r.Body)
		if r.URL.Path != "/v1/messages" || r.Header.Get("X-Api-Key") != fakeAnthropicKey || r.Header.Get("Authorization") != "" {
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, anthropicResponse)
	}))
	t.Cleanup(up.Close)
	upURL, _ := url.Parse(up.URL)

	cfg, err := config.Default("recommended")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Approval.Timeout = config.Duration{Duration: 5 * time.Second}
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	opts := daemon.Options{
		DataDir:        td.dir,
		Config:         cfg,
		PresenceSource: fakePresence{},
		Approver:       approval.DenyApprover{},
		HelloAvailable: func() (bool, string) { return false, "test" },
		Upstream:       func(*provider.Provider) *url.URL { u := *upURL; return &u },
		Transport:      up.Client().Transport,
		ProxyListener:  proxyLn,
		Logger:         slog.New(slog.NewTextHandler(td.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
	if tcpAdmin {
		adminLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		opts.AdminListener = adminLn
		td.adminAddr = adminLn.Addr().String()
	}
	d, err := daemon.Start(context.Background(), opts)
	if err != nil {
		if !tcpAdmin {
			proxyLn.Close()
			t.Skipf("cannot start a daemon on the default admin channel (is a real keyleash daemon running?): %v", err)
		}
		t.Fatal(err)
	}
	td.d = d
	t.Cleanup(func() { d.Close() })
	return td
}

// client returns an admin client for the daemon.
func (td *testDaemon) client() *client.Client {
	if td.adminAddr == "" {
		c, err := client.Dial(td.dir)
		if err != nil {
			td.t.Fatal(err)
		}
		return c
	}
	addr := td.adminAddr
	return client.New(func(ctx context.Context) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	})
}

// app returns a CLI app wired to the daemon, with stdin and environment.
func (td *testDaemon) app(stdin string, environ ...string) (*app, *bytes.Buffer, *bytes.Buffer) {
	a, out, errb := newTestApp(stdin)
	dir := td.dir
	a.getenv = func(k string) string {
		if k == "KEYLEASH_HOME" {
			return dir
		}
		for _, kv := range environ {
			if name, v, _ := strings.Cut(kv, "="); name == k {
				return v
			}
		}
		return ""
	}
	a.environ = func() []string { return append([]string(nil), environ...) }
	a.dial = func() (*client.Client, error) { return td.client(), nil }
	return a, out, errb
}

// run executes the CLI and returns exit code, stdout and stderr.
func (td *testDaemon) run(stdin string, args ...string) (int, string, string) {
	td.t.Helper()
	a, out, errb := td.app(stdin)
	code := a.main(args)
	return code, out.String(), errb.String()
}

// callProxy sends one Anthropic request with token and returns the status.
func callProxy(t *testing.T, proxyAddr, token string) int {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+proxyAddr+"/anthropic/v1/messages", strings.NewReader(anthropicRequest))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-api-key", token)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp.StatusCode
}
