// Package proxy is keyleash's loopback reverse proxy (spec §10).
//
// The proxy is mechanical: it checks that a request comes from this machine,
// routes it to a provider from the registry, enforces the endpoint allowlist,
// swaps the client's pass for the real provider key and streams the response
// back while feeding a usage parser. Every policy decision (is the pass valid,
// may this request spend money, is the vault unlocked) is delegated to
// interfaces the daemon implements: Authenticator, Gate, KeySource and Meter.
package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/h-a-forster/keyleash/internal/meter"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// Defaults applied by New when the corresponding Config field is zero.
const (
	DefaultAddr                  = "127.0.0.1:47114"
	DefaultBodyLimit             = 32 << 20
	DefaultResponseHeaderTimeout = 10 * time.Minute
	DefaultStreamIdleTimeout     = 5 * time.Minute

	dialTimeout       = 10 * time.Second
	tlsTimeout        = 10 * time.Second
	readHeaderTimeout = 10 * time.Second
	bodyReadTimeout   = 2 * time.Minute
	shutdownGrace     = 5 * time.Second
)

// ClientInfo identifies the local process that sent a request.
type ClientInfo struct {
	PID    int
	Image  string
	Remote netip.AddrPort
}

// PeerResolver maps a TCP connection (proxy-side local endpoint, client-side
// remote endpoint) to the owning client process. It must not block for long.
// A nil resolver yields ClientInfo{Remote: remote}.
type PeerResolver func(local, remote netip.AddrPort) ClientInfo

// Principal is who a request acts for once its pass is verified.
type Principal struct {
	PassID, PassName string
	// EntryID is the vault entry holding this provider's key.
	EntryID string
}

// Authenticator verifies the pass a client presented for a provider. It
// returns a *Denial for refusals (invalid/expired pass, locked daemon); any
// other error is reported to the client as an invalid pass.
type Authenticator interface {
	Authenticate(ctx context.Context, provider string, token string, client ClientInfo) (Principal, error)
}

// Meter inspects requests and builds response usage parsers. It is satisfied
// by an adapter over *meter.Meter (NewUsageParser maps to
// meter.NewProviderUsageParser with p.Name).
type Meter interface {
	Inspect(p *provider.Provider, ep provider.Endpoint, path string, body []byte) (meter.RequestInfo, error)
	PrepareBody(ep provider.Endpoint, body []byte, info meter.RequestInfo) ([]byte, error)
	NewUsageParser(p *provider.Provider, ep provider.Endpoint, stream bool) meter.UsageParser
}

// headerObserver is optionally implemented by usage parsers that need the
// upstream response headers (e.g. Gemini's service tier header).
type headerObserver interface {
	ObserveResponseHeader(h http.Header)
}

// Admission is what the Gate decides on.
type Admission struct {
	Principal Principal
	Provider  *provider.Provider
	Endpoint  provider.Endpoint
	Info      meter.RequestInfo
	Client    ClientInfo
	RequestID string
}

// Outcome reports how an admitted request ended.
type Outcome struct {
	// Status is the upstream status, or the status keyleash returned when the
	// request never got an upstream response.
	Status int
	Usage  meter.Usage
	// UsageOK is true only when the parser found usage AND the body was
	// relayed completely. Otherwise the gate should charge the reservation.
	UsageOK       bool
	UpstreamErr   error
	Latency       time.Duration
	BytesOut      int64
	ClientAborted bool
	// Sent is true when the request may have reached upstream (a connection
	// was obtained for it). False means it certainly did not, so the gate can
	// release rather than settle.
	Sent bool
}

// Ticket is an admitted request. Finish is called exactly once.
type Ticket interface {
	Finish(o Outcome)
}

// Gate admits or refuses a request (budget, policy, approval). Admit may
// block, e.g. waiting for step-up approval. Policy refusals are *Denial.
type Gate interface {
	Admit(ctx context.Context, a Admission) (Ticket, error)
}

// KeySource lends the provider key for a vault entry for the duration of fn.
// fn must not retain key. Returning a *Denial (e.g. locked) passes its status
// to the client; other errors become a generic 500.
type KeySource interface {
	WithKey(entryID string, fn func(key []byte) error) error
}

// Config configures a Server. Zero fields take the documented defaults.
type Config struct {
	// Addr is the listen address; its host must be a loopback IP.
	Addr string
	// BodyLimit caps request bodies (default 32 MiB); larger → 413.
	BodyLimit int64
	// AllowedOrigins lists exact Origin values (e.g. "http://localhost:3000")
	// that may call the proxy. Requests with any other Origin are refused.
	AllowedOrigins []string
	// Upstream returns the base URL for a provider. Default: https://<Host>.
	Upstream func(p *provider.Provider) *url.URL
	// Transport is the upstream round tripper. Default: hardened transport
	// (TLS ≥ 1.2, system roots, HTTP/2, no environment proxy).
	Transport http.RoundTripper
	// ResponseHeaderTimeout bounds the wait for upstream response headers
	// (default 10m). StreamIdleTimeout bounds the gap between body reads
	// (default 5m). Both are enforced by the proxy itself, whatever Transport is.
	ResponseHeaderTimeout, StreamIdleTimeout time.Duration
	// Now is the clock used for latency (default time.Now).
	Now func() time.Time
	// ErrorLog receives operational messages (never secrets) and is used as
	// the http.Server error log. Default: discard.
	ErrorLog *log.Logger
}

// Server is the loopback proxy.
type Server struct {
	cfg     Config
	auth    Authenticator
	gate    Gate
	keys    KeySource
	meter   Meter
	peers   PeerResolver
	client  *http.Client
	origins map[string]bool
	cfgPort uint16

	mu    sync.Mutex
	bound string
}

// New validates cfg and returns a Server. auth, gate, keys and m are required;
// peers is optional.
func New(cfg Config, auth Authenticator, gate Gate, keys KeySource, m Meter, peers PeerResolver) (*Server, error) {
	if auth == nil || gate == nil || keys == nil || m == nil {
		return nil, errors.New("proxy: authenticator, gate, key source and meter are required")
	}
	if cfg.Addr == "" {
		cfg.Addr = DefaultAddr
	}
	ap, err := netip.ParseAddrPort(cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: listen address %q must be ip:port", cfg.Addr)
	}
	if !ap.Addr().Unmap().IsLoopback() {
		return nil, fmt.Errorf("proxy: listen address %q is not loopback", cfg.Addr)
	}
	if cfg.BodyLimit <= 0 {
		cfg.BodyLimit = DefaultBodyLimit
	}
	if cfg.Upstream == nil {
		cfg.Upstream = defaultUpstream
	}
	if cfg.Transport == nil {
		cfg.Transport = NewTransport(cfg.ResponseHeaderTimeout)
	}
	if cfg.ResponseHeaderTimeout <= 0 {
		cfg.ResponseHeaderTimeout = DefaultResponseHeaderTimeout
	}
	if cfg.StreamIdleTimeout <= 0 {
		cfg.StreamIdleTimeout = DefaultStreamIdleTimeout
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.ErrorLog == nil {
		cfg.ErrorLog = log.New(discard{}, "", 0)
	}
	origins := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		origins[o] = true
	}
	s := &Server{
		cfg: cfg, auth: auth, gate: gate, keys: keys, meter: m, peers: peers,
		origins: origins, cfgPort: ap.Port(),
		client: &http.Client{
			Transport: cfg.Transport,
			// Never follow redirects: the 3xx goes back to the client and the
			// key is never sent to another host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	return s, nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func defaultUpstream(p *provider.Provider) *url.URL {
	return &url.URL{Scheme: "https", Host: p.Host}
}

// NewTransport returns the hardened upstream transport: TLS 1.2+, system
// roots with verification, HTTP/2, environment proxies ignored, 10 s dial and
// TLS handshake timeouts, no transparent compression.
func NewTransport(responseHeaderTimeout time.Duration) *http.Transport {
	if responseHeaderTimeout <= 0 {
		responseHeaderTimeout = DefaultResponseHeaderTimeout
	}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    tlsTimeout,
		ForceAttemptHTTP2:      true,
		ResponseHeaderTimeout:  responseHeaderTimeout,
		DisableCompression:     true,
		MaxIdleConns:           32,
		MaxIdleConnsPerHost:    8,
		IdleConnTimeout:        90 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 1 << 20,
	}
}

// Handler returns the proxy's HTTP handler.
func (s *Server) Handler() http.Handler { return http.HandlerFunc(s.serveHTTP) }

// Addr returns the bound address once serving, else the configured address.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bound != "" {
		return s.bound
	}
	return s.cfg.Addr
}

// ListenAndServe listens on Config.Addr and serves until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("proxy: listen: %w", err)
	}
	return s.Serve(ctx, ln)
}

// Serve serves on ln until ctx is done, then shuts down (in-flight requests
// get a short grace period). ln must be bound to a loopback address. A nil
// return means a clean shutdown.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	ap, err := netip.ParseAddrPort(ln.Addr().String())
	if err != nil || !ap.Addr().Unmap().IsLoopback() {
		ln.Close()
		return errors.New("proxy: refusing to serve on a non-loopback listener")
	}
	s.mu.Lock()
	s.bound = ln.Addr().String()
	s.mu.Unlock()

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: readHeaderTimeout,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          s.cfg.ErrorLog,
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil {
			srv.Close()
		}
		<-errc
		return nil
	}
}
