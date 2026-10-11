package client

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// pipeListener serves HTTP over net.Pipe connections.
type pipeListener struct {
	ch     chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *pipeListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *pipeListener) Addr() net.Addr { return &net.UnixAddr{Name: "pipe", Net: "unix"} }
func (l *pipeListener) dial(ctx context.Context) (net.Conn, error) {
	a, b := net.Pipe()
	select {
	case l.ch <- b:
		return a, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func serve(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	l := &pipeListener{ch: make(chan net.Conn), closed: make(chan struct{})}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	c := New(l.dial)
	t.Cleanup(c.Close)
	return c
}

func TestAPIErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		code   string
	}{
		{"structured", 401, `{"error":{"code":"wrong_secret","message":"wrong secret"}}`, CodeWrongSecret},
		{"unstructured", 500, `oops`, CodeInternal},
		{"empty", 423, ``, CodeInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := serve(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			})
			_, err := c.Status(t.Context())
			var ae *APIError
			if !asAPI(err, &ae) || ae.Status != tc.status || ae.Code != tc.code || !IsCode(err, tc.code) {
				t.Fatalf("err = %#v", err)
			}
		})
	}
}

func asAPI(err error, target **APIError) bool {
	ae, ok := err.(*APIError)
	if ok {
		*target = ae
	}
	return ok
}

func TestUnlockSendsSecretOnlyInBody(t *testing.T) {
	secret := []byte("hunter2-hunter2")
	var got UnlockRequest
	var gotURL string
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		json.NewDecoder(r.Body).Decode(&got)
		io.WriteString(w, `{"state":"unlocked","limits":[],"in_flight":[],"vault":{"slots":[]}}`)
	})
	st, err := c.Unlock(t.Context(), MethodPassphrase, secret)
	if err != nil || st.State != StateUnlocked {
		t.Fatalf("unlock: %v", err)
	}
	if string(got.Secret) != string(secret) || got.Method != MethodPassphrase {
		t.Fatalf("server got %+v", got)
	}
	if strings.Contains(gotURL, "hunter2") {
		t.Fatal("secret in URL")
	}
	if string(secret) != "hunter2-hunter2" {
		t.Fatal("caller's secret modified")
	}
}

func TestQueryEncoding(t *testing.T) {
	var q string
	c := serve(t, func(w http.ResponseWriter, r *http.Request) {
		q = r.URL.RawQuery
		io.WriteString(w, `{"by":"pass","rows":[]}`)
	})
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if _, err := c.Usage(t.Context(), "pass", since); err != nil {
		t.Fatal(err)
	}
	if q != "by=pass&since=2026-10-01T00%3A00%3A00Z" {
		t.Fatalf("query = %q", q)
	}
}

func TestUnreachableDaemon(t *testing.T) {
	c := New(func(context.Context) (net.Conn, error) { return nil, net.ErrClosed })
	if _, err := c.Status(t.Context()); err == nil || !strings.Contains(err.Error(), "cannot reach") {
		t.Fatalf("err = %v", err)
	}
}
