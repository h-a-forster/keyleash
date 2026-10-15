// Package client is the typed Go client for the keyleash daemon's admin
// channel (docs/DAEMON.md "Admin channel"), and holds the request and
// response types shared by the daemon and the CLI.
//
// The channel is HTTP/1.1 + JSON over an OS-protected local transport: on
// Windows the named pipe \\.\pipe\keyleash-<user SID>, whose security
// descriptor grants access only to the current user; elsewhere the Unix
// socket <data dir>/admin.sock (mode 0600 in a 0700 directory). Requests carry
// no credential: access control is the OS ACL. On Windows the client also
// checks that the pipe is owned by the current user before sending anything,
// so a pipe pre-created by another account cannot capture a passphrase.
//
// Secrets (passphrases, recovery codes, provider keys) travel only in
// request bodies; the client wipes its copy of the encoded body after the
// request has been sent.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/h-a-forster/keyleash/internal/secmem"
)

// MaxResponseSize caps an admin response body.
const MaxResponseSize = 8 << 20

// APIError is a non-2xx admin response.
type APIError struct {
	Status  int
	Code    string
	Message string
}

// Error implements error.
func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("keyleash daemon: %s (HTTP %d)", e.Code, e.Status)
	}
	return fmt.Sprintf("keyleash daemon: %s: %s", e.Code, e.Message)
}

// IsCode reports whether err is an *APIError with the given code.
func IsCode(err error, code string) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Code == code
}

// Client talks to one daemon. It is safe for concurrent use.
type Client struct {
	hc *http.Client
}

// DialFunc opens one connection to the daemon's admin channel.
type DialFunc func(ctx context.Context) (net.Conn, error)

// New returns a client that opens connections with dial. Tests use it with
// an in-memory listener; the CLI uses Dial.
func New(dial DialFunc) *Client {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dial(ctx)
		},
		MaxIdleConns:           2,
		IdleConnTimeout:        30 * time.Second,
		DisableCompression:     true,
		ForceAttemptHTTP2:      false,
		MaxResponseHeaderBytes: 64 << 10,
	}
	return &Client{hc: &http.Client{Transport: tr}}
}

// Dial returns a client for the daemon serving dataDir (see the package doc
// for the transport). It does not connect until the first call.
func Dial(dataDir string) (*Client, error) {
	d, err := adminDialer(dataDir)
	if err != nil {
		return nil, err
	}
	return New(d), nil
}

// Close releases idle connections.
func (c *Client) Close() { c.hc.CloseIdleConnections() }

// do sends a JSON request and decodes a JSON response into out (if non-nil).
// The encoded request body is wiped after the request completes.
func (c *Client) do(ctx context.Context, method, path string, q url.Values, in, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return fmt.Errorf("keyleash client: encode request: %w", err)
		}
	}
	defer secmem.Wipe(body)
	u := "http://keyleash" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader = http.NoBody
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return fmt.Errorf("keyleash client: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("keyleash client: cannot reach the daemon (is `keyleash daemon` running?): %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return fmt.Errorf("keyleash client: read response: %w", err)
	}
	defer secmem.Wipe(raw)
	if len(raw) > MaxResponseSize {
		return errors.New("keyleash client: response too large")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var eb ErrorBody
		ae := &APIError{Status: resp.StatusCode, Code: CodeInternal}
		if json.Unmarshal(raw, &eb) == nil && eb.Error.Code != "" {
			ae.Code, ae.Message = eb.Error.Code, eb.Error.Message
		}
		return ae
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("keyleash client: decode response: %w", err)
	}
	return nil
}

// Status returns the daemon status.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodGet, "/v1/status", nil, nil, &s)
	return s, err
}

// Unlock unlocks the vault. secret (passphrase or recovery code) may be nil
// for hello and dpapi; the caller still owns and should wipe it.
func (c *Client) Unlock(ctx context.Context, method string, secret []byte) (Status, error) {
	return c.UnlockWith(ctx, UnlockRequest{Method: method}, secret)
}

// UnlockWith is Unlock with every UnlockRequest option (e.g.
// AcceptRollback); req.Secret is ignored in favour of secret.
func (c *Client) UnlockWith(ctx context.Context, req UnlockRequest, secret []byte) (Status, error) {
	var s Status
	req.Secret = nil
	if len(secret) > 0 {
		req.Secret = append([]byte(nil), secret...)
		defer secmem.Wipe(req.Secret)
	}
	err := c.do(ctx, http.MethodPost, "/v1/unlock", nil, req, &s)
	return s, err
}

// Lock locks the daemon.
func (c *Client) Lock(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodPost, "/v1/lock", nil, struct{}{}, &s)
	return s, err
}

// Shutdown asks the daemon to stop gracefully. It returns once the daemon
// has accepted the request; the shutdown itself continues after that.
func (c *Client) Shutdown(ctx context.Context) error {
	var r ShutdownResponse
	return c.do(ctx, http.MethodPost, "/v1/shutdown", nil, struct{}{}, &r)
}

// Panic locks the daemon and revokes every pass.
func (c *Client) Panic(ctx context.Context, revokeUpstream bool) (PanicSummary, error) {
	var s PanicSummary
	err := c.do(ctx, http.MethodPost, "/v1/panic", nil, PanicRequest{RevokeUpstream: revokeUpstream}, &s)
	return s, err
}

// Away starts an unattended grant (step-up; blocks until approved).
func (c *Client) Away(ctx context.Context, req AwayRequest) (Grant, error) {
	var g Grant
	err := c.do(ctx, http.MethodPost, "/v1/away", nil, req, &g)
	return g, err
}

// Resume leaves the Tripped state (step-up; blocks until approved).
func (c *Client) Resume(ctx context.Context) (Status, error) {
	var s Status
	err := c.do(ctx, http.MethodPost, "/v1/resume", nil, struct{}{}, &s)
	return s, err
}

// CreatePass issues a pass. The token in the response is the only copy.
func (c *Client) CreatePass(ctx context.Context, req PassCreateRequest) (PassCreateResponse, error) {
	var r PassCreateResponse
	err := c.do(ctx, http.MethodPost, "/v1/passes", nil, req, &r)
	return r, err
}

// Passes lists passes (including revoked and expired ones).
func (c *Client) Passes(ctx context.Context) ([]PassInfo, error) {
	var r []PassInfo
	err := c.do(ctx, http.MethodGet, "/v1/passes", nil, nil, &r)
	return r, err
}

// RevokePass revokes a pass by id.
func (c *Client) RevokePass(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/passes", nil, PassRevokeRequest{ID: id}, nil)
}

// Keys lists vault entries (masked metadata).
func (c *Client) Keys(ctx context.Context) ([]KeyInfo, error) {
	var r []KeyInfo
	err := c.do(ctx, http.MethodGet, "/v1/keys", nil, nil, &r)
	return r, err
}

// AddKey stores a provider key. The caller owns and should wipe secret.
func (c *Client) AddKey(ctx context.Context, provider, label string, secret []byte) (KeyInfo, error) {
	var k KeyInfo
	req := AddKeyRequest{Provider: provider, Label: label, Secret: append([]byte(nil), secret...)}
	defer secmem.Wipe(req.Secret)
	err := c.do(ctx, http.MethodPost, "/v1/keys", nil, req, &k)
	return k, err
}

// UseKey makes entry id its provider's active key: the key new passes are
// mapped to (step-up; blocks until approved).
func (c *Client) UseKey(ctx context.Context, id string) (KeyInfo, error) {
	var k KeyInfo
	err := c.do(ctx, http.MethodPost, "/v1/keys/"+url.PathEscape(id)+"/use", nil, struct{}{}, &k)
	return k, err
}

// RemoveKey deletes a vault entry (step-up).
func (c *Client) RemoveKey(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/keys/"+url.PathEscape(id), nil, nil, nil)
}

// Usage aggregates settled spend by "pass", "model", "provider" or
// "process" since the given time (zero: start of the current month).
func (c *Client) Usage(ctx context.Context, by string, since time.Time) (Usage, error) {
	var u Usage
	q := url.Values{}
	if by != "" {
		q.Set("by", by)
	}
	if !since.IsZero() {
		q.Set("since", since.UTC().Format(time.RFC3339))
	}
	err := c.do(ctx, http.MethodGet, "/v1/usage", q, nil, &u)
	return u, err
}

// Approvals lists pending step-up requests.
func (c *Client) Approvals(ctx context.Context) ([]Approval, error) {
	var r []Approval
	err := c.do(ctx, http.MethodGet, "/v1/approvals", nil, nil, &r)
	return r, err
}

// Decide answers a pending approval. Approving needs req.Secret (the vault
// passphrase or recovery code); the caller still owns and should wipe it.
func (c *Client) Decide(ctx context.Context, id string, req DecideRequest) error {
	if len(req.Secret) > 0 {
		req.Secret = append([]byte(nil), req.Secret...)
		defer secmem.Wipe(req.Secret)
	}
	return c.do(ctx, http.MethodPost, "/v1/approvals/"+url.PathEscape(id), nil, req, nil)
}

// AuditTail returns up to the last n audit records.
func (c *Client) AuditTail(ctx context.Context, n int) ([]AuditRecord, error) {
	var r []AuditRecord
	q := url.Values{}
	if n > 0 {
		q.Set("n", strconv.Itoa(n))
	}
	err := c.do(ctx, http.MethodGet, "/v1/audit/tail", q, nil, &r)
	return r, err
}

// AuditVerify verifies the audit chain (and anchors, when unlocked).
func (c *Client) AuditVerify(ctx context.Context) (AuditVerify, error) {
	var r AuditVerify
	err := c.do(ctx, http.MethodGet, "/v1/audit/verify", nil, nil, &r)
	return r, err
}

// Config returns the effective configuration as TOML.
func (c *Client) Config(ctx context.Context) (string, error) {
	var r struct {
		TOML string `json:"toml"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/config", nil, nil, &r)
	return r.TOML, err
}

// RotateRecovery replaces the recovery code (step-up, re-keys the vault).
func (c *Client) RotateRecovery(ctx context.Context) (RotateRecoveryResponse, error) {
	var r RotateRecoveryResponse
	err := c.do(ctx, http.MethodPost, "/v1/vault/recovery", nil, struct{}{}, &r)
	return r, err
}

// RemoveSlot removes a key slot (step-up, re-keys the vault).
func (c *Client) RemoveSlot(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/v1/vault/slots/"+url.PathEscape(id), nil, nil, nil)
}
