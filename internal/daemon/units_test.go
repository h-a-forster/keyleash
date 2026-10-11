package daemon

import (
	"bytes"
	"context"
	"crypto/rsa"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/proxy"
	"github.com/h-a-forster/keyleash/internal/vault"
	"github.com/h-a-forster/keyleash/internal/winhello"
)

type fakeHello struct {
	decErr, pkcsErr error
	pkcsCalled      bool
}

func (f *fakeHello) KeyName() string                    { return "SID//keyleash//vault" }
func (f *fakeHello) PublicKey() (*rsa.PublicKey, error) { return nil, errors.New("unused") }
func (f *fakeHello) Decrypt(context.Context, []byte, string) ([]byte, error) {
	if f.decErr != nil {
		return nil, f.decErr
	}
	return []byte("kek"), nil
}
func (f *fakeHello) DecryptPKCS1v15(context.Context, []byte, string) ([]byte, error) {
	f.pkcsCalled = true
	return []byte("kek"), f.pkcsErr
}

func TestHelloAdapterMapsOAEPUnsupported(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		wantVault bool
		wantErr   bool
	}{
		{"ok", nil, false, false},
		{"oaep unsupported", winhello.ErrOAEPUnsupported, true, true},
		{"wrapped oaep unsupported", errors.Join(errors.New("ncrypt"), winhello.ErrOAEPUnsupported), true, true},
		{"cancelled", winhello.ErrCancelled, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := helloKey{k: &fakeHello{decErr: tc.err}}
			pt, err := h.Decrypt(t.Context(), []byte("ct"), "p")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v", err)
			}
			if got := errors.Is(err, vault.ErrOAEPUnsupported); got != tc.wantVault {
				t.Fatalf("errors.Is(vault.ErrOAEPUnsupported) = %v", got)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatal("original error lost")
			}
			if err == nil && string(pt) != "kek" {
				t.Fatal("plaintext lost")
			}
		})
	}
	f := &fakeHello{}
	var hk vault.HelloKey = helloKey{k: f}
	p1, ok := hk.(vault.HelloKeyPKCS1)
	if !ok {
		t.Fatal("adapter does not implement HelloKeyPKCS1")
	}
	if _, err := p1.DecryptPKCS1v15(t.Context(), nil, ""); err != nil || !f.pkcsCalled {
		t.Fatal("PKCS1 fallback not forwarded")
	}
}

func TestStateFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, StateFile)
	key := bytes.Repeat([]byte{7}, 32)
	cp := &budget.Checkpoint{Month: "2026-10", Records: 3, LastHash: strings.Repeat("ab", 32), Settled: 1234}

	if _, exists, err := loadStateFile(p, key, "v1"); exists || err != nil {
		t.Fatalf("missing file: %v %v", exists, err)
	}
	if err := saveStateFile(p, key, stateBody{Version: 1, VaultID: "v1", Checkpoint: cp}); err != nil {
		t.Fatal(err)
	}
	st, exists, err := loadStateFile(p, key, "v1")
	if err != nil || !exists || *st.Checkpoint != *cp {
		t.Fatalf("round trip: %+v %v", st, err)
	}
	raw, _ := os.ReadFile(p)
	if !bytes.Contains(raw, []byte(`"records":3`)) {
		t.Fatalf("unexpected encoding: %s", raw)
	}
	cases := []struct {
		name    string
		mutate  func() []byte
		key     []byte
		vaultID string
	}{
		{"wrong key", func() []byte { return raw }, bytes.Repeat([]byte{8}, 32), "v1"},
		{"other vault", func() []byte { return raw }, key, "v2"},
		{"edited body", func() []byte { return bytes.Replace(raw, []byte(`"records":3`), []byte(`"records":2`), 1) }, key, "v1"},
		{"garbage", func() []byte { return []byte("{") }, key, "v1"},
		{"no mac", func() []byte { return []byte(`{"body":{"version":1}}`) }, key, "v1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(p, tc.mutate(), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, exists, err := loadStateFile(p, tc.key, tc.vaultID); !exists || !errors.Is(err, errStateAuth) {
				t.Fatalf("exists=%v err=%v", exists, err)
			}
		})
	}
}

func TestInit(t *testing.T) {
	for _, profile := range config.Profiles {
		t.Run(profile, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "kl")
			code, err := Init(dir, InitOptions{Method: "passphrase", Passphrase: testPassphrase, Profile: profile})
			if err != nil || code == "" {
				t.Fatalf("init: %v", err)
			}
			cfg, err := config.Load(filepath.Join(dir, ConfigFile))
			if err != nil || cfg.Profile != profile {
				t.Fatalf("generated config: %v %+v", err, cfg)
			}
			want, _ := config.Default(profile)
			a, _ := cfg.Encode()
			b, _ := want.Encode()
			if a != b {
				t.Fatal("generated config differs from the profile defaults")
			}
			raw, _ := os.ReadFile(filepath.Join(dir, ConfigFile))
			if bytes.Contains(raw, testPassphrase) || bytes.Contains(raw, []byte(code)) {
				t.Fatal("secret written to config")
			}
			v, err := vault.Open(filepath.Join(dir, VaultFile))
			if err != nil {
				t.Fatal(err)
			}
			if err := v.UnlockRecovery(code); err != nil {
				t.Fatalf("recovery code does not unlock: %v", err)
			}
			roots := 0
			for _, e := range v.Entries() {
				if isRootEntry(e) {
					roots++
				}
			}
			v.Lock()
			if roots != 1 {
				t.Fatalf("integrity roots = %d", roots)
			}
			if _, err := Init(dir, InitOptions{Method: "passphrase", Passphrase: testPassphrase}); !errors.Is(err, ErrAlreadyInitialized) {
				t.Fatalf("second init: %v", err)
			}
		})
	}
	bad := []InitOptions{
		{Method: "passphrase", Passphrase: []byte("short")},
		{Method: "carrier-pigeon"},
		{Method: "passphrase", Passphrase: testPassphrase, Profile: "yolo"},
	}
	for _, o := range bad {
		if _, err := Init(t.TempDir(), o); err == nil {
			t.Fatalf("Init(%+v) succeeded", o.Method)
		} else if strings.Contains(err.Error(), "short") && o.Method == "passphrase" && bytes.Equal(o.Passphrase, []byte("short")) {
			t.Fatal("passphrase echoed in error")
		}
	}
}

func TestAuditFailureTrips(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	e.d.markAuditBroken(errors.New("disk full"))
	wantReason(t, e.anthropic(tok), 423, proxy.ReasonTripped)
	if s := e.status(); s.State != client.StateTripped || s.TripReason != TripAudit || s.AuditHealthy {
		t.Fatalf("status = %s %s healthy=%v", s.State, s.TripReason, s.AuditHealthy)
	}
	e.appr.approve.Store(true)
	if _, err := e.c.Resume(e.ctx()); err != nil {
		t.Fatal(err)
	}
	if s := e.status(); s.State != client.StateUnlocked || !s.AuditHealthy {
		t.Fatalf("after resume: %s healthy=%v", s.State, s.AuditHealthy)
	}
	if r := e.anthropic(tok); r.status != 200 {
		t.Fatal(r.status)
	}
}

// TestLockSettlesInFlight: a lock while a request streams charges it at the
// reserved amount while the MAC key is still set, so the next unlock
// verifies cleanly.
func TestLockSettlesInFlight(t *testing.T) {
	e := newEnv(t, nil)
	e.unlock()
	e.addKeys()
	tok := e.newPass(client.PassCreateRequest{})
	done := make(chan result, 1)
	go func() { done <- e.anthropic(tok, "X-Test-Hold", "1") }()
	select {
	case <-e.up.held:
	case <-time.After(10 * time.Second):
		t.Fatal("held request never arrived")
	}
	if len(e.status().InFlight) != 1 {
		t.Fatal("expected one in-flight reservation")
	}
	if _, err := e.c.Lock(e.ctx()); err != nil {
		t.Fatal(err)
	}
	close(e.up.relea)
	<-done
	est := e.estimate("anthropic", "/v1/messages", anthropicReq)
	e.restart()
	e.unlock() // fatals if integrity failed
	if got, _ := limitSettled(e.status(), "global", "month"); got != est {
		t.Fatalf("settled = %s, want the reserved %s", got, est)
	}
	u, _ := e.c.Usage(e.ctx(), "model", time.Time{})
	if len(u.Rows) != 1 || u.Rows[0].Estimated != 1 {
		t.Fatalf("usage = %+v", u)
	}
}

func TestClientAPIErrorNeverEchoesSecret(t *testing.T) {
	e := newEnv(t, nil)
	secret := []byte("my-very-secret-passphrase")
	_, err := e.c.Unlock(e.ctx(), client.MethodPassphrase, secret)
	var ae *client.APIError
	if !errors.As(err, &ae) || ae.Status != 401 || !client.IsCode(err, client.CodeWrongSecret) {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), string(secret)) || strings.Contains(e.logText(), string(secret)) {
		t.Fatal("secret echoed")
	}
	if _, err := e.c.Config(e.ctx()); err != nil {
		t.Fatal(err)
	}
}

func TestFallbackAmount(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.Global.Request = &config.Amount{Micros: 3_000_000}
		c.Limits.Provider["openai"] = config.Limits{Request: &config.Amount{Micros: 500_000}}
	})
	e.d.mu.Lock()
	defer e.d.mu.Unlock()
	if got := e.d.fallbackAmountLocked("anthropic", "p1"); got != 3_000_000 {
		t.Fatalf("anthropic fallback = %s", got)
	}
	if got := e.d.fallbackAmountLocked("openai", "p1"); got != 500_000 {
		t.Fatalf("openai fallback = %s", got)
	}
	e.d.cfg.Limits.Global.Request = nil
	if got := e.d.fallbackAmountLocked("anthropic", "p1"); got != DefaultFallbackAmount {
		t.Fatalf("default fallback = %s", got)
	}
}

func TestRunStopsOnCancel(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, InitOptions{Method: "passphrase", Passphrase: testPassphrase}); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{DataDir: dir, Config: testConfig(t), PresenceSource: &fakePresence{},
			ProxyListener: ln, AdminListener: newMemListener(), Logger: slog.New(slog.DiscardHandler)})
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	// The instance lock was released.
	if _, err := Init(dir, InitOptions{Method: "passphrase", Passphrase: testPassphrase}); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("re-init: %v", err)
	}
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	d, err := Start(t.Context(), Options{DataDir: dir, Config: testConfig(t), PresenceSource: &fakePresence{},
		ProxyListener: ln2, AdminListener: newMemListener(), manualPresence: true, manualHousekeeping: true,
		Logger: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatalf("restart after Run: %v", err)
	}
	d.Close()
}
