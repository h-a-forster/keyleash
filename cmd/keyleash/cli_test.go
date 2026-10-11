package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/config"
	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/vault"
)

// Secrets used across tests. They only look real.
const (
	fakeAnthropicKey = "sk-ant-api03-TESTKEY-0123456789abcdefABCDEF"
	fakeOpenAIKey    = "sk-proj-TESTKEY-0123456789abcdefABCDEFghij"
	fakeGeminiKey    = "AIzaSyTESTKEY0123456789abcdefABCDEFghi"
	fakeRecovery     = "ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-2345-6789"
)

// newTestApp returns an app with captured output whose admin channel is
// unreachable unless dial is replaced.
func newTestApp(stdin string) (*app, *bytes.Buffer, *bytes.Buffer) {
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	a := &app{
		stdin: strings.NewReader(stdin), stdout: out, stderr: errb,
		getenv:  func(string) string { return "" },
		environ: func() []string { return nil },
	}
	a.dial = func() (*client.Client, error) {
		return client.New(func(context.Context) (net.Conn, error) {
			return nil, errors.New("connection refused")
		}), nil
	}
	return a, out, errb
}

func TestLooksLikeSecret(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{fakeAnthropicKey, true},
		{fakeOpenAIKey, true},
		{fakeGeminiKey, true},
		{"sk-or-v1-0123456789abcdef0123", true},
		{"klp_ABCDEFGHIJ_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG", true},
		{fakeRecovery, true},
		{strings.ToLower(fakeRecovery), true},
		{"Bearer " + fakeOpenAIKey, true},
		{"anthropic", false},
		{"openai", false},
		{"sk-", false},
		{"sk-short", false},
		{"claude-sonnet-4-5-20250929", false},
		{"day=5", false},
		{"8h", false},
		{"", false},
		{"p_0123456789", false},
	}
	for _, tt := range tests {
		if got := looksLikeSecret(tt.in); got != tt.want {
			t.Errorf("looksLikeSecret(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestRejectSecretArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		bad  bool
	}{
		{"plain", []string{"anthropic", "--label", "work"}, false},
		{"key positional", []string{"anthropic", fakeAnthropicKey}, true},
		{"key in flag value", []string{"anthropic", "--label=" + fakeAnthropicKey}, true},
		{"key as flag value", []string{"anthropic", "--label", fakeOpenAIKey}, true},
		{"key glued to dashes", []string{"--" + fakeOpenAIKey}, true},
		{"recovery code", []string{fakeRecovery}, true},
		{"after double dash is the child's", []string{"--budget", "5", "--", "tool", fakeAnthropicKey}, false},
		{"before double dash", []string{fakeAnthropicKey, "--", "tool"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := rejectSecretArgs(tt.args)
			if (err != nil) != tt.bad {
				t.Fatalf("rejectSecretArgs(%v) = %v, want error %v", tt.args, err, tt.bad)
			}
			if err != nil {
				for _, a := range tt.args {
					if looksLikeSecret(a) && strings.Contains(err.Error(), a) {
						t.Fatalf("error echoes the secret: %v", err)
					}
				}
			}
		})
	}
}

// TestMainRejectsSecretsInArgv runs the whole CLI entry point: a key on the
// command line is refused with exit code 2, before any daemon contact, and
// is not echoed anywhere.
func TestMainRejectsSecretsInArgv(t *testing.T) {
	cases := [][]string{
		{"add", "anthropic", fakeAnthropicKey},
		{"add", "openai", "--stdin", fakeOpenAIKey},
		{"unlock", "--method", "recovery", fakeRecovery},
		{"pass", "revoke", "klp_ABCDEFGHIJ_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG"},
		{"env", "--name", fakeGeminiKey},
	}
	for _, args := range cases {
		a, out, errb := newTestApp("")
		dialed := false
		a.dial = func() (*client.Client, error) { dialed = true; return nil, errors.New("no") }
		code := a.main(args)
		if code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args[:2], code, exitUsage)
		}
		if dialed {
			t.Errorf("%v: contacted the daemon before rejecting", args[:2])
		}
		all := out.String() + errb.String()
		for _, s := range args {
			if looksLikeSecret(s) && strings.Contains(all, s) {
				t.Errorf("%v: output echoes the secret", args[:2])
			}
		}
		if !strings.Contains(errb.String(), "never takes secrets on the command line") {
			t.Errorf("%v: unexpected message %q", args[:2], errb.String())
		}
	}
}

func TestAddRejectsExtraArgument(t *testing.T) {
	a, out, errb := newTestApp("")
	code := a.main([]string{"add", "anthropic", "my-key-value"})
	if code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
	if strings.Contains(out.String()+errb.String(), "my-key-value") {
		t.Fatal("the extra argument was echoed")
	}
	if !strings.Contains(errb.String(), "never taken from the command line") {
		t.Fatalf("unexpected message: %s", errb.String())
	}
}

func TestParseFlags(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		intersperse bool
		wantPos     []string
		wantLabel   string
		wantStdin   bool
		wantErr     string
	}{
		{"flags first", []string{"--label", "w", "anthropic"}, true, []string{"anthropic"}, "w", false, ""},
		{"interspersed", []string{"anthropic", "--label=w", "--stdin"}, true, []string{"anthropic"}, "w", true, ""},
		{"double dash keeps rest", []string{"--stdin", "--", "--label", "x"}, true, []string{"--label", "x"}, "", true, ""},
		{"no intersperse stops at command", []string{"--stdin", "tool", "--label", "x"}, false, []string{"tool", "--label", "x"}, "", true, ""},
		{"no intersperse with double dash", []string{"--label", "a", "--", "tool", "-v"}, false, []string{"tool", "-v"}, "a", false, ""},
		{"unknown flag", []string{"--nope"}, true, nil, "", false, "unknown flag --nope"},
		{"missing value", []string{"--label"}, true, nil, "", false, "flag --label needs a value"},
		{"odd flag name not echoed", []string{"--" + strings.Repeat("x", 40)}, true, nil, "", false, "unknown flag"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := newFlagSet("add")
			label := fs.String("label", "", "")
			stdin := fs.Bool("stdin", false, "")
			pos, err := parseFlags(fs, tt.args, tt.intersperse)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				var ue *usageError
				if !errors.As(err, &ue) {
					t.Fatalf("want a usage error, got %T", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(pos, tt.wantPos) {
				t.Errorf("pos = %q, want %q", pos, tt.wantPos)
			}
			if *label != tt.wantLabel || *stdin != tt.wantStdin {
				t.Errorf("label=%q stdin=%v, want %q %v", *label, *stdin, tt.wantLabel, tt.wantStdin)
			}
		})
	}
}

func TestFlagErrorsDoNotEchoValues(t *testing.T) {
	secretish := "hunter2-value-that-should-not-appear"
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"--budget", secretish}, "invalid value for --budget: want an amount like 5, 2.50 or $5"},
		{[]string{"--ttl", secretish}, "invalid value for --ttl: want a duration like 30m, 8h or 7d"},
		{[]string{"--limit", secretish}, "invalid value for --limit: want window=amount, e.g. day=5"},
		{[]string{"--concurrency", secretish}, "invalid value for --concurrency"},
		{[]string{"--json=" + secretish}, "invalid flag value"},
	}
	for _, tt := range tests {
		fs := newFlagSet("x")
		addPassFlags(fs, "")
		fs.Bool("json", false, "")
		_, err := parseFlags(fs, tt.args, true)
		if err == nil {
			t.Fatalf("%v: no error", tt.args)
		}
		if strings.Contains(err.Error(), secretish) {
			t.Fatalf("%v: error echoes the value: %v", tt.args, err)
		}
		if !strings.HasPrefix(err.Error(), tt.want) {
			t.Errorf("%v: err = %q, want prefix %q", tt.args, err, tt.want)
		}
	}
}

func TestValueFlags(t *testing.T) {
	var m moneyFlag
	for in, want := range map[string]money.Micros{"5": 5 * money.Dollar, "$2.50": 2_500_000, "150c": 1_500_000} {
		if err := m.Set(in); err != nil || m.v != want {
			t.Errorf("money %q = %v, %v; want %v", in, m.v, err, want)
		}
	}
	for _, bad := range []string{"", "-1", "0", "abc", "$1.0000001"} {
		if err := (&moneyFlag{}).Set(bad); err == nil {
			t.Errorf("money %q accepted", bad)
		}
	}
	var d durationFlag
	for in, want := range map[string]time.Duration{"8h": 8 * time.Hour, "7d": 7 * 24 * time.Hour, "90s": 90 * time.Second} {
		if err := d.Set(in); err != nil || d.v != want {
			t.Errorf("duration %q = %v, %v; want %v", in, d.v, err, want)
		}
	}
	for _, bad := range []string{"", "0", "-5m", "d", "xd", "99999d", "soon"} {
		if err := (&durationFlag{}).Set(bad); err == nil {
			t.Errorf("duration %q accepted", bad)
		}
	}
	var l limitsFlag
	if err := l.Set("day=5, hour=$1"); err != nil {
		t.Fatal(err)
	}
	if err := l.Set("SESSION=2"); err != nil {
		t.Fatal(err)
	}
	want := limitsFlag{{Window: "day", Amount: 5 * money.Dollar}, {Window: "hour", Amount: money.Dollar}, {Window: "session", Amount: 2 * money.Dollar}}
	if !reflect.DeepEqual(l, want) {
		t.Errorf("limits = %v, want %v", l, want)
	}
	for _, bad := range []string{"day", "week=5", "day=0", "day=-1", "=5"} {
		if err := (&limitsFlag{}).Set(bad); err == nil {
			t.Errorf("limit %q accepted", bad)
		}
	}
	var lf listFlag
	_ = lf.Set("anthropic, openai,,")
	_ = lf.Set("gemini")
	if !reflect.DeepEqual([]string(lf), []string{"anthropic", "openai", "gemini"}) {
		t.Errorf("list = %v", lf)
	}
}

func TestBudgetLimits(t *testing.T) {
	got := budgetLimits(3 * money.Dollar)
	want := []client.PassLimit{{Window: "session", Amount: 3 * money.Dollar}, {Window: "month", Amount: 3 * money.Dollar}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("budgetLimits = %v, want %v", got, want)
	}
}

func TestPassFlagsRequest(t *testing.T) {
	fs := newFlagSet("run")
	pf := addPassFlags(fs, "dflt")
	if _, err := parseFlags(fs, []string{"--budget", "4", "--limit", "hour=1", "--models", "claude-*", "--deny-models", "*opus*", "--ttl", "2h", "--concurrency", "3"}, true); err != nil {
		t.Fatal(err)
	}
	req, err := pf.request("run", "run", []string{"anthropic"})
	if err != nil {
		t.Fatal(err)
	}
	if req.Name != "dflt" || req.Kind != "run" || req.TTL != 2*time.Hour || req.Concurrency != 3 {
		t.Errorf("unexpected request %+v", req)
	}
	if !reflect.DeepEqual(req.Models, []string{"claude-*"}) || !reflect.DeepEqual(req.DenyModels, []string{"*opus*"}) {
		t.Errorf("models %v deny %v", req.Models, req.DenyModels)
	}
	if len(req.Limits) != 3 || req.Limits[0].Window != "hour" {
		t.Errorf("limits %v", req.Limits)
	}
	// Negative cases.
	fs = newFlagSet("run")
	pf = addPassFlags(fs, "")
	_, _ = parseFlags(fs, []string{"--concurrency", "-1"}, true)
	if _, err := pf.request("run", "run", []string{"anthropic"}); err == nil {
		t.Error("negative concurrency accepted")
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	if got, _ := parseSince("", now); !got.IsZero() {
		t.Errorf("empty = %v", got)
	}
	if got, _ := parseSince("7d", now); !got.Equal(now.Add(-7 * 24 * time.Hour)) {
		t.Errorf("7d = %v", got)
	}
	if got, _ := parseSince("2026-10-01T00:00:00Z", now); !got.Equal(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("rfc3339 = %v", got)
	}
	if got, _ := parseSince("2026-10-01", now); got.Day() != 1 || got.Hour() != 0 {
		t.Errorf("date = %v", got)
	}
	for _, bad := range []string{"yesterday", "2026-13-01", "-5h"} {
		if _, err := parseSince(bad, now); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRecoveryConfirmed(t *testing.T) {
	code := "0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WX10"
	tests := []struct {
		typed string
		ok    bool
	}{
		{"WX10", true},
		{"wx10", true},
		{" wx-1o ", true}, // Crockford alias O→0, spaces and dashes ignored
		{"WXIO", true},    // I→1, O→0
		{code, true},
		{strings.ReplaceAll(code, "-", ""), true},
		{"RSTV", false},
		{"WX1", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := recoveryConfirmed(code, tt.typed); got != tt.ok {
			t.Errorf("recoveryConfirmed(%q) = %v, want %v", tt.typed, got, tt.ok)
		}
	}
}

func TestConfirmRecoveryLoopsUntilMatch(t *testing.T) {
	code := "0123-4567-89AB-CDEF-GHJK-MNPQ-RSTV-WX10"
	a, _, errb := newTestApp("nope\nRSTV\nwx10\n")
	if err := a.confirmRecovery(code); err != nil {
		t.Fatal(err)
	}
	if strings.Count(errb.String(), "does not match") != 2 {
		t.Errorf("prompts: %s", errb.String())
	}
	a, _, _ = newTestApp("nope\n")
	if err := a.confirmRecovery(code); err == nil {
		t.Error("EOF without a match must fail")
	}
}

func TestCheckNewPassphrase(t *testing.T) {
	tests := []struct {
		pw string
		ok bool
	}{
		{"correct horse battery", true},
		{"twelve chars", true},
		{"short", false},
		{"elevenchars", false},
		{"            ", false},
		{"ünïcödé-pässwörd", true},
		{string([]byte{0xff, 0xfe, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k'}), false},
		{strings.Repeat("x", 1025), false},
	}
	for _, tt := range tests {
		if err := checkNewPassphrase([]byte(tt.pw)); (err == nil) != tt.ok {
			t.Errorf("checkNewPassphrase(%q) = %v, want ok=%v", tt.pw, err, tt.ok)
		}
	}
}

func TestNewPassphraseFromStdin(t *testing.T) {
	a, _, _ := newTestApp("correct horse battery staple\r\nnext line\n")
	pw, err := a.newPassphrase(true)
	if err != nil || string(pw) != "correct horse battery staple" {
		t.Fatalf("pw=%q err=%v", pw, err)
	}
	a, _, _ = newTestApp("short\n")
	if _, err := a.newPassphrase(true); err == nil {
		t.Fatal("short passphrase accepted")
	}
	// No terminal and no --stdin: refuse rather than read a visible line.
	a, _, _ = newTestApp("correct horse battery staple\n")
	if _, err := a.newPassphrase(false); err == nil || !strings.Contains(err.Error(), "--stdin") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadLineBounded(t *testing.T) {
	r := strings.NewReader("first\r\nsecond")
	l1, err := readLineBounded(r)
	if err != nil || string(l1) != "first" {
		t.Fatalf("l1=%q err=%v", l1, err)
	}
	l2, err := readLineBounded(r)
	if err != nil || string(l2) != "second" {
		t.Fatalf("l2=%q err=%v", l2, err)
	}
	if _, err := readLineBounded(r); err == nil {
		t.Fatal("EOF must be an error")
	}
	if _, err := readLineBounded(strings.NewReader(strings.Repeat("a", maxSecretInput+1))); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestCheckKeyInput(t *testing.T) {
	tests := []struct {
		prov, key string
		err, warn bool
	}{
		{"anthropic", fakeAnthropicKey, false, false},
		{"openai", fakeOpenAIKey, false, false},
		{"gemini", fakeGeminiKey, false, false},
		{"openai", fakeAnthropicKey, false, true}, // an Anthropic key stored under openai
		{"anthropic", "abcdef0123456789", false, true},
		{"anthropic", "", true, false},
		{"anthropic", "sk-ant-api03 with spaces", true, false},
		{"anthropic", "sk-ant-api03-\x07bell", true, false},
		{"anthropic", "klp_ABCDEFGHIJ_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG", true, false},
	}
	for _, tt := range tests {
		warn, err := checkKeyInput(tt.prov, []byte(tt.key))
		if (err != nil) != tt.err || (warn != "") != tt.warn {
			t.Errorf("checkKeyInput(%s, %q) = %q, %v", tt.prov, tt.key, warn, err)
		}
		for _, msg := range []string{warn, errString(err)} {
			if tt.key != "" && strings.Contains(msg, tt.key) {
				t.Errorf("message echoes the key: %q", msg)
			}
		}
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestChooseUnlockMethod(t *testing.T) {
	defer func(f func() (bool, string)) { helloAvailable = f }(helloAvailable)
	pass := client.Slot{Type: "passphrase"}
	hello := client.Slot{Type: "hello"}
	rec := client.Slot{Type: "recovery"}
	tests := []struct {
		slots     []client.Slot
		helloOK   bool
		fromStdin bool
		want      string
	}{
		{[]client.Slot{pass, rec}, true, false, "passphrase"},
		{[]client.Slot{hello, rec}, true, false, "hello"},
		{[]client.Slot{hello, rec}, false, false, "hello"}, // only Hello: let the daemon explain
		{[]client.Slot{hello, pass, rec}, false, false, "passphrase"},
		{[]client.Slot{hello, pass, rec}, true, true, "passphrase"},
		{[]client.Slot{rec}, true, false, "recovery"},
	}
	for _, tt := range tests {
		helloAvailable = func() (bool, string) { return tt.helloOK, "test" }
		if got := chooseUnlockMethod(tt.slots, tt.fromStdin); got != tt.want {
			t.Errorf("chooseUnlockMethod(%v, hello=%v, stdin=%v) = %s, want %s", tt.slots, tt.helloOK, tt.fromStdin, got, tt.want)
		}
	}
}

func TestResolveProviders(t *testing.T) {
	keys := []client.KeyInfo{
		{Provider: "openai", Kind: "api_key"},
		{Provider: "gemini", Kind: "api_key"},
		{Provider: "anthropic", Kind: "admin_key"},
	}
	got, err := resolveProviders(nil, keys, true)
	if err != nil || !reflect.DeepEqual(got, []string{"openai"}) {
		t.Errorf("default with base URL = %v, %v", got, err)
	}
	got, err = resolveProviders(nil, keys, false)
	if err != nil || !reflect.DeepEqual(got, []string{"gemini", "openai"}) { // registry order
		t.Errorf("default = %v, %v", got, err)
	}
	got, err = resolveProviders([]string{"Gemini", "anthropic", "gemini"}, keys, true)
	if err != nil || !reflect.DeepEqual(got, []string{"gemini", "anthropic"}) {
		t.Errorf("explicit = %v, %v", got, err)
	}
	if _, err := resolveProviders([]string{"nope"}, keys, true); err == nil {
		t.Error("unknown provider accepted")
	}
	if _, err := resolveProviders([]string{"*"}, keys, true); err == nil {
		t.Error("wildcard accepted")
	}
	if _, err := resolveProviders(nil, nil, true); err == nil || !strings.Contains(err.Error(), "keyleash add") {
		t.Errorf("no keys: %v", err)
	}
	if miss := missingKeys([]string{"anthropic", "openai"}, keys); !reflect.DeepEqual(miss, []string{"anthropic"}) {
		t.Errorf("missingKeys = %v", miss)
	}
}

func TestFriendlyErrors(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{&client.APIError{Status: 423, Code: client.CodeLocked, Message: "keyleash is locked"}, "keyleash is locked — run: keyleash unlock"},
		{&client.APIError{Status: 409, Code: client.CodeConflict, Message: "keyleash is tripped; run `keyleash resume`"}, "run: keyleash resume"},
		{&client.APIError{Status: 401, Code: client.CodeWrongSecret, Message: "wrong secret"}, "wrong passphrase"},
		{&client.APIError{Status: 403, Code: client.CodeStepUpDenied}, "denied"},
		{&client.APIError{Status: 400, Code: client.CodeBadRequest, Message: "bad limit"}, "bad limit"},
	}
	for _, tt := range tests {
		if got := friendly(tt.err).Error(); !strings.Contains(got, tt.want) {
			t.Errorf("friendly(%v) = %q, want it to contain %q", tt.err, got, tt.want)
		}
	}
}

func TestCommandsReportDaemonDown(t *testing.T) {
	for _, args := range [][]string{{"status"}, {"keys"}, {"lock"}, {"pass", "list"}, {"usage"}, {"run", "--", "x"}} {
		a, _, errb := newTestApp("")
		if code := a.main(args); code != exitError {
			t.Errorf("%v: exit %d", args, code)
		}
		if !strings.Contains(errb.String(), "start it with: keyleash daemon") {
			t.Errorf("%v: stderr %q", args, errb.String())
		}
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"nope"}, {"run"}, {"run", "--budget"}, {"away", "--budget", "5"}, {"pass"}, {"pass", "frob"},
		{"audit"}, {"audit", "frob"}, {"config"}, {"usage", "--by", "day"}, {"limits", "set", "x"},
		{"unlock", "--method", "telepathy"}, {"init", "--profile", "yolo"}, {"approvals", "approve"},
		{"env", "--shell", "tcsh"}, {"help", "nope"},
	} {
		a, _, errb := newTestApp("")
		if code := a.main(args); code != exitUsage {
			t.Errorf("%v: exit %d (stderr %q)", args, code, errb.String())
		}
	}
}

func TestHelpAndVersion(t *testing.T) {
	a, out, _ := newTestApp("")
	if code := a.main([]string{"help"}); code != 0 || !strings.Contains(out.String(), "run") {
		t.Fatalf("help: %d %s", code, out.String())
	}
	for _, c := range commands {
		a, out, _ := newTestApp("")
		if code := a.main([]string{"help", c.name}); code != 0 || !strings.Contains(out.String(), "Usage: keyleash "+c.name) {
			t.Errorf("help %s: %d %s", c.name, code, out.String())
		}
	}
	a, out, _ = newTestApp("")
	if code := a.main([]string{"version"}); code != 0 || !strings.HasPrefix(out.String(), "keyleash "+version) {
		t.Fatalf("version: %d %s", code, out.String())
	}
	a, out, _ = newTestApp("")
	if code := a.main([]string{"--version", "--json"}); code != 0 || !strings.Contains(out.String(), `"version"`) {
		t.Fatalf("version --json: %d %s", code, out.String())
	}
}

func TestInitRefusesWithoutTerminal(t *testing.T) {
	dir := t.TempDir()
	a, _, errb := newTestApp("")
	a.getenv = func(k string) string {
		if k == "KEYLEASH_HOME" {
			return dir
		}
		return ""
	}
	if code := a.main([]string{"init"}); code != exitError || !strings.Contains(errb.String(), "needs a terminal") {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	a, _, errb = newTestApp("")
	a.getenv = func(string) string { return dir }
	if code := a.main([]string{"init", "--stdin", "--method", "hello"}); code != exitUsage {
		t.Fatalf("--stdin with hello: exit %d: %s", code, errb.String())
	}
}

func TestInitFromStdin(t *testing.T) {
	defer func(f func() (bool, string)) { helloAvailable = f }(helloAvailable)
	helloAvailable = func() (bool, string) { return false, "test" }
	restore := vault.SetTestKDFParams()
	defer restore()
	dir := t.TempDir()
	home := func(k string) string {
		if k == "KEYLEASH_HOME" {
			return dir
		}
		return ""
	}

	a, _, errb := newTestApp("short\n")
	a.getenv = home
	if code := a.main([]string{"init", "--stdin"}); code != exitError || !strings.Contains(errb.String(), "too short") {
		t.Fatalf("short passphrase: %d %q", code, errb.String())
	}
	if vaultExists(dir) {
		t.Fatal("a vault was created despite the bad passphrase")
	}

	a, out, errb := newTestApp(testPassphrase + "\n")
	a.getenv = home
	if code := a.main([]string{"init", "--stdin", "--profile", "strict"}); code != 0 {
		t.Fatalf("init: %d %q", code, errb.String())
	}
	code := between(out.String(), "    ", "\n")
	if !recoveryCodeRE.MatchString(code) {
		t.Fatalf("no recovery code in output:\n%s", out.String())
	}
	if strings.Contains(out.String()+errb.String(), testPassphrase) {
		t.Fatal("passphrase echoed")
	}
	cfg, err := config.Load(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Profile != "strict" || cfg.Approval.Method != "console" {
		t.Errorf("config: profile %s, approval %s", cfg.Profile, cfg.Approval.Method)
	}

	a, _, errb = newTestApp(testPassphrase + "\n")
	a.getenv = home
	if code := a.main([]string{"init", "--stdin"}); code != exitError || !strings.Contains(errb.String(), "already holds a keyleash vault") {
		t.Fatalf("second init: %d %q", code, errb.String())
	}
}

func TestSetApprovalMethod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	orig := "profile = \"recommended\"\n# [approval]\n# method = \"hello\"\n"
	for _, m := range []string{"console", "deny"} {
		if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := setApprovalMethod(path, m); err != nil {
			t.Fatal(err)
		}
		cfg, err := config.Load(path)
		if err != nil || cfg.Approval.Method != m {
			t.Fatalf("%s: %v %+v", m, err, cfg)
		}
	}
	// An override that does not validate is reverted.
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setApprovalMethod(path, "carrier-pigeon"); err == nil {
		t.Fatal("invalid method accepted")
	}
	if b, _ := os.ReadFile(path); string(b) != orig {
		t.Fatalf("config not reverted:\n%s", b)
	}
}
