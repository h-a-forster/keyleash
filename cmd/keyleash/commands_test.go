package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/daemon"
	"github.com/h-a-forster/keyleash/internal/meter"
)

// TestCommandsAgainstDaemon drives the CLI against an in-process daemon:
// unlock, add, keys, passes, env, usage, limits, audit, approvals, config,
// lock and panic, checking output and that no secret is ever printed.
func TestCommandsAgainstDaemon(t *testing.T) {
	defer func(f func() (bool, string)) { helloAvailable = f }(helloAvailable)
	helloAvailable = func() (bool, string) { return false, "test" }
	td := startTestDaemon(t, true)
	proxyAddr := td.d.ProxyAddr()
	var printed strings.Builder
	run := func(stdin string, args ...string) (int, string, string) {
		t.Helper()
		code, out, errOut := td.run(stdin, args...)
		printed.WriteString(out + errOut)
		return code, out, errOut
	}

	code, out, _ := run("", "status")
	if code != 0 || !strings.Contains(out, "state:      locked") {
		t.Fatalf("status: %d %q", code, out)
	}
	// add before unlock: actionable error, and the key is not even read.
	if code, _, errOut := run(fakeAnthropicKey+"\n", "add", "anthropic", "--stdin"); code != exitError || !strings.Contains(errOut, "keyleash unlock") {
		t.Fatalf("add while locked: %d %q", code, errOut)
	}
	if code, _, errOut := run("not the passphrase\n", "unlock", "--stdin"); code != exitError || !strings.Contains(errOut, "wrong passphrase") {
		t.Fatalf("wrong passphrase: %d %q", code, errOut)
	}
	if code, out, errOut := run(testPassphrase+"\n", "unlock", "--stdin"); code != 0 || !strings.Contains(out, "Unlocked") {
		t.Fatalf("unlock: %d %q %q", code, out, errOut)
	}
	if code, out, _ := run("", "unlock"); code != 0 || !strings.Contains(out, "already unlocked") {
		t.Fatalf("second unlock: %d %q", code, out)
	}

	// Keys.
	if code, _, errOut := run("klp_ABCDEFGHIJ_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG\n", "add", "anthropic", "--stdin"); code != exitError || !strings.Contains(errOut, "keyleash pass") {
		t.Fatalf("adding a pass as a key: %d %q", code, errOut)
	}
	code, out, errOut := run(fakeAnthropicKey+"\n", "add", "anthropic", "--stdin", "--label", "work")
	if code != 0 || !strings.Contains(out, `Added anthropic key "work"`) {
		t.Fatalf("add: %d %q %q", code, out, errOut)
	}
	code, out, _ = run("", "keys")
	if code != 0 || !strings.Contains(out, "anthropic") || !strings.Contains(out, "work") {
		t.Fatalf("keys: %d %q", code, out)
	}
	code, out, _ = run("", "keys", "--json")
	var keys []client.KeyInfo
	if code != 0 || json.Unmarshal([]byte(out), &keys) != nil || len(keys) != 1 || keys[0].Fingerprint == "" {
		t.Fatalf("keys --json: %d %q", code, out)
	}

	// Named pass: create, use, list, revoke.
	code, out, errOut = run("", "pass", "create", "--name", "editor", "--providers", "anthropic", "--budget", "3", "--json")
	var created client.PassCreateResponse
	if code != 0 || json.Unmarshal([]byte(out), &created) != nil || created.Token == "" {
		t.Fatalf("pass create: %d %q %q", code, out, errOut)
	}
	if created.Pass.Name != "editor" || len(created.Pass.Limits) != 2 {
		t.Errorf("pass: %+v", created.Pass)
	}
	if st := callProxy(t, proxyAddr, created.Token); st != 200 {
		t.Fatalf("named pass request: %d", st)
	}
	code, out, _ = run("", "pass", "list")
	if code != 0 || !strings.Contains(out, created.Pass.ID) || strings.Contains(out, created.Token) {
		t.Fatalf("pass list: %d %q", code, out)
	}
	if code, out, _ := run("", "pass", "revoke", created.Pass.ID); code != 0 || !strings.Contains(out, "Revoked") {
		t.Fatalf("pass revoke: %d %q", code, out)
	}
	if st := callProxy(t, proxyAddr, created.Token); st != 401 {
		t.Fatalf("revoked pass request: %d, want 401", st)
	}
	if code, out, _ := run("", "pass", "list"); code != 0 || strings.Contains(out, created.Pass.ID) {
		t.Fatalf("revoked pass still listed as active: %q", out)
	}
	if code, out, _ := run("", "pass", "list", "--all"); code != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("pass list --all: %q", out)
	}
	// Plain-text create: token alone on stdout.
	code, out, errOut = run("", "pass", "create", "--name", "plain")
	if code != 0 || !strings.HasPrefix(out, "klp_") || strings.Count(out, "\n") != 1 || !strings.Contains(errOut, "shown once") {
		t.Fatalf("pass create text: %d %q %q", code, out, errOut)
	}

	// env: exports for bash, using the pass.
	a, envOut, envErr := td.app("", "ANTHROPIC_AUTH_TOKEN=leftover")
	if code := a.main([]string{"env", "--shell", "bash", "--name", "vscode"}); code != 0 {
		t.Fatalf("env: %d %q", code, envErr.String())
	}
	text := envOut.String()
	for _, want := range []string{
		"unset ANTHROPIC_AUTH_TOKEN\n",
		"export ANTHROPIC_BASE_URL='http://" + proxyAddr + "/anthropic'\n",
		"export KEYLEASH_PROXY='http://" + proxyAddr + "'\n",
		"export ANTHROPIC_API_KEY='klp_",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("env output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "OPENAI") {
		t.Errorf("env exported a provider without a key:\n%s", text)
	}
	token := between(text, "export ANTHROPIC_API_KEY='", "'")
	if st := callProxy(t, proxyAddr, token); st != 200 {
		t.Fatalf("env pass request: %d", st)
	}
	if !strings.Contains(envErr.String(), "keyleash pass revoke") {
		t.Errorf("env stderr: %q", envErr.String())
	}
	a, envOut, _ = td.app("")
	if code := a.main([]string{"env", "--shell", "powershell", "--providers", "anthropic"}); code != 0 || !strings.Contains(envOut.String(), "$env:ANTHROPIC_BASE_URL = 'http://"+proxyAddr+"/anthropic'") {
		t.Fatalf("env powershell: %d %q", code, envOut.String())
	}

	// Status, usage, limits.
	code, out, _ = run("", "status")
	if code != 0 || !strings.Contains(out, "state:      unlocked") || !strings.Contains(out, "global") || !strings.Contains(out, "passes:") {
		t.Fatalf("status: %d %q", code, out)
	}
	code, out, _ = run("", "status", "--json")
	var st client.Status
	if code != 0 || json.Unmarshal([]byte(out), &st) != nil || st.State != client.StateUnlocked {
		t.Fatalf("status --json: %d %q", code, out)
	}
	code, out, _ = run("", "usage")
	for _, want := range []string{"By pass", "By model", "By provider", "By process", "claude-sonnet-4-5", "anthropic"} {
		if !strings.Contains(out, want) {
			t.Errorf("usage lacks %q:\n%s", want, out)
		}
	}
	code, out, _ = run("", "usage", "--by", "model", "--json", "--since", "1d")
	var u client.Usage
	if code != 0 || json.Unmarshal([]byte(out), &u) != nil || u.Total <= 0 || len(u.Rows) != 1 || u.Rows[0].Requests != 2 {
		t.Fatalf("usage --json: %d %q", code, out)
	}
	code, out, _ = run("", "limits")
	if code != 0 || !strings.Contains(out, "global:") || !strings.Contains(out, "tripwire:") || !strings.Contains(out, "REMAINING") {
		t.Fatalf("limits: %d %q", code, out)
	}

	// Audit, approvals, config.
	if code, out, _ := run("", "audit", "verify"); code != 0 || !strings.Contains(out, "Audit log OK") || !strings.Contains(out, "chain and anchors") {
		t.Fatalf("audit verify: %d %q", code, out)
	}
	if code, out, _ := run("", "audit", "tail", "-n", "50"); code != 0 || !strings.Contains(out, "pass_issue") || !strings.Contains(out, "key_add") {
		t.Fatalf("audit tail: %d %q", code, out)
	}
	if code, out, _ := run("", "approvals"); code != 0 || !strings.Contains(out, "No pending approvals") {
		t.Fatalf("approvals: %d %q", code, out)
	}
	if code, _, errOut := run("", "approvals", "approve", "nope"); code != exitError || !strings.Contains(errOut, "no such pending approval") {
		t.Fatalf("approve unknown: %d %q", code, errOut)
	}
	if code, out, _ := run("", "config", "show"); code != 0 || !strings.Contains(out, "[proxy]") {
		t.Fatalf("config show: %d %q", code, out)
	}
	if code, out, _ := run("", "config", "path"); code != 0 || strings.TrimSpace(out) != filepath.Join(td.dir, "config.toml") {
		t.Fatalf("config path: %d %q", code, out)
	}
	if code, out, _ := run("", "config", "check"); code != 0 || !strings.Contains(out, "[limits") {
		t.Fatalf("config check: %d %q", code, out)
	}
	// Step-up is denied by the test approver.
	if code, _, errOut := run("", "away", "--budget", "5", "--for", "1h"); code != exitError || !strings.Contains(errOut, "denied") {
		t.Fatalf("away: %d %q", code, errOut)
	}
	if code, _, errOut := run("", "rm-key", keys[0].ID); code != exitError || !strings.Contains(errOut, "denied") {
		t.Fatalf("rm-key: %d %q", code, errOut)
	}

	// Lock: passes stop working, run refuses with an actionable error.
	if code, out, _ := run("", "lock"); code != 0 || !strings.Contains(out, "Locked") {
		t.Fatalf("lock: %d %q", code, out)
	}
	if st := callProxy(t, proxyAddr, token); st != 423 {
		t.Fatalf("request while locked: %d, want 423", st)
	}
	if code, _, errOut := run("", "run", "--", "whatever"); code != exitError || !strings.Contains(errOut, "keyleash is locked — run: keyleash unlock") {
		t.Fatalf("run while locked: %d %q", code, errOut)
	}
	if code, _, errOut := run("", "env", "--shell", "bash"); code != exitError || !strings.Contains(errOut, "keyleash unlock") {
		t.Fatalf("env while locked: %d %q", code, errOut)
	}
	if code, out, _ := run("", "panic"); code != 0 || !strings.Contains(out, "passes revoked") {
		t.Fatalf("panic: %d %q", code, out)
	}

	// Nothing printed or logged may contain the provider key or the
	// passphrase.
	for name, s := range map[string]string{"cli output": printed.String(), "daemon log": td.logs.String()} {
		for _, secret := range []string{fakeAnthropicKey, testPassphrase} {
			if strings.Contains(s, secret) {
				t.Errorf("%s contains a secret", name)
			}
		}
	}
}

func between(s, start, end string) string {
	i := strings.Index(s, start)
	if i < 0 {
		return ""
	}
	s = s[i+len(start):]
	if j := strings.Index(s, end); j >= 0 {
		return s[:j]
	}
	return s
}

func TestPricingFindings(t *testing.T) {
	now := time.Now().UTC()
	day := func(d int) string { return now.AddDate(0, 0, d).Format("2006-01-02") }
	override := `{"version":1,"providers":{"anthropic":{"models":{
		"zz-old-model":{"input":"$1","output":"$2","source_url":"https://example.invalid","as_of":"` + day(-120) + `"},
		"zz-promo":{"input":"$1","output":"$2","source_url":"https://example.invalid","as_of":"` + day(0) + `","valid_until":"` + day(10) + `"},
		"zz-later-promo":{"input":"$1","output":"$2","source_url":"https://example.invalid","as_of":"` + day(0) + `","valid_until":"` + day(60) + `"},
		"zz-expired":{"input":"$1","output":"$2","source_url":"https://example.invalid","as_of":"` + day(-20) + `","valid_until":"` + day(-2) + `"}
	}}}}`
	path := filepath.Join(t.TempDir(), "pricing.json")
	if err := os.WriteFile(path, []byte(override), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := meter.LoadPricing(path)
	if err != nil {
		t.Fatal(err)
	}
	stale, expiring, unpriced := pricingFindings(p, now)
	has := func(list []string, id string) bool {
		for _, s := range list {
			if strings.HasPrefix(s, "anthropic/"+id+" ") || s == "anthropic/"+id {
				return true
			}
		}
		return false
	}
	if !has(stale, "zz-old-model") || has(stale, "zz-promo") {
		t.Errorf("stale = %v", stale)
	}
	if !has(expiring, "zz-promo") || has(expiring, "zz-later-promo") {
		t.Errorf("expiring = %v", expiring)
	}
	if !has(unpriced, "zz-expired") {
		t.Errorf("unpriced = %v", unpriced)
	}
	c := pricingCheck(p, now)
	if c.Level != levelWarn || !strings.Contains(c.Detail, "older than 90 days") || !strings.Contains(c.Detail, "within 30 days") {
		t.Errorf("check = %+v", c)
	}
}

func TestDoctorOffline(t *testing.T) {
	defer func(f func() (bool, string)) { helloAvailable = f }(helloAvailable)
	helloAvailable = func() (bool, string) { return false, "test" }
	dir := t.TempDir()
	a, out, _ := newTestApp("")
	a.getenv = func(k string) string {
		if k == "KEYLEASH_HOME" {
			return dir
		}
		return ""
	}
	a.main([]string{"doctor", "--json"})
	var checks []check
	if err := json.Unmarshal(out.Bytes(), &checks); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	got := map[string]check{}
	for _, c := range checks {
		got[c.Name] = c
	}
	for _, name := range []string{"windows hello", "data dir", "vault", "config", "daemon", "proxy port", "clock", "pricing"} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing check %q", name)
		}
	}
	if got["daemon"].Level != levelWarn || got["vault"].Level != levelWarn {
		t.Errorf("daemon/vault: %+v %+v", got["daemon"], got["vault"])
	}
	if got["approvals"].Level != levelWarn {
		t.Errorf("hello approval without Hello should warn: %+v", got["approvals"])
	}
}

func TestDoctorFlagsBadConfigAndClock(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[proxy]\nport = \"nope\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "audit"), 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "audit", "audit-2026-10.jsonl")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(3 * time.Hour)
	if err := os.Chtimes(f, future, future); err != nil {
		t.Fatal(err)
	}
	if c := clockCheck(dir, time.Now()); c.Level != levelFail {
		t.Errorf("clock behind data: %+v", c)
	}
	if c := clockCheck(dir, time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)); c.Level != levelFail {
		t.Errorf("implausible clock: %+v", c)
	}
	a, out, _ := newTestApp("")
	a.getenv = func(k string) string {
		if k == "KEYLEASH_HOME" {
			return dir
		}
		return ""
	}
	if code := a.main([]string{"doctor"}); code != exitError || !strings.Contains(out.String(), "[FAIL]  config") {
		t.Fatalf("doctor: %d\n%s", code, out.String())
	}
}

func TestPortCheck(t *testing.T) {
	st := &client.Status{ProxyAddr: "127.0.0.1:47114"}
	if c := portCheck(47114, st); c.Level != levelOK || !strings.Contains(c.Detail, "keyleash") {
		t.Errorf("own port: %+v", c)
	}
	if c := portCheck(47115, st); c.Level != levelWarn {
		t.Errorf("mismatch: %+v", c)
	}
	// A port held by something else.
	td := startTestDaemon(t, true)
	addr := td.d.ProxyAddr()
	port := addr[strings.LastIndexByte(addr, ':')+1:]
	n := 0
	for _, r := range port {
		n = n*10 + int(r-'0')
	}
	if c := portCheck(n, nil); c.Level != levelFail {
		t.Errorf("busy port: %+v", c)
	}
}

// TestApprovalsApproveNeedsSecret: approving over the admin channel needs the
// vault passphrase or recovery code; a waiting command points at the
// approval it triggered; denying needs nothing.
func TestApprovalsApproveNeedsSecret(t *testing.T) {
	td := startTestDaemon(t, true, func(o *daemon.Options) { o.Approver = manualApprover{} })
	if code, _, errOut := td.run(testPassphrase+"\n", "unlock", "--stdin"); code != 0 {
		t.Fatalf("unlock: %q", errOut)
	}
	c := td.client()
	defer c.Close()
	waitPending := func() client.Approval {
		t.Helper()
		for i := 0; i < 500; i++ {
			if list, _ := c.Approvals(t.Context()); len(list) == 1 {
				return list[0]
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("no pending approval")
		return client.Approval{}
	}
	type res struct {
		code        int
		out, errOut string
	}
	away := func() chan res {
		ch := make(chan res, 1)
		go func() {
			code, out, errOut := td.run("", "away", "--budget", "1", "--for", "1h")
			ch <- res{code, out, errOut}
		}()
		return ch
	}

	done := away()
	ap := waitPending()
	if ap.Requester != os.Getpid() || ap.Kind != "away_grant" {
		t.Fatalf("approval = %+v", ap)
	}
	if code, _, errOut := td.run("not the passphrase\n", "approvals", "approve", ap.ID, "--stdin"); code != exitError || !strings.Contains(errOut, "wrong passphrase") {
		t.Fatalf("wrong secret: %d %q", code, errOut)
	}
	if code, _, errOut := td.run(testPassphrase+"\n", "approvals", "approve", ap.ID, "--stdin"); code != 0 || !strings.Contains(errOut, "Approved "+ap.ID) {
		t.Fatalf("approve: %d %q", code, errOut)
	}
	r := <-done
	if r.code != 0 || !strings.Contains(r.out, "Grant g_") {
		t.Fatalf("away: %d %q %q", r.code, r.out, r.errOut)
	}
	if strings.Contains(r.out+r.errOut, testPassphrase) {
		t.Fatal("passphrase echoed")
	}

	done = away()
	ap = waitPending()
	if code, out, errOut := td.run("", "approvals", "deny", ap.ID); code != 0 || !strings.Contains(out, "Denied") {
		t.Fatalf("deny: %d %q %q", code, out, errOut)
	}
	if r := <-done; r.code == 0 || !strings.Contains(r.errOut, "denied") {
		t.Fatalf("denied away: %d %q", r.code, r.errOut)
	}
	if code, _, errOut := td.run(testPassphrase+"\n", "approvals", "approve", "nope", "--stdin"); code != exitError || !strings.Contains(errOut, "no such pending approval") {
		t.Fatalf("unknown id: %d %q", code, errOut)
	}
}

func TestStopCommand(t *testing.T) {
	td := startTestDaemon(t, true)
	// The test daemon runs via Start, not Run: close it when asked to stop,
	// as Run does.
	go func() {
		<-td.d.StopRequested()
		td.d.Close()
	}()
	code, out, errOut := td.run("", "stop")
	if code != 0 || !strings.Contains(out, "daemon stopped") {
		t.Fatalf("stop: %d %q %q", code, out, errOut)
	}
	if code, out, _ := td.run("", "stop"); code != 0 || !strings.Contains(out, "not running") {
		t.Fatalf("stop again: %d %q", code, out)
	}
}

func TestRecoveryRotateCommand(t *testing.T) {
	td := startTestDaemon(t, true, func(o *daemon.Options) { o.Approver = manualApprover{} })
	if code, _, errOut := td.run(testPassphrase+"\n", "unlock", "--stdin"); code != 0 {
		t.Fatalf("unlock: %q", errOut)
	}
	c := td.client()
	defer c.Close()
	type res struct {
		code        int
		out, errOut string
	}
	done := make(chan res, 1)
	go func() {
		code, out, errOut := td.run("", "recovery", "rotate")
		done <- res{code, out, errOut}
	}()
	var ap client.Approval
	for i := 0; i < 500 && ap.ID == ""; i++ {
		if list, _ := c.Approvals(t.Context()); len(list) == 1 {
			ap = list[0]
		} else {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if ap.ID == "" || ap.Requester != os.Getpid() || ap.Kind != "admin_change" {
		t.Fatalf("approval = %+v", ap)
	}
	// The current recovery code is a valid step-up secret.
	if code, _, errOut := td.run(td.recovery+"\n", "approvals", "approve", ap.ID, "--stdin"); code != 0 {
		t.Fatalf("approve: %d %q", code, errOut)
	}
	r := <-done
	if r.code != 0 || !strings.Contains(r.out, "New recovery code") {
		t.Fatalf("rotate: %d %q %q", r.code, r.out, r.errOut)
	}
	newCode := ""
	for _, line := range strings.Split(r.out, "\n") {
		if strings.HasPrefix(line, "    ") {
			newCode = strings.TrimSpace(line)
		}
	}
	if newCode == "" || newCode == td.recovery || !looksLikeSecret(newCode) {
		t.Fatalf("new code not printed: %q", r.out)
	}
	if strings.Contains(r.out+r.errOut, td.recovery) {
		t.Fatal("old recovery code echoed")
	}
	// The audit log never holds either code.
	recs, err := c.AuditTail(t.Context(), 100)
	if err != nil {
		t.Fatal(err)
	}
	rotated := false
	for _, rec := range recs {
		b := fmt.Sprint(rec.Fields)
		if strings.Contains(b, newCode) || strings.Contains(b, td.recovery) {
			t.Fatalf("audit record %s holds a recovery code", rec.Type)
		}
		rotated = rotated || (rec.Type == "rekey" && rec.Fields["op"] == "rotate_recovery" && rec.Fields["ok"] == true)
	}
	if !rotated {
		t.Fatal("no rekey audit record")
	}
	if code, _, errOut := td.run("", "lock"); code != 0 {
		t.Fatalf("lock: %q", errOut)
	}
	if code, _, errOut := td.run(td.recovery+"\n", "unlock", "--method", "recovery", "--stdin"); code != exitError || !strings.Contains(errOut, "wrong passphrase") {
		t.Fatalf("old code unlock: %d %q", code, errOut)
	}
	if code, _, errOut := td.run(newCode+"\n", "unlock", "--method", "recovery", "--stdin"); code != 0 {
		t.Fatalf("new code unlock: %d %q", code, errOut)
	}
	if code, _, errOut := td.run("", "lock"); code != 0 {
		t.Fatalf("lock: %q", errOut)
	}
	if code, _, errOut := td.run(testPassphrase+"\n", "unlock", "--stdin"); code != 0 {
		t.Fatalf("passphrase unlock after rotation: %d %q", code, errOut)
	}
}
