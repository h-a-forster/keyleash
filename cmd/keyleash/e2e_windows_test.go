//go:build windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
)

// helperSource is a tiny client built by the end-to-end test: it records
// the pass it received (so the test can try it from outside the process
// tree, and again after the run), optionally waits for a "go" file, calls
// the proxy with the environment `keyleash run` gave it, prints what it
// saw, and exits with code 7 so exit-code propagation is checked too.
const helperSource = `package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	base := os.Getenv("ANTHROPIC_BASE_URL")
	key := os.Getenv("ANTHROPIC_API_KEY")
	if err := os.WriteFile(os.Args[1], []byte(key), 0o600); err != nil {
		fmt.Println("write:", err)
		os.Exit(2)
	}
	if len(os.Args) > 2 {
		deadline := time.Now().Add(30 * time.Second)
		for {
			if _, err := os.Stat(os.Args[2]); err == nil {
				break
			}
			if time.Now().After(deadline) {
				fmt.Println("timed out waiting for", os.Args[2])
				os.Exit(2)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	body := ` + "`" + anthropicRequest + "`" + `
	req, err := http.NewRequest("POST", base+"/v1/messages", strings.NewReader(body))
	if err != nil {
		fmt.Println("request:", err)
		os.Exit(2)
	}
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		fmt.Println("call:", err)
		os.Exit(2)
	}
	resp.Body.Close()
	fmt.Printf("status=%d\nbase=%s\nauth_token=%q\npass_id=%s\nkey_is_pass=%v\n", resp.StatusCode, base,
		os.Getenv("ANTHROPIC_AUTH_TOKEN"), os.Getenv("KEYLEASH_PASS_ID"), strings.HasPrefix(key, "klp_"))
	os.Exit(7)
}
`

// TestRunEndToEnd builds the real keyleash binary and a helper program,
// starts an in-process daemon on the default admin pipe (with a fake TLS
// upstream), and runs `keyleash run -- helper`: the child's request must
// succeed with the injected pass, the CLI must exit with the child's code,
// and the pass must be revoked once the run is over.
func TestRunEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds binaries")
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go tool not in PATH")
	}
	// Refuse to touch a real daemon that owns the per-user pipe.
	if c, err := client.Dial(t.TempDir()); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, serr := c.Status(ctx)
		cancel()
		c.Close()
		if serr == nil {
			t.Skip("a keyleash daemon is already running for this user")
		}
	}
	td := startTestDaemon(t, false)

	bin := t.TempDir()
	kl := filepath.Join(bin, "keyleash.exe")
	build := exec.Command(goTool, "build", "-ldflags", "-X main.version=e2e-test", "-o", kl, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build keyleash: %v\n%s", err, out)
	}
	helperDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(helperDir, "main.go"), []byte(helperSource), 0o600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(bin, "helper.exe")
	hb := exec.Command(goTool, "build", "-o", helper, "main.go")
	hb.Dir = helperDir
	hb.Env = append(os.Environ(), "GO111MODULE=off")
	if out, err := hb.CombinedOutput(); err != nil {
		t.Fatalf("build helper: %v\n%s", err, out)
	}

	env := append(os.Environ(),
		"KEYLEASH_HOME="+td.dir,
		"ANTHROPIC_AUTH_TOKEN=must-be-removed",
		"ANTHROPIC_BASE_URL=https://api.anthropic.com",
	)
	var printed strings.Builder
	runKL := func(stdin string, args ...string) (int, string, string) {
		t.Helper()
		cmd := exec.Command(kl, args...)
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatalf("keyleash %v: %v", args, err)
		}
		printed.WriteString(out.String() + errb.String())
		return code, out.String(), errb.String()
	}

	if code, out, _ := runKL("", "version"); code != 0 || !strings.Contains(out, "e2e-test") {
		t.Fatalf("version: %d %q", code, out)
	}
	if code, _, errOut := runKL("", "add", "anthropic", fakeAnthropicKey); code != exitUsage || strings.Contains(errOut, fakeAnthropicKey) {
		t.Fatalf("key in argv: %d %q", code, errOut)
	}
	if code, out, errOut := runKL(testPassphrase+"\n", "unlock", "--stdin"); code != 0 {
		t.Fatalf("unlock: %d %q %q", code, out, errOut)
	}
	if code, out, errOut := runKL(fakeAnthropicKey+"\n", "add", "anthropic", "--stdin"); code != 0 {
		t.Fatalf("add: %d %q %q", code, out, errOut)
	}

	work := t.TempDir()
	tokenFile, goFile := filepath.Join(work, "token"), filepath.Join(work, "go")
	runCmd := exec.Command(kl, "run", "--providers", "anthropic", "--budget", "1", "--name", "e2e", "--", helper, tokenFile, goFile)
	runCmd.Env = env
	var runOut, runErr bytes.Buffer
	runCmd.Stdout, runCmd.Stderr = &runOut, &runErr
	if err := runCmd.Start(); err != nil {
		t.Fatal(err)
	}
	var token []byte
	for deadline := time.Now().Add(30 * time.Second); ; {
		if b, err := os.ReadFile(tokenFile); err == nil && len(b) > 0 {
			token = b
			break
		}
		if time.Now().After(deadline) {
			runCmd.Process.Kill()
			t.Fatalf("helper never started\nstderr: %s", runErr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !strings.HasPrefix(string(token), "klp_") {
		t.Fatalf("child got %q instead of a pass", token)
	}
	// While the run is live, the pass is refused from outside keyleash's
	// process tree (this test process is keyleash's parent).
	if st := callProxy(t, td.d.ProxyAddr(), string(token)); st != 401 {
		t.Errorf("run pass used by a non-descendant: status %d, want 401", st)
	}
	if err := os.WriteFile(goFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	err = runCmd.Wait()
	var ee *exec.ExitError
	code := 0
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	out, errOut := runOut.String(), runErr.String()
	printed.WriteString(out + errOut)
	if code != 7 {
		t.Fatalf("run exit code %d, want the child's 7\nstdout: %s\nstderr: %s\ndaemon log: %s", code, out, errOut, td.logs.String())
	}
	wantBase := "http://" + td.d.ProxyAddr() + "/anthropic"
	for _, want := range []string{"status=200", "base=" + wantBase + "\n", `auth_token=""`, "key_is_pass=true"} {
		if !strings.Contains(out, want) {
			t.Errorf("child output lacks %q:\n%s", want, out)
		}
	}
	if td.upHits.Load() != 1 {
		t.Errorf("upstream hits = %d, want 1", td.upHits.Load())
	}

	// The pass is revoked: it no longer works and is listed as revoked.
	if st := callProxy(t, td.d.ProxyAddr(), string(token)); st != 401 {
		t.Errorf("pass after run: status %d, want 401", st)
	}
	c := td.client()
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	passes, err := c.Passes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range passes {
		if p.Name == "e2e" {
			found = true
			if p.Kind != "run" || !p.Revoked || p.BindPID == 0 || !strings.EqualFold(p.BindImage, "keyleash.exe") {
				t.Errorf("run pass: %+v", p)
			}
			if !strings.Contains(out, "pass_id="+p.ID) {
				t.Errorf("child did not see KEYLEASH_PASS_ID=%s", p.ID)
			}
		}
	}
	if !found {
		t.Fatal("run pass not found")
	}

	// Exit codes of other commands propagate, and a command that cannot
	// start still has its pass revoked.
	code, out, errOut = runKL("", "run", "--providers", "anthropic", "--name", "e2e-cmd", "--", "cmd", "/c", "exit 3")
	if code != 3 {
		t.Fatalf("run cmd exit: %d %q %q", code, out, errOut)
	}
	if code, _, errOut := runKL("", "run", "--", filepath.Join(bin, "does-not-exist.exe")); code != exitCommandNotFound || !strings.Contains(errOut, "command not found") {
		t.Fatalf("missing command: %d %q", code, errOut)
	}
	passes, err = c.Passes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range passes {
		if p.Kind == "run" && !p.Revoked {
			t.Errorf("run pass %s (%s) left active", p.ID, p.Name)
		}
	}

	for name, s := range map[string]string{"cli output": printed.String(), "daemon log": td.logs.String()} {
		for _, secret := range []string{fakeAnthropicKey, testPassphrase} {
			if strings.Contains(s, secret) {
				t.Errorf("%s contains a secret", name)
			}
		}
	}
}
