package main

import (
	"encoding/base64"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"
)

const testToken = "klp_ABCDEFGHIJ_secretsecretsecretsecretsecretsecretsecr"

func planMap(p envPlan) map[string]string {
	m := map[string]string{}
	for _, v := range p.Set {
		m[v.Name] = v.Value
	}
	return m
}

func TestBuildEnvPlanPerProvider(t *testing.T) {
	const addr = "127.0.0.1:47114"
	tests := []struct {
		provider string
		set      map[string]string
		absent   []string
		unset    []string
	}{
		{
			provider: "anthropic",
			set: map[string]string{
				"ANTHROPIC_BASE_URL":          "http://127.0.0.1:47114/anthropic",
				"KEYLEASH_ANTHROPIC_BASE_URL": "http://127.0.0.1:47114/anthropic",
				"ANTHROPIC_API_KEY":           testToken,
				"KEYLEASH_PROXY":              "http://127.0.0.1:47114",
				"KEYLEASH_PASS_ID":            "p1",
			},
			unset: []string{"ANTHROPIC_AUTH_TOKEN"},
		},
		{
			provider: "openai",
			set: map[string]string{
				"OPENAI_BASE_URL":          "http://127.0.0.1:47114/openai/v1",
				"KEYLEASH_OPENAI_BASE_URL": "http://127.0.0.1:47114/openai/v1",
				"OPENAI_API_KEY":           testToken,
			},
			unset: []string{"OPENAI_API_BASE"},
		},
		{
			provider: "openrouter",
			set: map[string]string{
				"KEYLEASH_OPENROUTER_BASE_URL": "http://127.0.0.1:47114/openrouter/v1",
				"OPENROUTER_API_KEY":           testToken,
			},
			absent: []string{"OPENROUTER_BASE_URL"},
		},
		{
			provider: "gemini",
			set: map[string]string{
				"KEYLEASH_GEMINI_BASE_URL": "http://127.0.0.1:47114/gemini",
				"GEMINI_API_KEY":           testToken,
			},
			unset: []string{"GOOGLE_API_KEY"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			plan, err := buildEnvPlan(addr, []string{tt.provider}, testToken, "p1", nil)
			if err != nil {
				t.Fatal(err)
			}
			got := planMap(plan)
			for k, v := range tt.set {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
			for _, k := range tt.absent {
				if _, ok := got[k]; ok {
					t.Errorf("%s should not be set", k)
				}
			}
			if !reflect.DeepEqual(plan.Unset, tt.unset) {
				t.Errorf("unset = %v, want %v", plan.Unset, tt.unset)
			}
			if _, ok := got["NO_PROXY"]; ok {
				t.Error("NO_PROXY set without an outbound proxy")
			}
		})
	}
}

func TestBuildEnvPlanMultiAndIPv6(t *testing.T) {
	plan, err := buildEnvPlan("[::1]:9000", []string{"openai", "anthropic"}, testToken, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := planMap(plan)
	if got["ANTHROPIC_BASE_URL"] != "http://[::1]:9000/anthropic" || got["OPENAI_BASE_URL"] != "http://[::1]:9000/openai/v1" {
		t.Errorf("urls: %v", got)
	}
	if _, ok := got["KEYLEASH_PASS_ID"]; ok {
		t.Error("empty pass id exported")
	}
	// Registry order, not argument order.
	if plan.Set[0].Name != "ANTHROPIC_BASE_URL" {
		t.Errorf("first var %s", plan.Set[0].Name)
	}
}

func TestBuildEnvPlanRejects(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:47114", "192.168.1.5:47114", "localhost:47114", "127.0.0.1:0", "", "evil.example:80"} {
		if _, err := buildEnvPlan(addr, []string{"anthropic"}, testToken, "", nil); err == nil {
			t.Errorf("address %q accepted", addr)
		}
	}
	if _, err := buildEnvPlan("127.0.0.1:1", []string{"nope"}, testToken, "", nil); err == nil {
		t.Error("unknown provider accepted")
	}
	if _, err := buildEnvPlan("127.0.0.1:1", nil, testToken, "", nil); err == nil {
		t.Error("no providers accepted")
	}
}

func TestNoProxy(t *testing.T) {
	plan, err := buildEnvPlan("127.0.0.1:1", []string{"anthropic"}, testToken, "", []string{"HTTPS_PROXY=http://corp:3128", "NO_PROXY=intranet,localhost"})
	if err != nil {
		t.Fatal(err)
	}
	got := planMap(plan)
	if got["NO_PROXY"] != "intranet,localhost,127.0.0.1,::1" || got["no_proxy"] != got["NO_PROXY"] {
		t.Errorf("NO_PROXY = %q / %q", got["NO_PROXY"], got["no_proxy"])
	}
}

func TestApplyEnvPlan(t *testing.T) {
	plan, err := buildEnvPlan("127.0.0.1:47114", []string{"anthropic"}, testToken, "p1", nil)
	if err != nil {
		t.Fatal(err)
	}
	environ := []string{
		"PATH=/bin",
		"ANTHROPIC_API_KEY=" + fakeAnthropicKey,
		"ANTHROPIC_AUTH_TOKEN=oauth-token",
		"ANTHROPIC_BASE_URL=https://api.anthropic.com",
		"=C:=C:\\work",
		"HOME=/home/me",
	}
	if runtime.GOOS == "windows" {
		environ = append(environ, "anthropic_api_key=lowercase-dup")
	}
	out := applyEnvPlan(environ, plan)
	joined := strings.Join(out, "\n")
	for _, bad := range []string{fakeAnthropicKey, "oauth-token", "https://api.anthropic.com", "lowercase-dup"} {
		if strings.Contains(joined, bad) {
			t.Errorf("child env still contains %q", bad)
		}
	}
	for _, want := range []string{"PATH=/bin", "HOME=/home/me", "=C:=C:\\work", "ANTHROPIC_API_KEY=" + testToken,
		"ANTHROPIC_BASE_URL=http://127.0.0.1:47114/anthropic", "KEYLEASH_PASS_ID=p1"} {
		if !slices.Contains(out, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestRenderEnv(t *testing.T) {
	plan := envPlan{
		Set:   []envVar{{"ANTHROPIC_BASE_URL", "http://127.0.0.1:47114/anthropic"}, {"ANTHROPIC_API_KEY", testToken}},
		Unset: []string{"ANTHROPIC_AUTH_TOKEN"},
	}
	tests := map[string]string{
		shellPOSIX: "unset ANTHROPIC_AUTH_TOKEN\n" +
			"export ANTHROPIC_BASE_URL='http://127.0.0.1:47114/anthropic'\n" +
			"export ANTHROPIC_API_KEY='" + testToken + "'\n",
		shellFish: "set -e ANTHROPIC_AUTH_TOKEN\n" +
			"set -gx ANTHROPIC_BASE_URL 'http://127.0.0.1:47114/anthropic'\n" +
			"set -gx ANTHROPIC_API_KEY '" + testToken + "'\n",
		shellPowerShell: "Remove-Item Env:ANTHROPIC_AUTH_TOKEN -ErrorAction SilentlyContinue\n" +
			"$env:ANTHROPIC_BASE_URL = 'http://127.0.0.1:47114/anthropic'\n" +
			"$env:ANTHROPIC_API_KEY = '" + testToken + "'\n",
		shellCmd: "set ANTHROPIC_AUTH_TOKEN=\n" +
			"set \"ANTHROPIC_BASE_URL=http://127.0.0.1:47114/anthropic\"\n" +
			"set \"ANTHROPIC_API_KEY=" + testToken + "\"\n",
	}
	for shell, want := range tests {
		got, err := renderEnv(shell, plan)
		if err != nil {
			t.Fatalf("%s: %v", shell, err)
		}
		if got != want {
			t.Errorf("%s:\n got %q\nwant %q", shell, got, want)
		}
	}
	if _, err := renderEnv("tcsh", plan); err == nil {
		t.Error("unknown shell accepted")
	}
}

func TestShellQuoting(t *testing.T) {
	tests := []struct {
		in, posix, fish, ps string
	}{
		{"plain", "'plain'", "'plain'", "'plain'"},
		{"it's", `'it'\''s'`, `'it\'s'`, "'it''s'"},
		{`a\b`, `'a\b'`, `'a\\b'`, `'a\b'`},
		{"$HOME `x` $(y)", "'$HOME `x` $(y)'", "'$HOME `x` $(y)'", "'$HOME `x` $(y)'"},
		{"\u2019smart", "'\u2019smart'", "'\u2019smart'", "'\u2019\u2019smart'"},
	}
	for _, tt := range tests {
		if got := quotePOSIX(tt.in); got != tt.posix {
			t.Errorf("posix(%q) = %q, want %q", tt.in, got, tt.posix)
		}
		if got := quoteFish(tt.in); got != tt.fish {
			t.Errorf("fish(%q) = %q, want %q", tt.in, got, tt.fish)
		}
		if got := quotePowerShell(tt.in); got != tt.ps {
			t.Errorf("powershell(%q) = %q, want %q", tt.in, got, tt.ps)
		}
	}
	for _, bad := range []string{`a"b`, "100%", "wow!"} {
		if _, err := quoteCmd(bad); err == nil {
			t.Errorf("cmd accepted %q", bad)
		}
	}
	for _, shell := range []string{shellPOSIX, shellFish, shellPowerShell, shellCmd} {
		if _, err := renderEnv(shell, envPlan{Set: []envVar{{"X", "a\nb"}}}); err == nil {
			t.Errorf("%s accepted a newline", shell)
		}
		if _, err := renderEnv(shell, envPlan{Set: []envVar{{"X;rm", "a"}}}); err == nil {
			t.Errorf("%s accepted a bad name", shell)
		}
		if _, err := renderEnv(shell, envPlan{Unset: []string{"$(x)"}}); err == nil {
			t.Errorf("%s accepted a bad unset name", shell)
		}
	}
}

// TestShellQuotingRoundTrip evaluates the rendered output in real shells
// when they are installed, proving the values survive unchanged.
func TestShellQuotingRoundTrip(t *testing.T) {
	value := `it's $HOME "q" ` + "`x` ‘curly’ back\\slash;&|"
	plan := envPlan{Set: []envVar{{"KL_TEST_VALUE", value}}}
	runs := []struct {
		shell, exe, print string
	}{
		{shellPOSIX, "bash", `printf '%s' "$KL_TEST_VALUE"`},
		{shellFish, "fish", `printf '%s' "$KL_TEST_VALUE"`},
		{shellPowerShell, "pwsh", `[Console]::Out.Write($env:KL_TEST_VALUE)`},
		{shellPowerShell, "powershell", `[Console]::Out.Write($env:KL_TEST_VALUE)`},
	}
	for _, r := range runs {
		t.Run(r.exe, func(t *testing.T) {
			if _, err := exec.LookPath(r.exe); err != nil {
				t.Skipf("%s not installed", r.exe)
			}
			script, err := renderEnv(r.shell, plan)
			if err != nil {
				t.Fatal(err)
			}
			var cmd *exec.Cmd
			if r.shell == shellPowerShell {
				// -EncodedCommand avoids Windows command-line quoting.
				full := "[Console]::OutputEncoding = [Text.Encoding]::UTF8\n" + script + r.print
				u := utf16.Encode([]rune(full))
				b := make([]byte, 2*len(u))
				for i, c := range u {
					b[2*i], b[2*i+1] = byte(c), byte(c>>8)
				}
				cmd = exec.Command(r.exe, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b))
			} else {
				cmd = exec.Command(r.exe, "-c", script+r.print)
				cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
			}
			out, err := cmd.Output()
			if err != nil {
				t.Skipf("%s did not run: %v", r.exe, err)
			}
			if string(out) != value {
				t.Errorf("round trip through %s: got %q, want %q", r.exe, out, value)
			}
		})
	}
}

func TestDetectShell(t *testing.T) {
	tests := []struct {
		parent, shellEnv, goos, want string
	}{
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "", "windows", shellPowerShell},
		{`C:\Program Files\PowerShell\7\pwsh.exe`, "", "windows", shellPowerShell},
		{`C:\Windows\System32\cmd.exe`, "", "windows", shellCmd},
		{`C:\Program Files\Git\usr\bin\bash.exe`, "", "windows", shellPOSIX},
		{"/usr/bin/fish", "/bin/bash", "linux", shellFish},
		{"-zsh", "", "darwin", shellPOSIX},
		{`C:\Program Files\Code\Code.exe`, "", "windows", shellPowerShell},
		{"/usr/bin/tmux", "/usr/bin/fish", "linux", shellFish},
		{"", "", "linux", shellPOSIX},
	}
	for _, tt := range tests {
		if got := detectShell(tt.parent, tt.shellEnv, tt.goos); got != tt.want {
			t.Errorf("detectShell(%q, %q, %s) = %s, want %s", tt.parent, tt.shellEnv, tt.goos, got, tt.want)
		}
	}
	for in, want := range map[string]string{"ZSH": shellPOSIX, "pwsh": shellPowerShell, "cmd.exe": shellCmd, "fish": shellFish} {
		if got, err := normalizeShell(in); err != nil || got != want {
			t.Errorf("normalizeShell(%q) = %s, %v", in, got, err)
		}
	}
	if _, err := normalizeShell("tcsh"); err == nil {
		t.Error("tcsh accepted")
	}
}
