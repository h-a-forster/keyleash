package main

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/h-a-forster/keyleash/internal/provider"
)

// conflictingEnv lists, per provider, variables that would make an SDK or
// CLI bypass the pass (another credential that takes precedence, or a
// legacy base-URL variable). They are removed from a child's environment.
var conflictingEnv = map[string][]string{
	// Claude Code sends ANTHROPIC_AUTH_TOKEN as a bearer token in
	// preference to ANTHROPIC_API_KEY.
	"anthropic": {"ANTHROPIC_AUTH_TOKEN"},
	// openai-python < 1.0 reads its base URL from OPENAI_API_BASE.
	"openai": {"OPENAI_API_BASE"},
	// google-genai prefers GOOGLE_API_KEY over GEMINI_API_KEY.
	"gemini": {"GOOGLE_API_KEY"},
}

// proxyEnvVars are the variables that route HTTP clients through an
// outbound proxy; loopback must bypass them.
var proxyEnvVars = []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"}

// envVar is one variable to set.
type envVar struct {
	Name, Value string
}

// envPlan is the set of environment changes that point clients at the
// proxy with a pass.
type envPlan struct {
	Set   []envVar
	Unset []string
}

// proxyRoot returns "http://<addr>" for the proxy's listen address, which
// must be a loopback IP and port.
func proxyRoot(addr string) (string, error) {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 {
		return "", fmt.Errorf("the daemon reported an unexpected proxy address %q (want a loopback address)", addr)
	}
	return "http://" + ap.String(), nil
}

// baseURL is the value of a provider's base-URL variable for proxy root
// root: root + "/" + name + BaseURLSuffix.
func baseURL(root string, p *provider.Provider) string {
	return root + "/" + p.Name + p.BaseURLSuffix
}

// providerEnvName is the keyleash-specific base-URL variable for p, set for
// every provider so tools without a standard variable can be configured.
func providerEnvName(p *provider.Provider) string {
	return "KEYLEASH_" + strings.ToUpper(p.Name) + "_BASE_URL"
}

// buildEnvPlan computes the variables for providers (in registry order)
// given the proxy address, the pass token and id, and the current
// environment (consulted only for outbound proxy settings).
//
// For each provider it sets BaseURLEnv (when the provider has one) to the
// proxy root plus BaseURLSuffix, KEYLEASH_<NAME>_BASE_URL to the same
// value, and KeyEnv to the pass token, and it unsets conflicting
// credentials. When an outbound proxy is configured, loopback is added to
// NO_PROXY/no_proxy so requests reach keyleash directly.
func buildEnvPlan(proxyAddr string, providers []string, token, passID string, environ []string) (envPlan, error) {
	root, err := proxyRoot(proxyAddr)
	if err != nil {
		return envPlan{}, err
	}
	if len(providers) == 0 {
		return envPlan{}, errors.New("no providers")
	}
	var plan envPlan
	for _, name := range provider.Names() {
		if !slices.Contains(providers, name) {
			continue
		}
		p, _ := provider.Get(name)
		u := baseURL(root, p)
		if p.BaseURLEnv != "" {
			plan.Set = append(plan.Set, envVar{p.BaseURLEnv, u})
		}
		plan.Set = append(plan.Set, envVar{providerEnvName(p), u})
		if p.KeyEnv != "" {
			plan.Set = append(plan.Set, envVar{p.KeyEnv, token})
		}
		plan.Unset = append(plan.Unset, conflictingEnv[name]...)
	}
	for _, name := range providers {
		if _, ok := provider.Get(name); !ok {
			return envPlan{}, fmt.Errorf("unknown provider %q", sanitizeArg(name))
		}
	}
	plan.Set = append(plan.Set, envVar{"KEYLEASH_PROXY", root})
	if passID != "" {
		plan.Set = append(plan.Set, envVar{"KEYLEASH_PASS_ID", passID})
	}
	if np, ok := noProxyValue(environ); ok {
		plan.Set = append(plan.Set, envVar{"NO_PROXY", np}, envVar{"no_proxy", np})
	}
	return plan, nil
}

// noProxyValue returns NO_PROXY extended with loopback hosts when an
// outbound proxy variable is set; ok is false when no proxy is configured.
func noProxyValue(environ []string) (string, bool) {
	vals := map[string]string{}
	for _, kv := range environ {
		k, v, _ := strings.Cut(kv, "=")
		vals[k] = v
	}
	proxied := false
	for _, k := range proxyEnvVars {
		if strings.TrimSpace(vals[k]) != "" {
			proxied = true
		}
	}
	if !proxied {
		return "", false
	}
	cur := vals["NO_PROXY"]
	if cur == "" {
		cur = vals["no_proxy"]
	}
	var parts []string
	for _, p := range strings.Split(cur, ",") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	for _, h := range []string{"127.0.0.1", "localhost", "::1"} {
		if !slices.Contains(parts, h) {
			parts = append(parts, h)
		}
	}
	return strings.Join(parts, ","), true
}

// envNameEqual compares variable names the way the OS does (Windows
// environment names are case-insensitive).
func envNameEqual(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// applyEnvPlan returns environ with plan applied: every variable the plan
// sets or unsets is removed, then the plan's values are appended.
func applyEnvPlan(environ []string, plan envPlan) []string {
	drop := func(name string) bool {
		for _, v := range plan.Set {
			if envNameEqual(name, v.Name) {
				return true
			}
		}
		for _, u := range plan.Unset {
			if envNameEqual(name, u) {
				return true
			}
		}
		return false
	}
	out := make([]string, 0, len(environ)+len(plan.Set))
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		// Windows keeps per-drive cwd entries like "=C:=C:\x"; keep them.
		if name == "" || !drop(name) {
			out = append(out, kv)
		}
	}
	seen := map[string]bool{}
	for _, v := range plan.Set {
		key := v.Name
		if runtime.GOOS == "windows" {
			key = strings.ToUpper(key)
		}
		if seen[key] {
			continue // NO_PROXY and no_proxy are one variable on Windows
		}
		seen[key] = true
		out = append(out, v.Name+"="+v.Value)
	}
	return out
}

// Shells supported by `keyleash env`.
const (
	shellPOSIX      = "bash"
	shellFish       = "fish"
	shellPowerShell = "powershell"
	shellCmd        = "cmd"
)

// normalizeShell maps a user-supplied shell name to a supported one.
func normalizeShell(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bash", "zsh", "sh", "posix", "ksh", "dash":
		return shellPOSIX, nil
	case "fish":
		return shellFish, nil
	case "powershell", "pwsh", "ps":
		return shellPowerShell, nil
	case "cmd", "cmd.exe", "bat", "batch":
		return shellCmd, nil
	}
	return "", errors.New("shell must be bash, zsh, fish, powershell or cmd")
}

// shellFromImage maps an executable path to a shell, if it is one.
func shellFromImage(image string) (string, bool) {
	base := strings.ToLower(filepath.Base(strings.ReplaceAll(image, `\`, "/")))
	base = strings.TrimSuffix(base, ".exe")
	base = strings.TrimPrefix(base, "-") // login shells: "-bash"
	switch base {
	case "bash", "zsh", "sh", "ksh", "dash":
		return shellPOSIX, true
	case "fish":
		return shellFish, true
	case "powershell", "pwsh", "powershell_ise":
		return shellPowerShell, true
	case "cmd":
		return shellCmd, true
	}
	return "", false
}

// detectShell guesses the user's shell: the parent process image when it
// is a shell, then $SHELL, then the platform default (PowerShell on
// Windows, bash elsewhere).
func detectShell(parentImage, shellEnv, goos string) string {
	if s, ok := shellFromImage(parentImage); ok {
		return s
	}
	if s, ok := shellFromImage(shellEnv); ok && shellEnv != "" {
		return s
	}
	if goos == "windows" {
		return shellPowerShell
	}
	return shellPOSIX
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// renderEnv renders plan as commands for shell. Values are quoted for the
// shell; values that cannot be represented safely are refused.
func renderEnv(shell string, plan envPlan) (string, error) {
	var b strings.Builder
	for _, name := range plan.Unset {
		if !envNameRE.MatchString(name) {
			return "", fmt.Errorf("invalid variable name %q", name)
		}
		switch shell {
		case shellPOSIX:
			fmt.Fprintf(&b, "unset %s\n", name)
		case shellFish:
			fmt.Fprintf(&b, "set -e %s\n", name)
		case shellPowerShell:
			fmt.Fprintf(&b, "Remove-Item Env:%s -ErrorAction SilentlyContinue\n", name)
		case shellCmd:
			fmt.Fprintf(&b, "set %s=\n", name)
		default:
			return "", fmt.Errorf("unsupported shell %q", shell)
		}
	}
	for _, v := range plan.Set {
		if !envNameRE.MatchString(v.Name) {
			return "", fmt.Errorf("invalid variable name %q", v.Name)
		}
		if strings.ContainsAny(v.Value, "\x00\r\n") {
			return "", fmt.Errorf("value of %s contains a control character", v.Name)
		}
		switch shell {
		case shellPOSIX:
			fmt.Fprintf(&b, "export %s=%s\n", v.Name, quotePOSIX(v.Value))
		case shellFish:
			fmt.Fprintf(&b, "set -gx %s %s\n", v.Name, quoteFish(v.Value))
		case shellPowerShell:
			fmt.Fprintf(&b, "$env:%s = %s\n", v.Name, quotePowerShell(v.Value))
		case shellCmd:
			q, err := quoteCmd(v.Value)
			if err != nil {
				return "", fmt.Errorf("%s: %w", v.Name, err)
			}
			fmt.Fprintf(&b, "set \"%s=%s\"\n", v.Name, q)
		default:
			return "", fmt.Errorf("unsupported shell %q", shell)
		}
	}
	return b.String(), nil
}

// quotePOSIX single-quotes s for sh/bash/zsh: nothing is special inside
// single quotes, and a quote is written as '\”.
func quotePOSIX(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// quoteFish single-quotes s for fish, where \\ and \' are the only escapes
// inside single quotes.
func quoteFish(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "'", `\'`)
	return "'" + s + "'"
}

// quotePowerShell single-quotes s for PowerShell, where a quote is doubled.
// PowerShell also treats the typographic single quotes as quote marks, so
// they are doubled too.
func quotePowerShell(s string) string {
	var b strings.Builder
	b.WriteByte('\'')
	for _, r := range s {
		switch r {
		case '\'', '\u2018', '\u2019', '\u201A', '\u201B':
			b.WriteRune(r)
		}
		b.WriteRune(r)
	}
	b.WriteByte('\'')
	return b.String()
}

// quoteCmd validates s for cmd.exe's `set "NAME=value"` form. Inside the
// quotes & | < > ^ are literal, but " ends the quoting and % / ! trigger
// variable expansion, and there is no escape that works both interactively
// and in batch files, so those characters are refused.
func quoteCmd(s string) (string, error) {
	if strings.ContainsAny(s, "\"%!") {
		return "", errors.New(`value contains a character cmd.exe cannot quote safely (" % !)`)
	}
	return s, nil
}
