// Package config loads keyleash's TOML configuration. Every option has a
// recommended default, so a missing file means "recommended". A file only
// needs the options it changes.
package config

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/h-a-forster/keyleash/internal/money"
	"github.com/h-a-forster/keyleash/internal/provider"
)

// Duration is a time.Duration written as "10m", "12h", "60s" in TOML.
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("bad duration %q", string(b))
	}
	if v < 0 {
		return fmt.Errorf("negative duration %q", string(b))
	}
	d.Duration = v
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.Duration.String()), nil }

// Amount is a money amount written as "$2", "2.50" or "150c" in TOML. A nil
// *Amount means "no limit".
type Amount struct{ money.Micros }

// UnmarshalText implements encoding.TextUnmarshaler.
func (a *Amount) UnmarshalText(b []byte) error {
	v, err := money.Parse(string(b))
	if err != nil {
		return err
	}
	a.Micros = v
	return nil
}

// MarshalText implements encoding.TextMarshaler.
func (a Amount) MarshalText() ([]byte, error) { return []byte(a.Micros.String()), nil }

func amt(s string) *Amount {
	v, err := money.Parse(s)
	if err != nil {
		panic(err)
	}
	return &Amount{v}
}

// Limits is a set of spend limits for one scope. Nil fields are unlimited.
// Concurrency 0 means unlimited.
type Limits struct {
	Request     *Amount `toml:"request"`
	Minute      *Amount `toml:"minute"`
	Hour        *Amount `toml:"hour"`
	Session     *Amount `toml:"session"`
	Day         *Amount `toml:"day"`
	Month       *Amount `toml:"month"`
	Concurrency int     `toml:"concurrency"`
}

// Windows returns the configured limits keyed by budget window name.
func (l Limits) Windows() map[string]money.Micros {
	out := map[string]money.Micros{}
	for name, a := range map[string]*Amount{
		"request": l.Request, "minute": l.Minute, "hour": l.Hour,
		"session": l.Session, "day": l.Day, "month": l.Month,
	} {
		if a != nil {
			out[name] = a.Micros
		}
	}
	return out
}

// AwayLimits apply while the owner is away (idle or screen locked).
type AwayLimits struct {
	Total       *Amount `toml:"total"`
	Concurrency int     `toml:"concurrency"`
	// AllowNewRunPasses permits `keyleash run` while away.
	AllowNewRunPasses bool `toml:"allow_new_run_passes"`
	// MaxGrant caps the budget of one unattended grant (`keyleash away`).
	MaxGrant *Amount `toml:"max_grant"`
}

// PassDefaults apply to passes created without explicit settings.
type PassDefaults struct {
	TTL         Duration `toml:"ttl"`
	RunTTL      Duration `toml:"run_ttl"`
	Day         *Amount  `toml:"day"`
	Concurrency int      `toml:"concurrency"`
	// MaxRunBudget is the largest budget a run pass bound to the calling
	// process may get without a step-up (spec §6); it is also the default
	// budget of run passes created without one.
	MaxRunBudget *Amount `toml:"max_run_budget"`
}

// Config is the effective configuration.
type Config struct {
	Profile string `toml:"profile"`

	Proxy struct {
		Port           int      `toml:"port"`
		BodyLimit      int64    `toml:"body_limit"`
		AddStreamUsage bool     `toml:"add_stream_usage"`
		AllowedOrigins []string `toml:"allowed_origins"`
	} `toml:"proxy"`

	Presence struct {
		IdleAfter Duration `toml:"idle_after"`
		// ScreenLock is "away" or "lock".
		ScreenLock string   `toml:"screen_lock"`
		AwayMax    Duration `toml:"away_max"`
		MaxLease   Duration `toml:"max_lease"`
		Poll       Duration `toml:"poll"`
		// CountInjectedInput treats synthetic input (SendInput, remote
		// control tools) as presence. Off by default so a computer-use agent
		// driving the desktop cannot keep the session "present".
		CountInjectedInput bool `toml:"count_injected_input"`
	} `toml:"presence"`

	Limits struct {
		Global   Limits            `toml:"global"`
		Provider map[string]Limits `toml:"provider"`
		// Model limits are keyed by a glob matched against the model id.
		Model map[string]Limits `toml:"model"`
		Away  AwayLimits        `toml:"away"`
		Pass  PassDefaults      `toml:"pass"`
		// OnExceed is "deny" or "approve".
		OnExceed string `toml:"on_exceed"`
	} `toml:"limits"`

	Tripwire struct {
		Window    Duration `toml:"window"`
		Threshold *Amount  `toml:"threshold"`
	} `toml:"tripwire"`

	Models struct {
		// Unknown is the policy for models without a price: "approve",
		// "deny" or "allow". Allowed or approved requests reserve their
		// input estimate plus max output (or AssumeMaxOutputTokens) at the
		// provider's most expensive known rates and settle reported usage at
		// those rates (spec §7.5); requests whose input cannot be bounded
		// always need approval and reserve the per-request limit.
		Unknown               string   `toml:"unknown"`
		Allow                 []string `toml:"allow"`
		Deny                  []string `toml:"deny"`
		AssumeMaxOutputTokens int64    `toml:"assume_max_output_tokens"`
	} `toml:"models"`

	Approval struct {
		// Method is "hello", "passphrase", "console" or "deny" (spec §9).
		Method  string   `toml:"method"`
		Timeout Duration `toml:"timeout"`
		// GrantMaxMultiple caps a grant attached to an over-limit approval
		// at this many times the exceeded limit.
		GrantMaxMultiple int `toml:"grant_max_multiple"`
		// GrantMaxDuration caps how long such a grant lasts.
		GrantMaxDuration Duration `toml:"grant_max_duration"`
	} `toml:"approval"`

	Pricing struct {
		Override string `toml:"override"`
	} `toml:"pricing"`

	Audit struct {
		AnchorEvery Duration `toml:"anchor_every"`
	} `toml:"audit"`

	Run struct {
		// KillOnDaemonExit ends every process of a `keyleash run` session
		// when the daemon exits (Windows job objects), so a daemon restart
		// cannot leave confined agents running unconfined.
		KillOnDaemonExit bool `toml:"kill_on_daemon_exit"`
	} `toml:"run"`
}

// Profiles are named starting points; a config file overrides on top.
var Profiles = []string{"recommended", "strict", "relaxed"}

// Default returns the configuration for a profile.
func Default(profile string) (*Config, error) {
	c := &Config{Profile: profile}
	c.Proxy.Port = 47114
	c.Proxy.BodyLimit = 32 << 20
	c.Proxy.AddStreamUsage = true

	c.Presence.IdleAfter = Duration{10 * time.Minute}
	c.Presence.ScreenLock = "away"
	c.Presence.AwayMax = Duration{2 * time.Hour}
	c.Presence.MaxLease = Duration{12 * time.Hour}
	c.Presence.Poll = Duration{5 * time.Second}

	c.Limits.Global = Limits{
		Request: amt("$5"), Session: amt("$20"), Day: amt("$30"), Month: amt("$200"),
		Concurrency: 8,
	}
	c.Limits.Provider = map[string]Limits{}
	c.Limits.Model = map[string]Limits{}
	c.Limits.Away = AwayLimits{Total: amt("$3"), Concurrency: 2, MaxGrant: amt("$50")}
	c.Limits.Pass = PassDefaults{
		TTL: Duration{24 * time.Hour}, RunTTL: Duration{12 * time.Hour}, Concurrency: 4,
		MaxRunBudget: amt("$10"),
	}
	c.Limits.OnExceed = "deny"

	c.Tripwire.Window = Duration{5 * time.Minute}
	c.Tripwire.Threshold = amt("$5")

	c.Models.Unknown = "approve"
	c.Models.AssumeMaxOutputTokens = 64_000

	c.Approval.Method = "hello"
	c.Approval.Timeout = Duration{60 * time.Second}
	c.Approval.GrantMaxMultiple = 5
	c.Approval.GrantMaxDuration = Duration{24 * time.Hour}

	c.Audit.AnchorEvery = Duration{10 * time.Minute}
	c.Run.KillOnDaemonExit = true

	switch profile {
	case "", "recommended":
		c.Profile = "recommended"
	case "strict":
		c.Presence.IdleAfter = Duration{5 * time.Minute}
		c.Presence.ScreenLock = "lock"
		c.Presence.AwayMax = Duration{30 * time.Minute}
		c.Presence.MaxLease = Duration{8 * time.Hour}
		c.Limits.Global = Limits{
			Request: amt("$1"), Session: amt("$5"), Day: amt("$10"), Month: amt("$100"),
			Concurrency: 4,
		}
		c.Limits.Away = AwayLimits{Total: amt("$1"), Concurrency: 1, MaxGrant: amt("$20")}
		c.Limits.Pass.TTL = Duration{8 * time.Hour}
		c.Limits.Pass.Concurrency = 2
		c.Limits.OnExceed = "approve"
		c.Tripwire.Threshold = amt("$2")
		c.Models.Unknown = "deny"
	case "relaxed":
		c.Presence.IdleAfter = Duration{30 * time.Minute}
		c.Presence.AwayMax = Duration{8 * time.Hour}
		c.Presence.MaxLease = Duration{24 * time.Hour}
		c.Limits.Global = Limits{
			Request: amt("$10"), Session: amt("$50"), Day: amt("$100"), Month: amt("$1000"),
			Concurrency: 16,
		}
		c.Limits.Away = AwayLimits{Total: amt("$20"), Concurrency: 4, AllowNewRunPasses: true, MaxGrant: amt("$200")}
		c.Limits.Pass.TTL = Duration{7 * 24 * time.Hour}
		c.Limits.Pass.Concurrency = 8
		c.Tripwire.Threshold = amt("$25")
	default:
		return nil, fmt.Errorf("config: unknown profile %q (want one of %s)", profile, strings.Join(Profiles, ", "))
	}
	return c, nil
}

// Load reads the config file at p. A missing file yields the recommended
// profile. The file's `profile` key picks the base; every other key overrides
// it. Unknown keys are an error so typos don't silently weaken protection.
func Load(p string) (*Config, error) {
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return Default("recommended")
	}
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return Parse(string(raw))
}

// Parse decodes TOML text on top of its profile's defaults and validates it.
func Parse(text string) (*Config, error) {
	var head struct {
		Profile string `toml:"profile"`
	}
	if _, err := toml.Decode(text, &head); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c, err := Default(head.Profile)
	if err != nil {
		return nil, err
	}
	md, err := toml.Decode(text, c)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if und := md.Undecoded(); len(und) > 0 {
		keys := make([]string, len(und))
		for i, k := range und {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("config: unknown keys: %s", strings.Join(keys, ", "))
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks ranges and enumerations.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	if c.Proxy.Port < 1 || c.Proxy.Port > 65535 {
		bad("proxy.port %d out of range", c.Proxy.Port)
	}
	if c.Proxy.BodyLimit < 1<<10 || c.Proxy.BodyLimit > 1<<30 {
		bad("proxy.body_limit must be between 1 KiB and 1 GiB")
	}
	for _, o := range c.Proxy.AllowedOrigins {
		if o == "*" || !(strings.HasPrefix(o, "http://") || strings.HasPrefix(o, "https://")) {
			bad("proxy.allowed_origins: %q must be an exact http(s) origin", o)
		}
	}
	if c.Presence.ScreenLock != "away" && c.Presence.ScreenLock != "lock" {
		bad("presence.screen_lock must be \"away\" or \"lock\"")
	}
	if c.Presence.IdleAfter.Duration < time.Minute {
		bad("presence.idle_after must be at least 1m")
	}
	if c.Presence.MaxLease.Duration < 5*time.Minute || c.Presence.MaxLease.Duration > 7*24*time.Hour {
		bad("presence.max_lease must be between 5m and 168h")
	}
	if c.Presence.AwayMax.Duration > c.Presence.MaxLease.Duration {
		bad("presence.away_max cannot exceed presence.max_lease")
	}
	if c.Presence.Poll.Duration < time.Second || c.Presence.Poll.Duration > time.Minute {
		bad("presence.poll must be between 1s and 1m")
	}
	checkLimits := func(name string, l Limits) {
		if l.Concurrency < 0 {
			bad("%s.concurrency cannot be negative", name)
		}
	}
	checkLimits("limits.global", c.Limits.Global)
	for p, l := range c.Limits.Provider {
		if _, ok := provider.Get(p); !ok {
			bad("limits.provider.%s: unknown provider", p)
		}
		checkLimits("limits.provider."+p, l)
	}
	for g, l := range c.Limits.Model {
		if _, err := path.Match(g, ""); err != nil {
			bad("limits.model.%q: bad glob", g)
		}
		checkLimits("limits.model."+g, l)
	}
	if c.Limits.Away.Concurrency < 0 {
		bad("limits.away.concurrency cannot be negative")
	}
	if c.Limits.Away.MaxGrant == nil || c.Limits.Away.MaxGrant.Micros <= 0 {
		bad("limits.away.max_grant must be positive")
	}
	if c.Limits.Pass.TTL.Duration <= 0 || c.Limits.Pass.RunTTL.Duration <= 0 {
		bad("limits.pass.ttl and run_ttl must be positive")
	}
	if c.Limits.OnExceed != "deny" && c.Limits.OnExceed != "approve" {
		bad("limits.on_exceed must be \"deny\" or \"approve\"")
	}
	if c.Tripwire.Window.Duration < time.Minute && c.Tripwire.Threshold != nil {
		bad("tripwire.window must be at least 1m")
	}
	switch c.Models.Unknown {
	case "approve", "deny", "allow":
	default:
		bad("models.unknown must be \"approve\", \"deny\" or \"allow\"")
	}
	for _, g := range append(append([]string{}, c.Models.Allow...), c.Models.Deny...) {
		if _, err := path.Match(g, ""); err != nil {
			bad("models: bad glob %q", g)
		}
	}
	if c.Models.AssumeMaxOutputTokens < 1 {
		bad("models.assume_max_output_tokens must be positive")
	}
	switch c.Approval.Method {
	case "hello", "passphrase", "console", "deny":
	default:
		bad("approval.method must be \"hello\", \"passphrase\", \"console\" or \"deny\"")
	}
	if c.Approval.GrantMaxMultiple < 1 || c.Approval.GrantMaxMultiple > 100 {
		bad("approval.grant_max_multiple must be between 1 and 100")
	}
	if c.Approval.GrantMaxDuration.Duration < time.Minute || c.Approval.GrantMaxDuration.Duration > 7*24*time.Hour {
		bad("approval.grant_max_duration must be between 1m and 168h")
	}
	if c.Limits.Pass.MaxRunBudget != nil && c.Limits.Pass.MaxRunBudget.Micros <= 0 {
		bad("limits.pass.max_run_budget must be positive")
	}
	if c.Approval.Timeout.Duration < 5*time.Second || c.Approval.Timeout.Duration > 10*time.Minute {
		bad("approval.timeout must be between 5s and 10m")
	}
	if len(errs) > 0 {
		return fmt.Errorf("config: %w", errors.Join(errs...))
	}
	return nil
}

// Encode renders the config as TOML (used by `keyleash config show`).
func (c *Config) Encode() (string, error) {
	var b strings.Builder
	if err := toml.NewEncoder(&b).Encode(c); err != nil {
		return "", err
	}
	return b.String(), nil
}
