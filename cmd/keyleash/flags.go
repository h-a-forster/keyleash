package main

import (
	"errors"
	"flag"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/money"
)

// newFlagSet returns a flag set that never prints on its own: parse errors
// are rewritten by parseFlags so that a mistyped value is never echoed back
// (it might be a secret pasted into the wrong place).
func newFlagSet(cmd string) *flag.FlagSet {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parseFlags parses args with fs and returns the positional arguments.
// With intersperse, flags may follow positional arguments ("add anthropic
// --label work"); everything after "--" is positional either way. Without
// it, parsing stops at the first positional argument (used by `run`, whose
// command line belongs to the child).
func parseFlags(fs *flag.FlagSet, args []string, intersperse bool) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, usagef(fs.Name(), "use 'keyleash help %s' for help", fs.Name())
			}
			return nil, usagef(fs.Name(), "%s", sanitizeFlagError(err))
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		// flag stops after "--" too; detect it from what it consumed.
		consumed := len(args) - len(rest)
		if consumed > 0 && args[consumed-1] == "--" {
			return append(pos, rest...), nil
		}
		if !intersperse {
			return append(pos, rest...), nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

var flagNameRE = regexp.MustCompile(`^-{1,2}[A-Za-z][A-Za-z0-9-]{0,31}$`)

// dashes renders a flag name the way the help text writes it ("--name").
func dashes(name string) string {
	return "--" + strings.TrimLeft(name, "-")
}

// sanitizeFlagError rewrites a flag package error without echoing values.
func sanitizeFlagError(err error) string {
	msg := err.Error()
	switch {
	case strings.HasPrefix(msg, "flag provided but not defined: "):
		name := strings.TrimPrefix(msg, "flag provided but not defined: ")
		if flagNameRE.MatchString(name) {
			return "unknown flag " + dashes(name)
		}
		return "unknown flag"
	case strings.HasPrefix(msg, "flag needs an argument: "):
		name := strings.TrimPrefix(msg, "flag needs an argument: ")
		if flagNameRE.MatchString(name) {
			return "flag " + dashes(name) + " needs a value"
		}
		return "a flag needs a value"
	case strings.HasPrefix(msg, "invalid value "), strings.HasPrefix(msg, "invalid boolean value "):
		// `invalid value "<v>" for flag -<name>: <reason>`; drop <v>.
		rest := msg
		if i := strings.Index(rest, " for flag "); i >= 0 {
			rest = rest[i+len(" for flag "):]
			name, reason, _ := strings.Cut(rest, ": ")
			if flagNameRE.MatchString(name) {
				if reason != "" && !strings.Contains(reason, `"`) {
					return "invalid value for " + dashes(name) + ": " + reason
				}
				return "invalid value for " + dashes(name)
			}
		}
		return "invalid flag value"
	case strings.HasPrefix(msg, "bad flag syntax"):
		return "bad flag syntax"
	}
	return "invalid flags"
}

// sanitizeArg makes an argument safe to echo in an error: it is shown only
// when it is short and plainly not a secret.
func sanitizeArg(s string) string {
	if len(s) > 32 || looksLikeSecret(s) || strings.ContainsAny(s, "\r\n\x00") {
		return "<redacted>"
	}
	return s
}

// moneyFlag is a money amount flag ("5", "$5", "2.50", "150c").
type moneyFlag struct {
	v   money.Micros
	set bool
}

func (m *moneyFlag) String() string {
	if m == nil || !m.set {
		return ""
	}
	return m.v.String()
}

func (m *moneyFlag) Set(s string) error {
	v, err := money.Parse(strings.TrimSpace(s))
	if err != nil {
		return errors.New("want an amount like 5, 2.50 or $5")
	}
	if v <= 0 {
		return errors.New("must be positive")
	}
	m.v, m.set = v, true
	return nil
}

// durationFlag is a duration flag accepting Go durations plus days ("7d").
type durationFlag struct {
	v   time.Duration
	set bool
}

func (d *durationFlag) String() string {
	if d == nil || !d.set {
		return ""
	}
	return d.v.String()
}

func (d *durationFlag) Set(s string) error {
	v, err := parseDuration(s)
	if err != nil {
		return err
	}
	if v <= 0 {
		return errors.New("must be positive")
	}
	d.v, d.set = v, true
	return nil
}

// parseDuration parses "90s", "10m", "8h", "1h30m" or "7d" (days).
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if n, ok := strings.CutSuffix(s, "d"); ok && n != "" {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 || days > 3650 {
			return 0, errors.New(`want a duration like 30m, 8h or 7d`)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0, errors.New(`want a duration like 30m, 8h or 7d`)
	}
	return v, nil
}

// listFlag collects comma-separated values; it may be repeated.
type listFlag []string

func (l *listFlag) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, ",")
}

func (l *listFlag) Set(s string) error {
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			*l = append(*l, part)
		}
	}
	return nil
}

// limitsFlag collects per-pass limits written window=amount
// ("day=5", "hour=$1"); it may be repeated or comma-separated.
type limitsFlag []client.PassLimit

func (l *limitsFlag) String() string {
	if l == nil {
		return ""
	}
	parts := make([]string, 0, len(*l))
	for _, x := range *l {
		parts = append(parts, x.Window+"="+x.Amount.String())
	}
	return strings.Join(parts, ",")
}

func (l *limitsFlag) Set(s string) error {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		w, amt, ok := strings.Cut(part, "=")
		if !ok {
			return errors.New("want window=amount, e.g. day=5")
		}
		win := budget.Window(strings.ToLower(strings.TrimSpace(w)))
		if !win.Valid() {
			return errors.New("window must be request, minute, hour, day, month or session")
		}
		v, err := money.Parse(strings.TrimSpace(amt))
		if err != nil || v <= 0 {
			return errors.New("amount must be positive, e.g. day=5")
		}
		*l = append(*l, client.PassLimit{Window: string(win), Amount: v})
	}
	return nil
}

// budgetLimits turns a total budget into per-pass limits. A pass's
// "session" window resets whenever the vault is unlocked and its "month"
// window at the start of a calendar month; holding both caps the pass's
// total spend unless both reset together.
func budgetLimits(total money.Micros) []client.PassLimit {
	return []client.PassLimit{
		{Window: string(budget.WindowSession), Amount: total},
		{Window: string(budget.WindowMonth), Amount: total},
	}
}

// parseSince parses --since: RFC 3339, a date (local midnight), or a
// duration back from now ("7d", "24h").
func parseSince(s string, now time.Time) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		return t, nil
	}
	if d, err := parseDuration(s); err == nil && d > 0 {
		return now.Add(-d), nil
	}
	return time.Time{}, errors.New("--since wants a date (2026-10-01), an RFC 3339 time, or a duration like 7d")
}
