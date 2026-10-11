package config

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

func TestDefaultsValid(t *testing.T) {
	for _, p := range Profiles {
		c, err := Default(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if err := c.Validate(); err != nil {
			t.Errorf("%s: defaults invalid: %v", p, err)
		}
	}
	if _, err := Default("yolo"); err == nil {
		t.Error("unknown profile accepted")
	}
}

func TestMissingFileIsRecommended(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Profile != "recommended" || c.Limits.Global.Day.Micros != 20*money.Dollar {
		t.Errorf("unexpected defaults: %+v", c.Limits.Global)
	}
}

func TestOverrideOnProfile(t *testing.T) {
	c, err := Parse(`
profile = "strict"
[limits.global]
day = "$50"
[limits.provider.anthropic]
hour = "$4"
[limits.model."*opus*"]
request = "$1"
[presence]
idle_after = "20m"
`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Limits.Global.Day.Micros != 50*money.Dollar {
		t.Error("override not applied")
	}
	if c.Limits.Global.Request.Micros != money.Dollar {
		t.Error("strict profile value lost")
	}
	if c.Presence.ScreenLock != "lock" || c.Presence.IdleAfter.Duration != 20*time.Minute {
		t.Error("presence merge wrong")
	}
	if c.Limits.Provider["anthropic"].Windows()["hour"] != 4*money.Dollar {
		t.Error("provider limit missing")
	}
	if c.Limits.Model["*opus*"].Request == nil {
		t.Error("model limit missing")
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":      "[proxy]\nprot = 1\n",
		"bad money":        "[limits.global]\nday = \"lots\"\n",
		"bad duration":     "[presence]\nidle_after = \"soon\"\n",
		"short idle":       "[presence]\nidle_after = \"10s\"\n",
		"bad enum":         "[approval]\nmethod = \"vibes\"\n",
		"wildcard origin":  "[proxy]\nallowed_origins = [\"*\"]\n",
		"unknown provider": "[limits.provider.acme]\nday = \"$1\"\n",
		"bad glob":         "[models]\ndeny = [\"[\"]\n",
		"negative conc":    "[limits.global]\nconcurrency = -1\n",
		"away > lease":     "[presence]\naway_max = \"48h\"\n",
		"bad profile":      "profile = \"yolo\"\n",
	}
	for name, text := range cases {
		if _, err := Parse(text); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestEncodeRoundTrip(t *testing.T) {
	c, _ := Default("relaxed")
	s, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := Parse(s)
	if err != nil {
		t.Fatalf("re-parse: %v\n%s", err, s)
	}
	if c2.Limits.Global.Month.Micros != c.Limits.Global.Month.Micros || !strings.Contains(s, "relaxed") {
		t.Error("round trip lost values")
	}
}
