package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

// Hash returns the hex SHA-256 of the effective configuration's canonical
// TOML encoding. The daemon stores it in the vault so an edited config.toml
// is noticed at the next unlock (spec §14).
func (c *Config) Hash() (string, error) {
	enc, err := c.Encode()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(enc))
	return hex.EncodeToString(sum[:]), nil
}

// Diff compares two effective configurations rendered by Encode and returns
// one human-readable line per changed key, sorted:
// "limits.global.day: $20 -> $200". Keys present on one side only show
// "(unset)" for the other.
func Diff(oldTOML, newTOML string) ([]string, error) {
	a, err := flatten(oldTOML)
	if err != nil {
		return nil, fmt.Errorf("config: old: %w", err)
	}
	b, err := flatten(newTOML)
	if err != nil {
		return nil, fmt.Errorf("config: new: %w", err)
	}
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	var out []string
	for k := range keys {
		va, oka := a[k]
		vb, okb := b[k]
		if oka && okb && va == vb {
			continue
		}
		if !oka {
			va = "(unset)"
		}
		if !okb {
			vb = "(unset)"
		}
		out = append(out, k+": "+va+" -> "+vb)
	}
	sort.Strings(out)
	return out, nil
}

func flatten(text string) (map[string]string, error) {
	var m map[string]any
	if _, err := toml.Decode(text, &m); err != nil {
		return nil, err
	}
	out := map[string]string{}
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			if len(x) == 0 {
				out[prefix] = "{}"
			}
			for k, e := range x {
				p := k
				if prefix != "" {
					p = prefix + "." + k
				}
				walk(p, e)
			}
		case []any:
			parts := make([]string, len(x))
			for i, e := range x {
				parts[i] = fmt.Sprint(e)
			}
			out[prefix] = "[" + strings.Join(parts, ", ") + "]"
		default:
			out[prefix] = fmt.Sprint(x)
		}
	}
	walk("", m)
	return out, nil
}
