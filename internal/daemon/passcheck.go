package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/BurntSushi/toml"

	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/vault"
)

// unverifiedPassDiff is the outcome when passes.json cannot be checked at
// all (the daemon state is unreadable or verification failed): every pass
// counts as changed, so resuming revokes them all.
func (d *Daemon) unverifiedPassDiff() *pass.Diff {
	diff := &pass.Diff{}
	for _, p := range d.passes.List() {
		diff.Changed = append(diff.Changed, p.ID)
	}
	sort.Strings(diff.Changed)
	return diff
}

// rebaselinePasses accepts passes.json after a pass_store trip: the added
// and changed passes are revoked (never trusted), and an authenticated
// write records the new baseline in the vault.
func (d *Daemon) rebaselinePasses(diff *pass.Diff) ([]string, error) {
	d.mu.RLock()
	keys := d.st.keys
	d.mu.RUnlock()
	if keys == nil {
		return nil, fmt.Errorf("locked")
	}
	d.passes.SetMACKey(keys.passes.Bytes())
	ids := append(append([]string(nil), diff.Added...), diff.Changed...)
	if len(ids) > 0 {
		if _, err := d.passes.RevokeIDs(ids); err != nil {
			d.passes.SetMACKey(nil)
			return nil, err
		}
	}
	if err := d.passes.Commit(); err != nil {
		d.passes.SetMACKey(nil)
		return nil, err
	}
	for _, id := range ids {
		d.auditEvent("pass_revoke", map[string]any{"pass": id, "reason": "pass_store"})
	}
	return ids, nil
}

// passStoreChanges renders a pass-store mismatch for status and audit.
func passStoreChanges(diff *pass.Diff) []string {
	if diff == nil {
		return nil
	}
	var out []string
	if diff.Counter != diff.Baseline || !diff.MACOK {
		out = append(out, fmt.Sprintf("passes.json write %d, vault records write %d, authenticated: %v", diff.Counter, diff.Baseline, diff.MACOK))
	}
	for _, id := range diff.Added {
		out = append(out, "added "+id+" (revoked on resume)")
	}
	for _, id := range diff.Changed {
		out = append(out, "changed "+id+" (revoked on resume)")
	}
	for _, id := range diff.Removed {
		out = append(out, "removed "+id)
	}
	return out
}

// vaultHasAPIKey reports whether the vault holds a provider key.
func (d *Daemon) vaultHasAPIKey() bool {
	for _, e := range d.vault.Entries() {
		if e.Kind == vault.KindAPIKey && !isInternalEntry(e) {
			return true
		}
	}
	return false
}

// acceptedConfigText is the effective config as recorded when accepted:
// config.Encode plus, with a pricing override, the override file's path and
// the SHA-256 of the bytes the daemon priced with (spec §14). Without an
// override it is exactly config.Encode, so its hash equals Config.Hash.
func (d *Daemon) acceptedConfigText() (string, error) {
	text, err := d.cfg.Encode()
	if err != nil || d.overridePath == "" {
		return text, err
	}
	var b strings.Builder
	b.WriteString(text)
	b.WriteString("\n")
	err = toml.NewEncoder(&b).Encode(struct {
		F struct {
			Path   string `toml:"path"`
			SHA256 string `toml:"sha256"`
		} `toml:"pricing_override_file"`
	}{F: struct {
		Path   string `toml:"path"`
		SHA256 string `toml:"sha256"`
	}{Path: d.overridePath, SHA256: d.overrideSHA}})
	return b.String(), err
}

func hashText(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// riskPrefixes orders config keys in approval prompts: the keys that
// weaken approvals, limits or pricing first (spec §9, §14).
var riskPrefixes = []string{"approval.", "limits.", "models.", "pricing", "presence."}

func riskRank(key string) int {
	for i, p := range riskPrefixes {
		if strings.HasPrefix(key, p) {
			return i
		}
	}
	return len(riskPrefixes)
}

// changedKeys returns the keys of config.Diff lines ("key: a -> b"),
// highest-risk first.
func changedKeys(changes []string) []string {
	keys := make([]string, 0, len(changes))
	for _, c := range changes {
		k, _, _ := strings.Cut(c, ": ")
		keys = append(keys, k)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		ri, rj := riskRank(keys[i]), riskRank(keys[j])
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
	return keys
}

// resumeDetailRunes keeps the resume risk text well inside the prompt.
const resumeDetailRunes = 110

// resumeSummary builds the risk text (detail) and the optional note of a
// resume prompt: the trip reason, the number of changed config keys with
// the highest-risk keys named first, and the pass-store changes.
func resumeSummary(reason string, changes []string, diff *pass.Diff) (detail, note string) {
	parts := []string{"Tripped: " + reason}
	if diff != nil {
		parts = append(parts, fmt.Sprintf("passes: %d added, %d changed (revoked), %d removed",
			len(diff.Added), len(diff.Changed), len(diff.Removed)))
	}
	var keys []string
	if len(changes) > 0 {
		keys = changedKeys(changes)
		head := fmt.Sprintf("%d config keys changed", len(keys))
		if len(keys) == 1 {
			head = "1 config key changed"
		}
		base := strings.Join(append(parts, head), "; ")
		// Name as many keys as fit, highest risk first.
		named := 0
		cur := base
		for named < len(keys) {
			more := ""
			if rest := len(keys) - named - 1; rest > 0 {
				more = fmt.Sprintf(", +%d more", rest)
			}
			sep := ": "
			if named > 0 {
				sep = ", "
			}
			next := cur + sep + keys[named]
			if utf8.RuneCountInString(next+more) > resumeDetailRunes {
				break
			}
			cur = next
			named++
		}
		if rest := len(keys) - named; rest > 0 && named > 0 {
			cur += fmt.Sprintf(", +%d more", rest)
		}
		detail = cur
		if named < len(keys) {
			note = "also: " + strings.Join(keys[named:], ", ")
		}
		return detail, note
	}
	return strings.Join(parts, "; "), ""
}
