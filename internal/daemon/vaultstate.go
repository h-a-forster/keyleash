package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/pass"
	"github.com/h-a-forster/keyleash/internal/secmem"
	"github.com/h-a-forster/keyleash/internal/vault"
)

// The daemon's security-relevant bookkeeping lives in an authenticated vault
// entry (provider "keyleash", kind admin_key, label "daemon-state"), like the
// integrity root: sealed under the DEK, covered by the header MAC and the
// anti-rollback sidecar. Deleting state.json and the ledger therefore cannot
// silently reset spend (spec §7.7), and an edited config.toml is noticed at
// the next unlock (spec §14). state.json keeps only non-security
// bookkeeping (models seen without a price).
const stateLabel = "daemon-state"

// VaultCheckpointEvery is how often the ledger checkpoint is written to the
// vault while unlocked (it is also written on lock and shutdown).
const VaultCheckpointEvery = 5 * time.Minute

// vaultState is the JSON content of the daemon-state entry. It holds no
// secrets; it is in the vault for authentication, not confidentiality.
type vaultState struct {
	Version int `json:"version"`
	// Counter increases with every save.
	Counter uint64    `json:"counter"`
	Saved   time.Time `json:"saved,omitzero"`
	// Checkpoint is the ledger chain state at the last save.
	Checkpoint *budget.Checkpoint `json:"checkpoint,omitempty"`
	// ConfigHash and ConfigTOML are the last accepted effective config
	// (config.Encode) and its SHA-256.
	ConfigHash string `json:"config_hash,omitempty"`
	ConfigTOML string `json:"config_toml,omitempty"`
	// ActiveKeys maps a provider to its active api_key entry (changed only
	// by the step-up protected `keys use`).
	ActiveKeys map[string]string `json:"active_keys,omitempty"`
	// ApprovalMethod is approval.method of the accepted config. Resuming
	// after a config change or an integrity failure is approved with it
	// (never with a method the changed config names, spec §14).
	ApprovalMethod string `json:"approval_method,omitempty"`
	// PassStore is the baseline of passes.json: the counter of its last
	// authenticated write and a digest per pass (spec §6).
	PassStore *pass.Baseline `json:"pass_store,omitempty"`
	// KeysEverAdded is set once the vault has held an api_key: only before
	// that may a key be added without a step-up (spec §9).
	KeysEverAdded bool `json:"keys_ever_added,omitempty"`
}

func (s *vaultState) clone() *vaultState {
	c := *s
	if s.Checkpoint != nil {
		cp := *s.Checkpoint
		c.Checkpoint = &cp
	}
	if s.PassStore != nil {
		ps := pass.Baseline{Counter: s.PassStore.Counter, Digests: make(map[string]string, len(s.PassStore.Digests))}
		for k, v := range s.PassStore.Digests {
			ps.Digests[k] = v
		}
		c.PassStore = &ps
	}
	c.ActiveKeys = make(map[string]string, len(s.ActiveKeys))
	for k, v := range s.ActiveKeys {
		c.ActiveKeys[k] = v
	}
	return &c
}

func isStateEntry(e vault.EntryInfo) bool {
	return e.Provider == rootProvider && e.Label == stateLabel
}

// isInternalEntry reports entries the admin API hides and refuses to touch.
func isInternalEntry(e vault.EntryInfo) bool { return isRootEntry(e) || isStateEntry(e) }

func stateEntryID(v *vault.Vault) (string, bool) {
	for _, e := range v.Entries() {
		if isStateEntry(e) {
			return e.ID, true // the oldest wins, deterministically
		}
	}
	return "", false
}

// ensureStateEntry creates an empty daemon-state entry (Init).
func ensureStateEntry(v *vault.Vault) error {
	if _, ok := stateEntryID(v); ok {
		return nil
	}
	raw, err := json.Marshal(vaultState{Version: 1})
	if err != nil {
		return err
	}
	_, err = v.AddEntry(rootProvider, vault.KindAdminKey, stateLabel, raw)
	return err
}

// loadVaultState reads and caches the daemon-state entry. exists is false
// for a vault created before the entry existed (it is then migrated).
func (d *Daemon) loadVaultState() (st *vaultState, exists bool, err error) {
	id, ok := stateEntryID(d.vault)
	if !ok {
		return &vaultState{Version: 1}, false, nil
	}
	st = &vaultState{}
	err = d.vault.WithSecret(id, func(raw []byte) error {
		if jerr := json.Unmarshal(raw, st); jerr != nil || st.Version != 1 {
			return errors.New("daemon-state entry is malformed")
		}
		return nil
	})
	if err != nil {
		return nil, true, err
	}
	if st.ActiveKeys == nil {
		st.ActiveKeys = map[string]string{}
	}
	d.vsMu.Lock()
	d.vs = st.clone()
	d.vsMu.Unlock()
	return st, true, nil
}

// updateVaultState applies fn to the cached state and writes it to the
// vault (creating the entry if needed). The vault must be unlocked.
func (d *Daemon) updateVaultState(fn func(*vaultState)) error {
	d.vsMu.Lock()
	defer d.vsMu.Unlock()
	if d.vs == nil {
		return errors.New("daemon state not loaded")
	}
	next := d.vs.clone()
	fn(next)
	next.Version = 1
	next.Counter++
	next.Saved = d.clk.Now().UTC()
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	defer secmem.Wipe(raw)
	if id, ok := stateEntryID(d.vault); ok {
		err = d.vault.ReplaceEntrySecret(id, raw)
	} else {
		_, err = d.vault.AddEntry(rootProvider, vault.KindAdminKey, stateLabel, raw)
	}
	if err != nil {
		return fmt.Errorf("write daemon state to the vault: %w", err)
	}
	d.vs = next
	return nil
}

// vaultStateSnapshot returns a copy of the cached state (nil before the
// first unlock).
func (d *Daemon) vaultStateSnapshot() *vaultState {
	d.vsMu.Lock()
	defer d.vsMu.Unlock()
	if d.vs == nil {
		return nil
	}
	return d.vs.clone()
}

// onPassCommit records the pass store's new baseline in the vault after an
// authenticated write of passes.json (called with the store's lock held).
func (d *Daemon) onPassCommit(b pass.Baseline) {
	if err := d.updateVaultState(func(s *vaultState) { s.PassStore = &b }); err != nil {
		// The file is one write ahead of the vault; the next unlock accepts
		// exactly that (pass.Diff), anything else trips.
		d.log.Error("recording the pass store baseline in the vault failed", "err", err)
	}
}

// activeKey returns the provider's active entry from the cached state.
func (d *Daemon) activeKey(prov string) string {
	d.vsMu.Lock()
	defer d.vsMu.Unlock()
	if d.vs == nil {
		return ""
	}
	return d.vs.ActiveKeys[prov]
}
