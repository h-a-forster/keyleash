package daemon

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/h-a-forster/keyleash/internal/budget"
	"github.com/h-a-forster/keyleash/internal/secmem"
	"github.com/h-a-forster/keyleash/internal/vault"
)

// The daemon's long-lived MAC keys (audit anchors, ledger record MACs,
// state.json MAC) are derived with HKDF-SHA256 from a random 256-bit
// "integrity root" stored as a vault entry, not directly from the DEK:
//
//   - audit.Verify and budget.VerifyIntegrity check every record with ONE key,
//     and a vault re-key (RemoveSlot, RotateRecovery) changes every DeriveKey
//     output. Keys taken straight from the DEK would make all history fail
//     verification after any re-key. A vault entry is re-sealed by a re-key,
//     so the root (and the keys derived from it) survive it unchanged.
//   - The root is as protected as a provider key: sealed under the DEK,
//     covered by the header MAC and the anti-rollback sidecar, and readable
//     only while unlocked. Deleting state.json does not lose it.
//
// The entry is provider "keyleash" (not a registered provider, so it is never
// used to authenticate upstream), kind admin_key, label "integrity-root". It
// is hidden from the admin API's key listing and cannot be removed there.
const (
	rootProvider = "keyleash"
	rootLabel    = "integrity-root"

	infoAuditAnchor = vault.InfoAuditAnchor
	infoLedgerMAC   = "keyleash/v1/ledger-mac"
	infoStateMAC    = "keyleash/v1/state-mac"
)

// integrityKeys are the derived keys, held in secmem while unlocked.
type integrityKeys struct {
	anchor, ledger, state *secmem.Buffer
}

func isRootEntry(e vault.EntryInfo) bool {
	return e.Provider == rootProvider && e.Label == rootLabel
}

// ensureRootEntry creates the integrity root entry if the vault has none.
// It reports whether one was created.
func ensureRootEntry(v *vault.Vault) (bool, error) {
	for _, e := range v.Entries() {
		if isRootEntry(e) {
			return false, nil
		}
	}
	root := make([]byte, 32)
	defer secmem.Wipe(root)
	if _, err := io.ReadFull(rand.Reader, root); err != nil {
		return false, err
	}
	if _, err := v.AddEntry(rootProvider, vault.KindAdminKey, rootLabel, root); err != nil {
		return false, err
	}
	return true, nil
}

// loadIntegrityKeys reads (creating if missing) the integrity root and
// derives the three MAC keys into locked buffers.
func (d *Daemon) loadIntegrityKeys() (*integrityKeys, bool, error) {
	created, err := ensureRootEntry(d.vault)
	if err != nil {
		return nil, false, err
	}
	var id string
	for _, e := range d.vault.Entries() {
		if isRootEntry(e) {
			id = e.ID // the oldest one wins, deterministically
			break
		}
	}
	keys := &integrityKeys{}
	err = d.vault.WithSecret(id, func(root []byte) error {
		var derr error
		if keys.anchor, derr = deriveBuf(root, infoAuditAnchor); derr != nil {
			return derr
		}
		if keys.ledger, derr = deriveBuf(root, infoLedgerMAC); derr != nil {
			return derr
		}
		keys.state, derr = deriveBuf(root, infoStateMAC)
		return derr
	})
	if err != nil {
		keys.destroy()
		return nil, false, err
	}
	return keys, created, nil
}

func deriveBuf(root []byte, info string) (*secmem.Buffer, error) {
	if len(root) < 32 {
		return nil, errors.New("integrity root too short")
	}
	buf, err := secmem.New(32)
	if err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(hkdf.New(sha256.New, root, nil, []byte(info)), buf.Bytes()); err != nil {
		buf.Destroy()
		return nil, err
	}
	return buf, nil
}

// ---- state.json ------------------------------------------------------------

// stateBody is the authenticated content of state.json. It holds no secrets.
type stateBody struct {
	Version    int                `json:"version"`
	VaultID    string             `json:"vault_id"`
	Saved      time.Time          `json:"saved"`
	Checkpoint *budget.Checkpoint `json:"checkpoint,omitempty"`
	// ModelsSeen lists provider/model pairs seen without a price (for
	// `keyleash pricing check`).
	ModelsSeen []string `json:"models_seen,omitempty"`
}

type stateEnvelope struct {
	Body json.RawMessage `json:"body"`
	MAC  string          `json:"mac"`
}

const stateMACContext = "keyleash/v1/state\x00"

// errStateAuth is returned when state.json exists but does not authenticate.
var errStateAuth = errors.New("state file failed authentication")

func stateMAC(key, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(stateMACContext))
	m.Write(body)
	return hex.EncodeToString(m.Sum(nil))
}

// loadStateFile reads and authenticates state.json. A missing file returns
// exists=false and no error.
func loadStateFile(path string, key []byte, vaultID string) (stateBody, bool, error) {
	var st stateBody
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return st, false, nil
	}
	if err != nil {
		return st, true, fmt.Errorf("read: %w", err)
	}
	if len(raw) > 4<<20 {
		return st, true, errStateAuth
	}
	var env stateEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Body) == 0 {
		return st, true, errStateAuth
	}
	if !hmac.Equal([]byte(stateMAC(key, env.Body)), []byte(env.MAC)) {
		return st, true, errStateAuth
	}
	if err := json.Unmarshal(env.Body, &st); err != nil || st.Version != 1 || st.VaultID != vaultID {
		return stateBody{}, true, errStateAuth
	}
	return st, true, nil
}

// saveStateFile writes state.json atomically (temp file, fsync, rename).
func saveStateFile(path string, key []byte, st stateBody) error {
	body, err := json.Marshal(st)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(stateEnvelope{Body: body, MAC: stateMAC(key, body)})
	if err != nil {
		return err
	}
	return writeFileAtomic(path, raw)
}

func writeFileAtomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync() // best effort; not supported everywhere
		dir.Close()
	}
	return nil
}

// ledgerHasRecords reports whether any ledger file is non-empty.
func ledgerHasRecords(dir string) (bool, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), "ledger-") || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			return false, err
		}
		if info.Size() > 0 {
			return true, nil
		}
	}
	return false, nil
}
