package vault

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// Anti-rollback sidecar (spec §5.4).
//
// After every committed write the vault records (vault_id, seq) in SeqPath.
// On Windows the record is a DPAPI blob (user scope, entropy = vault_id); on
// other systems it is a 0600 file holding the record followed by
// HMAC-SHA256 under HKDF(DEK, "keyleash/v1/seq-sidecar").
//
// At unlock, after the DEK has been recovered and the header MAC verified
// (so the check is not an oracle for anyone without a slot secret), a
// sidecar that records a higher seq than the file being unlocked, names a
// different vault, or cannot be read, makes the unlock fail with
// ErrRollback. Any higher seq fails closed whether or not its MAC verifies:
// a legitimate re-key changes the DEK, so an older vault copy cannot verify
// the MAC of a newer sidecar. The MAC therefore only lets the vault tell a
// current, authentic record from one it should rewrite.
//
// Limits: the sidecar lives next to the vault, so an attacker who can
// replace the vault file can also delete the sidecar or restore an older
// copy of it together with the vault. Detection is best effort, as the spec
// says ("optional ... triggers a warning").

const (
	infoSidecar    = "keyleash/v1/seq-sidecar"
	sidecarPrefix  = "keyleash/v1/seq\x00"
	sidecarRecord  = len(sidecarPrefix) + 32 + 8
	maxSidecarSize = 8192
)

// sidecarUseDPAPI selects the sidecar encoding. Tests switch it to exercise
// the portable encoding on Windows.
var sidecarUseDPAPI = dpapiSupported

func sidecarPayload(vaultID string, seq uint64) []byte {
	b := make([]byte, 0, sidecarRecord)
	b = append(b, sidecarPrefix...)
	b = append(b, vaultID...)
	return binary.BigEndian.AppendUint64(b, seq)
}

func sidecarMAC(dek, payload []byte) ([]byte, error) {
	key, err := deriveSubkey(dek, infoSidecar)
	if err != nil {
		return nil, err
	}
	defer key.Destroy()
	m := hmac.New(sha256.New, key.Bytes())
	m.Write(payload)
	return m.Sum(nil), nil
}

func encodeSidecar(vaultID string, seq uint64, dek []byte) ([]byte, error) {
	p := sidecarPayload(vaultID, seq)
	if sidecarUseDPAPI {
		return dpapiProtect(p, []byte(vaultID))
	}
	mac, err := sidecarMAC(dek, p)
	if err != nil {
		return nil, err
	}
	return append(p, mac...), nil
}

// writeSidecar atomically records seq for the vault at path.
func writeSidecar(path, vaultID string, seq uint64, dek []byte) error {
	data, err := encodeSidecar(vaultID, seq, dek)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(filepath.Dir(path), data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, SeqPath(path)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("vault: write sidecar: %w", err)
	}
	_ = syncDir(filepath.Dir(path))
	return nil
}

// sidecarState is the result of reading the sidecar at unlock.
type sidecarState struct {
	present bool
	// rollback: the sidecar records a newer state than the file, belongs to
	// another vault, or is unreadable.
	rollback bool
	// seq is the recorded seq when it could be read (0 otherwise).
	seq uint64
	// current: the record is authentic and equals the unlocked seq, so it
	// does not need rewriting.
	current bool
}

// checkSidecar compares the sidecar with f. dek must be f's verified DEK.
func checkSidecar(path string, f *fileV1, dek []byte) (sidecarState, error) {
	fh, err := os.Open(SeqPath(path))
	if errors.Is(err, fs.ErrNotExist) {
		return sidecarState{}, nil
	}
	if err != nil {
		return sidecarState{}, fmt.Errorf("vault: read sidecar: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(fh, maxSidecarSize+1))
	fh.Close()
	if err != nil {
		return sidecarState{}, fmt.Errorf("vault: read sidecar: %w", err)
	}
	st := sidecarState{present: true, rollback: true}
	var payload, mac []byte
	if sidecarUseDPAPI {
		buf, err := dpapiUnprotect(data, []byte(f.VaultID))
		if err != nil {
			return st, nil
		}
		payload = bytes.Clone(buf.Bytes())
		buf.Destroy()
	} else {
		if len(data) != sidecarRecord+macSize {
			return st, nil
		}
		payload, mac = data[:sidecarRecord], data[sidecarRecord:]
	}
	if len(payload) != sidecarRecord || !bytes.HasPrefix(payload, []byte(sidecarPrefix)) ||
		string(payload[len(sidecarPrefix):len(sidecarPrefix)+32]) != f.VaultID {
		return st, nil
	}
	st.seq = binary.BigEndian.Uint64(payload[sidecarRecord-8:])
	st.rollback = st.seq > f.Seq
	authentic := true
	if mac != nil {
		want, err := sidecarMAC(dek, payload)
		if err != nil {
			return sidecarState{}, err
		}
		authentic = hmac.Equal(want, mac)
	}
	st.current = authentic && st.seq == f.Seq
	return st, nil
}
