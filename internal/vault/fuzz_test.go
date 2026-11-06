package vault

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzDecodeFile: vault.json is writable by anything running as the owner,
// so a malformed file must be refused without panicking, and an accepted one
// must be safe to hash for the header MAC and survive a re-encode.
func FuzzDecodeFile(f *testing.F) {
	path := filepath.Join(f.TempDir(), "vault.json")
	v, _, err := Create(path, SlotSpec{Type: SlotPassphrase, Label: "main", Passphrase: testPass})
	if err != nil {
		f.Fatal(err)
	}
	v.Lock()
	seed, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := decodeFile(data)
		if err != nil {
			return
		}
		_ = headerMACInput(file)
		out, err := json.Marshal(file)
		if err != nil {
			t.Fatalf("accepted file does not encode: %v", err)
		}
		if _, err := decodeFile(out); err != nil {
			t.Fatalf("accepted file does not re-decode: %v", err)
		}
	})
}
