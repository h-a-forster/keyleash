package vault

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// PrevPath returns the crash-recovery copy kept next to a vault file: the
// vault path with its extension replaced by ".prev" (".../vault.json" →
// ".../vault.prev", spec §5.4).
func PrevPath(path string) string {
	return strings.TrimSuffix(path, filepath.Ext(path)) + ".prev"
}

// SecureDir creates dir if needed and restricts it to the current user (and
// SYSTEM on Windows): DACL on Windows, mode 0700 on Unix. The daemon should
// call it on its data directory.
func SecureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("vault: create directory: %w", err)
	}
	if err := restrictPath(dir, true); err != nil {
		return fmt.Errorf("vault: restrict directory: %w", err)
	}
	return nil
}

// readFile reads and structurally validates the vault file at path.
func readFile(path string) (*fileV1, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	data, err := io.ReadAll(io.LimitReader(fh, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("vault: read: %w", err)
	}
	if len(data) > maxFileSize {
		return nil, corrupt("file too large")
	}
	return decodeFile(data)
}

// loadWithFallback reads path, falling back to its .prev copy when the main
// file is missing or structurally corrupt (a crash mid-write). A file that
// parses but fails authentication is not a crash artefact and is never
// replaced by the older copy here; that surfaces as ErrTampered on unlock.
func loadWithFallback(path string) (f *fileV1, fromPrev bool, err error) {
	f, err = readFile(path)
	if err == nil {
		return f, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, ErrCorrupt) {
		return nil, false, err
	}
	pf, perr := readFile(PrevPath(path))
	if perr != nil {
		return nil, false, err
	}
	return pf, true, nil
}

// writeAtomic replaces path with data: write a temp file in the same
// directory with owner-only permissions, fsync, move the current file to
// .prev (when keepPrev), rename the temp file into place, then fsync the
// directory where supported. A crash at any point leaves either the old
// file, or no main file and a valid .prev, or the new file.
func writeAtomic(path string, data []byte, keepPrev bool) (err error) {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".keyleash-vault-*.tmp")
	if err != nil {
		return fmt.Errorf("vault: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
		}
	}()
	if err = restrictPath(tmpName, false); err != nil {
		return fmt.Errorf("vault: restrict temp file: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("vault: write: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("vault: fsync: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("vault: close: %w", err)
	}
	if keepPrev {
		if _, serr := os.Lstat(path); serr == nil {
			if err = os.Rename(path, PrevPath(path)); err != nil {
				return fmt.Errorf("vault: keep previous version: %w", err)
			}
		} else if !errors.Is(serr, fs.ErrNotExist) {
			err = fmt.Errorf("vault: stat: %w", serr)
			return err
		}
	}
	if err = os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("vault: replace: %w", err)
	}
	// The rename has happened; making the directory entry durable is best
	// effort and its failure does not undo the write.
	_ = syncDir(dir)
	return nil
}
