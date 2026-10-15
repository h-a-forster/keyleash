package vault

import (
	"encoding/json"
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

// SeqPath returns the anti-rollback sidecar kept next to a vault file: the
// vault path with its extension replaced by ".seq" (spec §5.4).
func SeqPath(path string) string {
	return strings.TrimSuffix(path, filepath.Ext(path)) + ".seq"
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

// writeMode selects what writeAtomic does with the .prev copy.
type writeMode int

const (
	// writeKeepPrev moves the current main file to .prev (normal writes).
	writeKeepPrev writeMode = iota
	// writeNoPrev replaces the main file and leaves .prev alone (used when
	// the main file is corrupt and the state was loaded from .prev).
	writeNoPrev
	// writeRekey replaces the main file and then replaces .prev with a copy
	// of the new state, so no file left by this write holds the old DEK.
	writeRekey
)

// errPrevNotScrubbed is returned by writeAtomic in writeRekey mode when the
// main file was replaced but .prev could not be replaced or removed. The new
// state is committed.
var errPrevNotScrubbed = errors.New("vault: previous-version file not replaced")

// writeTemp writes data to a new owner-only temp file in dir and fsyncs it.
func writeTemp(dir string, data []byte) (name string, err error) {
	tmp, err := os.CreateTemp(dir, ".keyleash-vault-*.tmp")
	if err != nil {
		return "", fmt.Errorf("vault: create temp file: %w", err)
	}
	name = tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if err = restrictPath(name, false); err != nil {
		return "", fmt.Errorf("vault: restrict temp file: %w", err)
	}
	if _, err = tmp.Write(data); err != nil {
		return "", fmt.Errorf("vault: write: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return "", fmt.Errorf("vault: fsync: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return "", fmt.Errorf("vault: close: %w", err)
	}
	return name, nil
}

// scrubStalePrev replaces path's .prev with a copy of the live state f when
// .prev parses, has a lower seq than f and does not authenticate under the
// live dek: a copy left
// under an older DEK by a re-key that crashed between its two renames (or
// whose scrub failed), which the slots that re-key removed (an old recovery
// code, a removed slot) would still open. found reports such a .prev; err
// is errPrevNotScrubbed if it could be neither replaced nor removed. A
// missing or unparsable .prev opens with nothing and is left alone.
func scrubStalePrev(path string, f *fileV1, dek []byte) (found bool, err error) {
	pf, rerr := readFile(PrevPath(path))
	if rerr != nil {
		return false, nil
	}
	if ok, verr := verifyHeaderMAC(dek, pf); verr == nil && ok {
		return false, nil
	}
	if pf.Seq >= f.Seq {
		// Not an older copy: never overwrite it here. A newer .prev of this
		// vault fails the unlock as a rollback before this is reached.
		return false, nil
	}
	data, merr := json.MarshalIndent(f, "", "  ")
	if merr == nil {
		var tmp string
		if tmp, merr = writeTemp(filepath.Dir(path), append(data, '\n')); merr == nil {
			if merr = os.Rename(tmp, PrevPath(path)); merr != nil {
				_ = os.Remove(tmp)
			}
		}
	}
	if merr != nil {
		if rerr := os.Remove(PrevPath(path)); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return true, errPrevNotScrubbed
		}
	}
	_ = syncDir(filepath.Dir(path))
	return true, nil
}

// writeAtomic replaces path with data: write a temp file in the same
// directory with owner-only permissions, fsync, handle .prev according to
// mode, rename the temp file into place, then fsync the directory where
// supported. A crash at any point leaves either the old file, or no main
// file and a valid .prev, or the new file.
//
// In writeRekey mode a second temp copy is written before the main rename
// and renamed over .prev right after it, so the window in which .prev still
// holds the pre-re-key state is a single rename. If that last step fails,
// .prev is removed; if removal also fails, errPrevNotScrubbed is returned
// even though the main file now holds the new state. Removed files may
// persist on disk sectors; that is outside what the vault can control.
func writeAtomic(path string, data []byte, mode writeMode) error {
	dir := filepath.Dir(path)
	tmpName, err := writeTemp(dir, data)
	if err != nil {
		return err
	}
	var prevTmp string
	switch mode {
	case writeKeepPrev:
		if _, serr := os.Lstat(path); serr == nil {
			if err := os.Rename(path, PrevPath(path)); err != nil {
				_ = os.Remove(tmpName)
				return fmt.Errorf("vault: keep previous version: %w", err)
			}
		} else if !errors.Is(serr, fs.ErrNotExist) {
			_ = os.Remove(tmpName)
			return fmt.Errorf("vault: stat: %w", serr)
		}
	case writeRekey:
		if prevTmp, err = writeTemp(dir, data); err != nil {
			_ = os.Remove(tmpName)
			return err
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		if prevTmp != "" {
			_ = os.Remove(prevTmp)
		}
		return fmt.Errorf("vault: replace: %w", err)
	}
	var scrubErr error
	if prevTmp != "" {
		if err := os.Rename(prevTmp, PrevPath(path)); err != nil {
			_ = os.Remove(prevTmp)
			if rerr := os.Remove(PrevPath(path)); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
				scrubErr = errPrevNotScrubbed
			}
		}
	}
	// The rename has happened; making the directory entry durable is best
	// effort and its failure does not undo the write.
	_ = syncDir(dir)
	return scrubErr
}
