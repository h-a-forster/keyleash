package pass

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// TouchInterval is the minimum time between disk writes caused by Touch for
// one pass. LastUsed is always updated in memory.
const TouchInterval = time.Minute

const (
	fileFormat  = "keyleash-passes"
	fileVersion = 1
	maxFileSize = 64 << 20
)

// record is the on-disk form of a pass: its metadata plus the hex SHA-256 of
// its secret.
type record struct {
	Pass
	Hash string `json:"secret_sha256"`
}

type fileDoc struct {
	Format  string   `json:"format"`
	Version int      `json:"version"`
	Passes  []record `json:"passes"`
}

type entry struct {
	p        Pass
	hash     [sha256.Size]byte
	lastSave time.Time // LastUsed value last written to disk
}

// Store holds passes in memory and persists them to a JSON file with atomic
// writes. It is safe for concurrent use.
type Store struct {
	path  string
	clk   Clock
	mu    sync.Mutex
	byID  map[string]*entry
	dummy [sha256.Size]byte // compared against for unknown ids
}

// OpenStore loads the pass file at path (a missing file is an empty store).
// A malformed file is an error: the daemon must not silently forget
// revocations. clk may be nil for the real clock.
func OpenStore(path string, clk Clock) (*Store, error) {
	if clk == nil {
		clk = realClock{}
	}
	s := &Store{path: path, clk: clk, byID: map[string]*entry{}}
	// A random dummy hash keeps the unknown-id path doing the same compare
	// work without any chance of matching.
	ds, err := newSecret()
	if err != nil {
		return nil, err
	}
	s.dummy = sha256.Sum256(ds)
	wipe(ds)

	data, err := readLimited(path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("pass: read store: %w", err)
	}
	var doc fileDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("pass: parse store: %w", err)
	}
	if doc.Format != fileFormat || doc.Version != fileVersion {
		return nil, fmt.Errorf("pass: unsupported store format %q v%d", doc.Format, doc.Version)
	}
	for i, r := range doc.Passes {
		if !validID(r.ID) {
			return nil, fmt.Errorf("pass: store record %d: bad id", i)
		}
		if _, dup := s.byID[r.ID]; dup {
			return nil, fmt.Errorf("pass: store record %d: duplicate id %s", i, r.ID)
		}
		if r.Kind != KindNamed && r.Kind != KindRun {
			return nil, fmt.Errorf("pass: store record %d: bad kind", i)
		}
		h, err := hex.DecodeString(r.Hash)
		if err != nil || len(h) != sha256.Size {
			return nil, fmt.Errorf("pass: store record %d: bad secret hash", i)
		}
		e := &entry{p: r.Pass.clone(), lastSave: r.LastUsed}
		copy(e.hash[:], h)
		s.byID[r.ID] = e
	}
	return s, nil
}

func readLimited(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > maxFileSize {
		return nil, errors.New("store file too large")
	}
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(f); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Issue creates a pass from p, which supplies the scope. ID, Created,
// Revoked, RevokedAt and LastUsed are set by the store. Expires is required
// for every kind. The returned token is the only copy of the secret.
func (s *Store) Issue(p Pass) (token string, issued Pass, err error) {
	p = p.clone()
	now := s.clk.Now()
	if err := validate(&p, now); err != nil {
		return "", Pass{}, err
	}
	secret, err := newSecret()
	if err != nil {
		return "", Pass{}, err
	}
	defer wipe(secret)

	s.mu.Lock()
	defer s.mu.Unlock()
	var id string
	for i := 0; ; i++ {
		if id, err = newID(); err != nil {
			return "", Pass{}, err
		}
		if _, taken := s.byID[id]; !taken {
			break
		}
		if i > 16 {
			return "", Pass{}, errors.New("pass: could not allocate an id")
		}
	}
	p.ID = id
	p.Created = now
	p.Revoked = false
	p.RevokedAt = time.Time{}
	p.LastUsed = time.Time{}
	e := &entry{p: p, hash: sha256.Sum256(secret)}
	s.byID[id] = e
	if err := s.saveLocked(); err != nil {
		delete(s.byID, id)
		return "", Pass{}, err
	}
	return formatToken(id, secret), p.clone(), nil
}

// Verify checks token and returns its pass. Unknown ids do the same hashing
// and constant-time comparison as known ones, and both a wrong secret and an
// unknown id yield ErrInvalid. Revocation and expiry are only reported once
// the secret is proven, so they reveal nothing to a guesser.
func (s *Store) Verify(token string) (Pass, error) {
	id, secret, ok := parse(token)
	if !ok {
		return Pass{}, ErrInvalid
	}
	got := sha256.Sum256(secret)
	wipe(secret)

	s.mu.Lock()
	e, found := s.byID[id]
	want := s.dummy
	var p Pass
	if found {
		want = e.hash
		p = e.p.clone()
	}
	s.mu.Unlock()

	match := subtle.ConstantTimeCompare(got[:], want[:]) == 1
	if !found || !match {
		return Pass{}, ErrInvalid
	}
	if p.Revoked {
		return Pass{}, ErrRevoked
	}
	if p.Expired(s.clk.Now()) {
		return Pass{}, ErrExpired
	}
	return p, nil
}

// Revoke revokes pass id. Revoking an already revoked pass is a no-op. The
// in-memory revocation takes effect even if persisting it fails (fail
// closed); the error reports the persistence failure.
func (s *Store) Revoke(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if e.p.Revoked {
		return nil
	}
	e.p.Revoked = true
	e.p.RevokedAt = s.clk.Now()
	return s.saveLocked()
}

// RevokeAll revokes every pass and returns how many were newly revoked.
// Revocation is effective in memory even if the returned save error is
// non-nil.
func (s *Store) RevokeAll() (int, error) {
	return s.revokeWhere(func(Pass) bool { return true })
}

// RevokeKind revokes every pass of kind and returns how many were newly
// revoked (same persistence semantics as RevokeAll).
func (s *Store) RevokeKind(kind string) (int, error) {
	return s.revokeWhere(func(p Pass) bool { return p.Kind == kind })
}

func (s *Store) revokeWhere(match func(Pass) bool) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clk.Now()
	n := 0
	for _, e := range s.byID {
		if !e.p.Revoked && match(e.p) {
			e.p.Revoked = true
			e.p.RevokedAt = now
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.saveLocked()
}

// List returns all passes (including revoked and expired), oldest first.
func (s *Store) List() []Pass {
	s.mu.Lock()
	out := make([]Pass, 0, len(s.byID))
	for _, e := range s.byID {
		out = append(out, e.p.clone())
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Get returns pass id.
func (s *Store) Get(id string) (Pass, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return Pass{}, false
	}
	return e.p.clone(), true
}

// Touch records that pass id was used at at. LastUsed is updated in memory
// immediately; the file is rewritten at most once per TouchInterval per pass.
// Unknown ids and times not after the current LastUsed are ignored.
func (s *Store) Touch(id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok || !at.After(e.p.LastUsed) {
		return nil
	}
	e.p.LastUsed = at
	if !e.lastSave.IsZero() && at.Sub(e.lastSave) < TouchInterval {
		return nil
	}
	return s.saveLocked()
}

// PruneExpired deletes passes that expired, or were revoked, more than
// olderThan ago, and returns how many were removed.
func (s *Store) PruneExpired(olderThan time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.clk.Now().Add(-olderThan)
	var removed []*entry
	for id, e := range s.byID {
		dead := e.p.Expires.Before(cutoff) || (e.p.Revoked && e.p.RevokedAt.Before(cutoff))
		if dead {
			removed = append(removed, e)
			delete(s.byID, id)
		}
	}
	if len(removed) == 0 {
		return 0, nil
	}
	if err := s.saveLocked(); err != nil {
		for _, e := range removed {
			s.byID[e.p.ID] = e
		}
		return 0, err
	}
	return len(removed), nil
}

// saveLocked writes the whole store atomically. Caller holds s.mu.
func (s *Store) saveLocked() error {
	doc := fileDoc{Format: fileFormat, Version: fileVersion, Passes: make([]record, 0, len(s.byID))}
	ids := make([]string, 0, len(s.byID))
	for id := range s.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		e := s.byID[id]
		doc.Passes = append(doc.Passes, record{Pass: e.p, Hash: hex.EncodeToString(e.hash[:])})
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("pass: encode store: %w", err)
	}
	if err := writeAtomic(s.path, data); err != nil {
		return err
	}
	for _, e := range s.byID {
		e.lastSave = e.p.LastUsed
	}
	return nil
}

// writeAtomic replaces path with data via a temp file in the same directory,
// fsync and rename. The directory is created owner-only if missing; on
// Windows the daemon sets the data directory ACL.
func writeAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("pass: create store dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".keyleash-passes-*.tmp")
	if err != nil {
		return fmt.Errorf("pass: create temp file: %w", err)
	}
	name := tmp.Name()
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	// os.CreateTemp already creates the file 0600 on Unix.
	if _, err = tmp.Write(data); err != nil {
		return fmt.Errorf("pass: write store: %w", err)
	}
	if err = tmp.Sync(); err != nil {
		return fmt.Errorf("pass: fsync store: %w", err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("pass: close store: %w", err)
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("pass: replace store: %w", err)
	}
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync() // best effort; unsupported on Windows
		_ = d.Close()
	}
	return nil
}
