package pass

import (
	"bytes"
	"crypto/hmac"
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
	fileVersion = 2
	maxFileSize = 64 << 20
)

// ErrNoKey is returned by Issue, PruneExpired, Commit and VerifyAgainst
// while the store has no MAC key but holds authenticated content: such
// changes cannot be authenticated (the daemon issues passes only while
// unlocked).
var ErrNoKey = errors.New("pass: store is locked (no MAC key)")

// record is the on-disk form of a pass: its metadata plus the hex SHA-256 of
// its secret.
type record struct {
	Pass
	Hash string `json:"secret_sha256"`
}

// body is the authenticated part of the store file: every pass with its
// security-relevant fields (LastUsed is bookkeeping and kept outside) and a
// counter that increases with every authenticated write.
type body struct {
	Counter uint64   `json:"counter"`
	Passes  []record `json:"passes"`
}

// lockedRevocation is a revocation made while the store had no MAC key. It
// is applied on load and folded into the authenticated body at the next
// authenticated write. It can only ever restrict.
type lockedRevocation struct {
	ID string    `json:"id"`
	At time.Time `json:"at"`
}

// fileDoc is the store file (version 2). Body is authenticated by MAC
// (HMAC-SHA256 under a key the daemon derives from the vault); LastUsed and
// RevokedWhileLocked are not.
type fileDoc struct {
	Format             string               `json:"format"`
	Version            int                  `json:"version"`
	Body               json.RawMessage      `json:"body"`
	MAC                string               `json:"mac,omitempty"`
	LastUsed           map[string]time.Time `json:"last_used,omitempty"`
	RevokedWhileLocked []lockedRevocation   `json:"revoked_while_locked,omitempty"`
}

// fileDocV1 is the version 1 file (no authentication). It is read so an
// upgrade keeps its passes; the daemon accepts it only while the vault
// holds no baseline yet.
type fileDocV1 struct {
	Format  string   `json:"format"`
	Version int      `json:"version"`
	Passes  []record `json:"passes"`
}

type entry struct {
	p        Pass
	hash     [sha256.Size]byte
	lastSave time.Time // LastUsed value last written to disk
}

// Baseline is what the daemon keeps about the store in its authenticated
// vault state: the counter of the last authenticated write and a digest of
// every pass in it.
type Baseline struct {
	Counter uint64            `json:"counter"`
	Digests map[string]string `json:"digests,omitempty"`
}

// Diff is the outcome of VerifyAgainst.
type Diff struct {
	// OK is true when the store matches the baseline, or is exactly one
	// authenticated write ahead of it (a crash between the file write and
	// the vault update leaves that behind).
	OK bool
	// MACOK reports whether the file's body authenticated.
	MACOK bool
	// Counter is the body's counter; Baseline the vault's.
	Counter, Baseline uint64
	// Added, Removed and Changed list pass ids that differ from the
	// baseline, sorted.
	Added, Removed, Changed []string
}

// Store holds passes in memory and persists them to a JSON file with atomic
// writes. It is safe for concurrent use.
//
// While a MAC key is set (SetMACKey), every change other than Touch is an
// authenticated write: the counter increases, the body is MAC'd and the
// commit hook receives the new Baseline (the daemon stores it in the vault).
// Without a key, revocations are kept in an unauthenticated "revoked while
// locked" list next to the last authenticated body.
type Store struct {
	path  string
	clk   Clock
	mu    sync.Mutex
	byID  map[string]*entry
	dummy [sha256.Size]byte // compared against for unknown ids

	macKey   []byte
	counter  uint64          // counter of authBody
	authBody json.RawMessage // body as last written or loaded (nil: none)
	authMAC  string
	pending  map[string]time.Time // revocations not in authBody
	hook     func(Baseline)
}

// OpenStore loads the pass file at path (a missing file is an empty store).
// A malformed file is an error: the daemon must not silently forget
// revocations. clk may be nil for the real clock. The body is not
// authenticated here (that needs the vault key): see VerifyAgainst.
func OpenStore(path string, clk Clock) (*Store, error) {
	if clk == nil {
		clk = realClock{}
	}
	s := &Store{path: path, clk: clk, byID: map[string]*entry{}, pending: map[string]time.Time{}}
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
	var head struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		return nil, fmt.Errorf("pass: parse store: %w", err)
	}
	if head.Format != fileFormat || (head.Version != 1 && head.Version != fileVersion) {
		return nil, fmt.Errorf("pass: unsupported store format %q v%d", head.Format, head.Version)
	}
	var recs []record
	lastUsed := map[string]time.Time{}
	var revs []lockedRevocation
	if head.Version == 1 {
		var doc fileDocV1
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf("pass: parse store: %w", err)
		}
		recs = doc.Passes
		for _, r := range recs {
			lastUsed[r.ID] = r.LastUsed
		}
	} else {
		var doc fileDoc
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			return nil, fmt.Errorf("pass: parse store: %w", err)
		}
		var b body
		bd := json.NewDecoder(bytes.NewReader(doc.Body))
		bd.DisallowUnknownFields()
		if err := bd.Decode(&b); err != nil {
			return nil, fmt.Errorf("pass: parse store body: %w", err)
		}
		recs = b.Passes
		s.counter = b.Counter
		// The MAC covers the compact encoding (the file is indented).
		var cb bytes.Buffer
		if err := json.Compact(&cb, doc.Body); err != nil {
			return nil, fmt.Errorf("pass: parse store body: %w", err)
		}
		s.authBody = json.RawMessage(cb.Bytes())
		s.authMAC = doc.MAC
		for id, t := range doc.LastUsed {
			lastUsed[id] = t
		}
		revs = doc.RevokedWhileLocked
	}
	for i, r := range recs {
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
		p := r.Pass.clone()
		p.LastUsed = lastUsed[r.ID]
		e := &entry{p: p, lastSave: p.LastUsed}
		copy(e.hash[:], h)
		s.byID[r.ID] = e
	}
	// Revocations made while locked only ever restrict: apply them.
	for _, rv := range revs {
		if e, ok := s.byID[rv.ID]; ok {
			if !e.p.Revoked {
				e.p.Revoked, e.p.RevokedAt = true, rv.At
			}
			s.pending[rv.ID] = rv.At
		}
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

// SetCommitHook sets fn, called with the store's lock held after every
// authenticated write, with the new baseline. fn must not call the store.
func (s *Store) SetCommitHook(fn func(Baseline)) {
	s.mu.Lock()
	s.hook = fn
	s.mu.Unlock()
}

// SetMACKey sets (a copy of) the key that authenticates the store; nil
// clears and wipes it.
func (s *Store) SetMACKey(key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wipe(s.macKey)
	s.macKey = nil
	if key != nil {
		s.macKey = append([]byte(nil), key...)
	}
}

const bodyMACContext = "keyleash/v1/passes\x00"

func bodyMAC(key, b []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(bodyMACContext))
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

// recordDigest is the hex SHA-256 of a record's JSON (LastUsed excluded).
func recordDigest(r record) string {
	r.LastUsed = time.Time{}
	raw, err := json.Marshal(r)
	if err != nil {
		return "unencodable"
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// digestsOf parses a body and returns its counter and per-pass digests.
func digestsOf(raw []byte) (uint64, map[string]string, bool) {
	out := map[string]string{}
	if raw == nil {
		return 0, out, true
	}
	var b body
	if err := json.Unmarshal(raw, &b); err != nil {
		return 0, out, false
	}
	for _, r := range b.Passes {
		out[r.ID] = recordDigest(r)
	}
	return b.Counter, out, true
}

// VerifyAgainst checks the store's authenticated content (the body read by
// OpenStore, or last written) against base with the MAC key, which must be
// set. A nil base means the vault holds no baseline yet: the result is OK
// and the caller should Commit to record one. Revocations made while
// locked are not part of the comparison (they only restrict).
func (s *Store) VerifyAgainst(base *Baseline) (Diff, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.macKey == nil {
		return Diff{}, ErrNoKey
	}
	d := Diff{}
	if s.authBody != nil && s.authMAC != "" {
		d.MACOK = hmac.Equal([]byte(bodyMAC(s.macKey, s.authBody)), []byte(s.authMAC))
	}
	counter, digests, ok := digestsOf(s.authBody)
	if !ok {
		d.MACOK = false
	}
	if s.authBody == nil {
		// A version 1 file (or none): the passes in memory are the body.
		for id, e := range s.byID {
			p := e.p.clone()
			if _, pend := s.pending[id]; pend {
				continue
			}
			digests[id] = recordDigest(record{Pass: p, Hash: hex.EncodeToString(e.hash[:])})
		}
	}
	d.Counter = counter
	if base == nil {
		d.OK = true
		return d, nil
	}
	d.Baseline = base.Counter
	for id, dg := range digests {
		old, had := base.Digests[id]
		switch {
		case !had:
			d.Added = append(d.Added, id)
		case old != dg:
			d.Changed = append(d.Changed, id)
		}
	}
	for id := range base.Digests {
		if _, still := digests[id]; !still {
			d.Removed = append(d.Removed, id)
		}
	}
	sort.Strings(d.Added)
	sort.Strings(d.Removed)
	sort.Strings(d.Changed)
	same := len(d.Added)+len(d.Removed)+len(d.Changed) == 0
	switch {
	case !d.MACOK:
		// Only "never written, nothing recorded" matches without a MAC.
		d.OK = s.authBody == nil && same && base.Counter == 0
	case counter == base.Counter:
		d.OK = same
	case counter == base.Counter+1:
		d.OK = true // the vault update after this write was lost
	}
	return d, nil
}

// Commit makes an authenticated write of the current passes (folding in
// revocations made while locked) and reports the new baseline to the commit
// hook. It needs the MAC key.
func (s *Store) Commit() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.macKey == nil {
		return ErrNoKey
	}
	return s.saveLocked(true)
}

// Remove deletes pass id outright (used to roll back an issue whose audit
// record could not be written). Without the MAC key it revokes instead.
func (s *Store) Remove(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.byID[id]
	if !ok {
		return ErrNotFound
	}
	if s.macKey == nil && s.authBody != nil {
		e.p.Revoked, e.p.RevokedAt = true, s.clk.Now()
		s.pending[id] = e.p.RevokedAt
		return s.saveLocked(false)
	}
	delete(s.byID, id)
	delete(s.pending, id)
	return s.saveLocked(true)
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
	if s.macKey == nil && s.authBody != nil {
		return "", Pass{}, ErrNoKey
	}
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
	if err := s.saveLocked(true); err != nil {
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
	s.notePendingLocked(id, e.p.RevokedAt)
	return s.saveLocked(true)
}

// notePendingLocked records a revocation that cannot be authenticated now.
func (s *Store) notePendingLocked(id string, at time.Time) {
	if s.macKey == nil && s.authBody != nil {
		s.pending[id] = at
	}
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

// RevokeIDs revokes the listed passes (unknown ids are ignored) and returns
// how many were newly revoked (same persistence semantics as RevokeAll).
func (s *Store) RevokeIDs(ids []string) (int, error) {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	return s.revokeWhere(func(p Pass) bool { return set[p.ID] })
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
			s.notePendingLocked(e.p.ID, now)
			n++
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.saveLocked(true)
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
	return s.saveLocked(false)
}

// PruneExpired deletes passes that expired, or were revoked, more than
// olderThan ago, and returns how many were removed.
func (s *Store) PruneExpired(olderThan time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.macKey == nil && s.authBody != nil {
		return 0, ErrNoKey
	}
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
	if err := s.saveLocked(true); err != nil {
		for _, e := range removed {
			s.byID[e.p.ID] = e
		}
		return 0, err
	}
	return len(removed), nil
}

// saveLocked writes the store atomically. Caller holds s.mu.
//
// A change (change=true) with the MAC key set is an authenticated write: the
// counter increases, the body is rebuilt from memory and MAC'd, revocations
// made while locked are folded in and the commit hook gets the new
// baseline. Otherwise the last authenticated body is kept as is and
// revocations go to the "revoked while locked" list; a store that never had
// authenticated content writes an unauthenticated body (counter 0, no MAC).
func (s *Store) saveLocked(change bool) error {
	ids := make([]string, 0, len(s.byID))
	for id := range s.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	lastUsed := map[string]time.Time{}
	for _, id := range ids {
		if lu := s.byID[id].p.LastUsed; !lu.IsZero() {
			lastUsed[id] = lu
		}
	}
	buildBody := func(counter uint64) (json.RawMessage, error) {
		b := body{Counter: counter, Passes: make([]record, 0, len(ids))}
		for _, id := range ids {
			e := s.byID[id]
			p := e.p.clone()
			p.LastUsed = time.Time{}
			b.Passes = append(b.Passes, record{Pass: p, Hash: hex.EncodeToString(e.hash[:])})
		}
		return json.Marshal(b)
	}
	doc := fileDoc{Format: fileFormat, Version: fileVersion, LastUsed: lastUsed}
	authed := false
	counter := s.counter
	switch {
	case change && s.macKey != nil:
		counter++
		raw, err := buildBody(counter)
		if err != nil {
			return fmt.Errorf("pass: encode store: %w", err)
		}
		doc.Body, doc.MAC = raw, bodyMAC(s.macKey, raw)
		authed = true
	case s.authBody != nil:
		doc.Body, doc.MAC = s.authBody, s.authMAC
		pids := make([]string, 0, len(s.pending))
		for id := range s.pending {
			if _, ok := s.byID[id]; ok {
				pids = append(pids, id)
			}
		}
		sort.Strings(pids)
		for _, id := range pids {
			doc.RevokedWhileLocked = append(doc.RevokedWhileLocked, lockedRevocation{ID: id, At: s.pending[id]})
		}
	default:
		raw, err := buildBody(0)
		if err != nil {
			return fmt.Errorf("pass: encode store: %w", err)
		}
		doc.Body = raw
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
	if authed {
		s.counter = counter
		s.authBody, s.authMAC = doc.Body, doc.MAC
		clear(s.pending)
		if s.hook != nil {
			_, digests, _ := digestsOf(doc.Body)
			s.hook(Baseline{Counter: counter, Digests: digests})
		}
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
