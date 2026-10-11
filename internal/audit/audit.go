// Package audit is keyleash's append-only, hash-chained JSONL audit log
// (spec §11).
//
// Files are named audit-YYYY-MM.jsonl (UTC month) inside one directory. Each
// line is a canonical JSON object (see canonical.go):
//
//	{"hash":…,"prev":…,"seq":N,"ts":"RFC3339Nano UTC","type":"…", …fields}
//
// with hash = hex(SHA-256(prevHashBytes || canonical(line without "hash"))).
// seq starts at 1 and increases by one across files; the first record of a
// month chains to the last record of the previous file. While the vault is
// unlocked the daemon periodically calls Anchor, which writes an "anchor"
// record carrying HMAC-SHA256(anchor key, previous hash): an attacker without
// the vault cannot rebuild a chain that still verifies against the anchors.
//
// The log never stores secrets: Append rejects values that look like keys or
// passes (defense in depth; callers must already identify keys by
// fingerprint and passes by id).
package audit

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Errors.
var (
	ErrClosed      = errors.New("audit: log closed")
	ErrTampered    = errors.New("audit: chain verification failed")
	ErrNoAnchorKey = errors.New("audit: no anchor key set")
	ErrTooLarge    = errors.New("audit: record too large")
)

// Record types written by the package itself.
const (
	TypeAnchor  = "anchor"
	TypeRecover = "audit_recover"
)

// immediateSync lists record types that are fsync'd as soon as they are
// written; everything else is fsync'd on Flush/Close.
var immediateSync = map[string]bool{
	"panic": true, "unlock": true, "lock": true, "slot_change": true, "trip": true,
	TypeAnchor: true, TypeRecover: true,
}

// reserved keys cannot be used as field names.
var reserved = map[string]bool{"seq": true, "ts": true, "type": true, "prev": true, "hash": true}

var (
	namePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	filePattern = regexp.MustCompile(`^audit-\d{4}-\d{2}\.jsonl$`)
)

// MaxRecordSize caps one encoded record (line).
const MaxRecordSize = 256 << 10

// Clock supplies the current time. Tests inject a fake one.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Record is one decoded audit record. Fields holds every key other than the
// reserved ones, with numbers as json.Number.
type Record struct {
	Seq    uint64
	TS     time.Time
	Type   string
	Fields map[string]any
	Prev   string
	Hash   string
}

// Log appends to the audit log. It is safe for concurrent use.
type Log struct {
	mu        sync.Mutex
	dir       string
	clk       Clock
	f         *os.File
	fileName  string // name of f, or of the newest existing file before f is opened
	seq       uint64
	last      string // hex hash of the last record ("" if none)
	anchorKey []byte
	closed    bool
	broken    error // sticky write failure: the file may hold a torn line
}

func fileFor(t time.Time) string {
	return "audit-" + t.UTC().Format("2006-01") + ".jsonl"
}

func listFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if e.Type().IsRegular() && filePattern.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out) // YYYY-MM names sort chronologically
	return out, nil
}

// Open opens (creating if needed) the audit log in dir and resumes the chain
// from the last self-consistent record. A torn final line (no trailing
// newline, from a crash mid-write) is cut off and an "audit_recover" record
// noting the dropped byte count is appended. Other bad lines are left in
// place for Verify to report. clk may be nil for the real clock.
func Open(dir string, clk Clock) (*Log, error) {
	if clk == nil {
		clk = realClock{}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit: create dir: %w", err)
	}
	files, err := listFiles(dir)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	l := &Log{dir: dir, clk: clk}
	var dropped int64
	var droppedFile string
	if len(files) > 0 {
		newest := files[len(files)-1]
		l.fileName = newest
		if dropped, err = cutTornTail(filepath.Join(dir, newest)); err != nil {
			return nil, err
		}
		if dropped > 0 {
			droppedFile = newest
		}
	}
	for i := len(files) - 1; i >= 0; i-- {
		rec, found, err := lastValid(filepath.Join(dir, files[i]))
		if err != nil {
			return nil, err
		}
		if found {
			l.seq, l.last = rec.Seq, rec.Hash
			break
		}
	}
	if dropped > 0 {
		l.mu.Lock()
		err := l.appendLocked(TypeRecover, map[string]any{"file": droppedFile, "dropped_bytes": dropped})
		l.mu.Unlock()
		if err != nil {
			_ = l.Close()
			return nil, err
		}
	}
	return l, nil
}

// cutTornTail truncates path after its last newline and returns how many
// bytes were removed.
func cutTornTail(path string) (int64, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return 0, fmt.Errorf("audit: open: %w", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("audit: stat: %w", err)
	}
	size := st.Size()
	if size == 0 {
		return 0, nil
	}
	// Scan backwards for the last newline.
	const chunk = 64 << 10
	end := size
	for end > 0 {
		start := max(end-chunk, 0)
		buf := make([]byte, end-start)
		if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
			return 0, fmt.Errorf("audit: read: %w", err)
		}
		if i := bytes.LastIndexByte(buf, '\n'); i >= 0 {
			keep := start + int64(i) + 1
			if keep == size {
				return 0, nil
			}
			return size - keep, truncateSync(f, keep)
		}
		end = start
	}
	return size, truncateSync(f, 0)
}

func truncateSync(f *os.File, n int64) error {
	if err := f.Truncate(n); err != nil {
		return fmt.Errorf("audit: truncate torn record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("audit: fsync: %w", err)
	}
	return nil
}

// lastValid returns the last line of path that parses and whose hash matches
// its own contents.
func lastValid(path string) (Record, bool, error) {
	var last Record
	found := false
	err := scanLines(path, func(_ int, line []byte, _ bool) bool {
		m, rec, err := parseLine(line)
		if err != nil {
			return true
		}
		if h, err := computeHash(rec.Prev, m); err == nil && h == rec.Hash {
			last, found = rec, true
		}
		return true
	})
	return last, found, err
}

// scanLines calls fn for every line of path (without the newline). complete
// is false for a final line lacking its newline. fn returns false to stop.
func scanLines(path string, fn func(lineNo int, line []byte, complete bool) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("audit: open: %w", err)
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 64<<10)
	for n := 1; ; n++ {
		line, err := readLine(r)
		if len(line) == 0 && err == io.EOF {
			return nil
		}
		complete := err == nil
		if err != nil && err != io.EOF {
			return fmt.Errorf("audit: read: %w", err)
		}
		if !fn(n, bytes.TrimSuffix(line, []byte("\n")), complete) || !complete {
			return nil
		}
	}
}

// readLine reads one line, keeping at most MaxRecordSize+1 bytes of it (an
// overlong line is still consumed fully but will fail to parse).
func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		frag, err := r.ReadSlice('\n')
		if len(out) <= MaxRecordSize {
			out = append(out, frag...)
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		return out, err
	}
}

// parseLine decodes one canonical record line.
func parseLine(line []byte) (map[string]any, Record, error) {
	if len(line) > MaxRecordSize {
		return nil, Record{}, ErrTooLarge
	}
	v, err := decodeValue(line)
	if err != nil {
		return nil, Record{}, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, Record{}, errors.New("not an object")
	}
	var rec Record
	num, ok := m["seq"].(json.Number)
	if !ok {
		return nil, Record{}, errors.New("missing seq")
	}
	if rec.Seq, err = strconv.ParseUint(num.String(), 10, 64); err != nil {
		return nil, Record{}, errors.New("bad seq")
	}
	ts, ok1 := m["ts"].(string)
	typ, ok2 := m["type"].(string)
	prev, ok3 := m["prev"].(string)
	hash, ok4 := m["hash"].(string)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, Record{}, errors.New("missing reserved field")
	}
	rec.Type, rec.Prev, rec.Hash = typ, prev, hash
	if rec.TS, err = time.Parse(time.RFC3339Nano, ts); err != nil {
		return nil, Record{}, errors.New("bad ts")
	}
	if !validHash(rec.Hash) || (rec.Prev != "" && !validHash(rec.Prev)) {
		return nil, Record{}, errors.New("bad hash encoding")
	}
	rec.Fields = make(map[string]any, len(m))
	for k, v := range m {
		if !reserved[k] {
			rec.Fields[k] = v
		}
	}
	return m, rec, nil
}

func validHash(h string) bool {
	if len(h) != 2*sha256.Size {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// computeHash hashes m (ignoring any "hash" key) chained to prevHex.
func computeHash(prevHex string, m map[string]any) (string, error) {
	prev, err := hex.DecodeString(prevHex)
	if err != nil {
		return "", err
	}
	body := make(map[string]any, len(m))
	for k, v := range m {
		if k != "hash" {
			body[k] = v
		}
	}
	var buf bytes.Buffer
	if err := canonical(&buf, body); err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(buf.Bytes())
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Append writes one record of type typ. Field names must match
// ^[a-z][a-z0-9_]{0,63}$ and not be reserved (seq, ts, type, prev, hash);
// values must be JSON-encodable. Any string (or nested object key) that looks
// like a provider key or pass makes Append fail with ErrSecret, writing
// nothing. Types "panic", "unlock", "lock", "slot_change" and "trip" are
// fsync'd immediately; others on Flush/Close.
func (l *Log) Append(typ string, fields map[string]any) error {
	if typ == TypeAnchor || typ == TypeRecover {
		return fmt.Errorf("audit: type %q is reserved", typ)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.appendLocked(typ, fields)
}

func (l *Log) appendLocked(typ string, fields map[string]any) error {
	if l.closed {
		return ErrClosed
	}
	if l.broken != nil {
		return l.broken
	}
	if !namePattern.MatchString(typ) {
		return errors.New("audit: invalid record type")
	}
	rec := map[string]any{}
	if len(fields) > 0 {
		for k := range fields {
			if reserved[k] {
				return fmt.Errorf("audit: field name %q is reserved", k)
			}
			if !namePattern.MatchString(k) {
				return errors.New("audit: invalid field name")
			}
		}
		v, err := normalize(fields)
		if err != nil {
			return fmt.Errorf("audit: encode fields: %w", err)
		}
		if checkValue(v) {
			return ErrSecret
		}
		for k, x := range v.(map[string]any) {
			rec[k] = x
		}
	}
	now := l.clk.Now().UTC()
	rec["seq"] = json.Number(strconv.FormatUint(l.seq+1, 10))
	rec["ts"] = now.Format(time.RFC3339Nano)
	rec["type"] = typ
	rec["prev"] = l.last
	h, err := computeHash(l.last, rec)
	if err != nil {
		return fmt.Errorf("audit: hash: %w", err)
	}
	rec["hash"] = h
	var buf bytes.Buffer
	if err := canonical(&buf, rec); err != nil {
		return err
	}
	buf.WriteByte('\n')
	if buf.Len() > MaxRecordSize {
		return ErrTooLarge
	}
	if err := l.ensureFile(now); err != nil {
		return err
	}
	if _, err := l.f.Write(buf.Bytes()); err != nil {
		l.broken = fmt.Errorf("audit: write failed, log needs reopening: %w", err)
		return l.broken
	}
	l.seq++
	l.last = h
	if immediateSync[typ] {
		if err := l.f.Sync(); err != nil {
			return fmt.Errorf("audit: fsync: %w", err)
		}
	}
	return nil
}

// ensureFile opens the file for now's month. The file never moves to an
// earlier month than the newest one, so a clock stepped backwards cannot
// reorder files.
func (l *Log) ensureFile(now time.Time) error {
	name := fileFor(now)
	if name < l.fileName {
		name = l.fileName
	}
	if l.f != nil && name == l.fileName {
		return nil
	}
	if l.f != nil {
		if err := l.f.Sync(); err != nil {
			return fmt.Errorf("audit: fsync: %w", err)
		}
		if err := l.f.Close(); err != nil {
			return fmt.Errorf("audit: close: %w", err)
		}
		l.f = nil
	}
	f, err := os.OpenFile(filepath.Join(l.dir, name), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open: %w", err)
	}
	l.f, l.fileName = f, name
	return nil
}

// Flush fsyncs everything appended so far.
func (l *Log) Flush() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ErrClosed
	}
	if l.f == nil {
		return nil
	}
	return l.f.Sync()
}

// Close flushes and closes the log and forgets the anchor key.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	wipe(l.anchorKey)
	l.anchorKey = nil
	if l.f == nil {
		return nil
	}
	err := l.f.Sync()
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// SetAnchorKey sets the HMAC key used by Anchor (the vault's audit-anchor
// subkey). The key is copied; ClearAnchorKey wipes the copy.
func (l *Log) SetAnchorKey(key []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	wipe(l.anchorKey)
	l.anchorKey = append([]byte(nil), key...)
}

// ClearAnchorKey wipes and forgets the anchor key (call on vault lock).
func (l *Log) ClearAnchorKey() {
	l.mu.Lock()
	defer l.mu.Unlock()
	wipe(l.anchorKey)
	l.anchorKey = nil
}

// Anchor appends an "anchor" record whose field mac is
// hex(HMAC-SHA256(anchor key, raw bytes of the previous record's hash)).
func (l *Log) Anchor() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.anchorKey) == 0 {
		return ErrNoAnchorKey
	}
	mac, err := anchorMAC(l.anchorKey, l.last)
	if err != nil {
		return err
	}
	return l.appendLocked(TypeAnchor, map[string]any{"mac": mac})
}

func anchorMAC(key []byte, prevHex string) (string, error) {
	prev, err := hex.DecodeString(prevHex)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, key)
	m.Write(prev)
	return hex.EncodeToString(m.Sum(nil)), nil
}

// Tail returns up to the last n records in chronological order. It is a
// display helper: lines that do not parse are skipped (use Verify for
// integrity).
func (l *Log) Tail(n int) ([]Record, error) {
	if n <= 0 {
		return nil, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	files, err := listFiles(l.dir)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	var out []Record
	for i := len(files) - 1; i >= 0 && len(out) < n; i-- {
		var recs []Record
		err := scanLines(filepath.Join(l.dir, files[i]), func(_ int, line []byte, complete bool) bool {
			if !complete {
				return false
			}
			if _, rec, err := parseLine(line); err == nil {
				recs = append(recs, rec)
			}
			return true
		})
		if err != nil {
			return nil, err
		}
		need := n - len(out)
		if len(recs) > need {
			recs = recs[len(recs)-need:]
		}
		out = append(recs, out...)
	}
	return out, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
