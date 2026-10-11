package budget

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

// record is one line of ledger-YYYY-MM.jsonl. It holds no secrets.
//
// Records form a hash chain: Prev is the hex SHA-256 of the previous record's
// complete line (without its newline), across month files; it is empty only
// for the first record ever written. When a MAC key is set (SetMACKey), MAC is
// hex HMAC-SHA256(key, SHA-256(body)), where body is the line as it would be
// without the mac field. MAC is always the last field, so body is recovered
// byte-exactly by cutting the `,"mac":"..."` suffix.
type record struct {
	TS        time.Time    `json:"ts"`
	ID        string       `json:"id"`
	Scopes    []string     `json:"scopes"`
	Amount    money.Micros `json:"amount_micros"`
	Reserved  money.Micros `json:"reserved_micros"`
	Estimated bool         `json:"estimated"`
	Overrun   bool         `json:"overrun"`
	Pass      string       `json:"pass"`
	Provider  string       `json:"provider"`
	Model     string       `json:"model"`
	Session   string       `json:"session"`
	Client    string       `json:"client"`
	Prev      string       `json:"prev,omitempty"`
	MAC       string       `json:"mac,omitempty"` // must stay the last field
}

func (r *record) validate() error {
	switch {
	case r.TS.IsZero():
		return errors.New("missing ts")
	case r.Amount < 0 || r.Reserved < 0:
		return errors.New("negative amount")
	case len(r.Scopes) == 0:
		return errors.New("missing scopes")
	}
	for _, s := range r.Scopes {
		if ValidateScope(s) != nil {
			return errors.New("bad scope")
		}
	}
	return nil
}

// fileName is the ledger file for the month containing local time t.
func fileName(t time.Time) string { return "ledger-" + t.Format("2006-01") + ".jsonl" }

// monthOf returns "YYYY-MM" for a ledger file name, or "" if name is not one.
func monthOf(name string) string {
	m, ok := strings.CutPrefix(name, "ledger-")
	if !ok {
		return ""
	}
	m, ok = strings.CutSuffix(m, ".jsonl")
	if !ok || len(m) != 7 {
		return ""
	}
	if _, err := time.Parse("2006-01", m); err != nil {
		return ""
	}
	return m
}

// ledgerFiles lists the ledger file names in dir, oldest month first.
func ledgerFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("budget: list ledger dir: %w", err)
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() && monthOf(e.Name()) != "" {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	return names, nil
}

// lineHash is the chain hash of one complete line (without its newline).
func lineHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// recordMAC is the MAC over a record body (the line without its mac field).
func recordMAC(key, body []byte) []byte {
	h := sha256.Sum256(body)
	m := hmac.New(sha256.New, key)
	m.Write(h[:])
	return m.Sum(nil)
}

// macBody returns the record body of ln (ln without its trailing mac field,
// closed with '}') if mac is ln's last field with exactly that value.
func macBody(ln []byte, mac string) ([]byte, bool) {
	if len(mac) != 2*sha256.Size {
		return nil, false
	}
	suf := []byte(`,"mac":"` + mac + `"}`)
	if !bytes.HasSuffix(ln, suf) {
		return nil, false
	}
	return slices.Concat(ln[:len(ln)-len(suf)], []byte("}")), true
}

type line struct {
	file   string
	data   []byte // complete line including the trailing newline
	amount money.Micros
	hash   string
}

// writer batches records and appends them to the month's file. pending, head
// and macKey are guarded by the Ledger's mu; file state and checkpoints by
// writer.mu (taken before Ledger.mu when both are needed).
type writer struct {
	dir     string
	pending []line
	head    string // chain hash of the last enqueued line
	macKey  []byte

	mu       sync.Mutex
	f        *os.File
	name     string
	off      int64      // size of f
	work     Checkpoint // includes lines written to f but not yet fsync'd
	durable  Checkpoint // as of the last successful fsync
	unsynced bool       // lines were written but their fsync failed
}

func newWriter(dir string, cp Checkpoint) *writer {
	return &writer{dir: dir, head: cp.LastHash, work: cp, durable: cp}
}

func (w *writer) enqueue(rec record, local time.Time) error {
	rec.Prev, rec.MAC = w.head, ""
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("budget: encode record: %w", err)
	}
	if len(body) == 0 || body[len(body)-1] != '}' {
		return errors.New("budget: encode record: unexpected encoding")
	}
	data := body
	if len(w.macKey) > 0 {
		mac := hex.EncodeToString(recordMAC(w.macKey, body))
		data = slices.Concat(body[:len(body)-1], []byte(`,"mac":"`+mac+`"}`))
	}
	h := lineHash(data)
	w.head = h
	w.pending = append(w.pending, line{file: fileName(local), data: append(data, '\n'), amount: rec.Amount, hash: h})
	return nil
}

func (w *writer) take() []line {
	b := w.pending
	w.pending = nil
	return b
}

// putBack restores the unwritten tail of a batch ahead of newer records, so
// the hash chain stays in order. Lines already written are never written
// again (a duplicate would break the chain).
func (w *writer) putBack(b []line) { w.pending = append(slices.Clip(b), w.pending...) }

// writeLocked appends batch and fsyncs. It returns how many lines were
// completely written; on error the caller puts back batch[n:]. A partly
// written line is cut from the file so a retry cannot leave a fragment
// mid-file. With an empty batch it only retries a failed fsync.
func (w *writer) writeLocked(batch []line) (int, error) {
	for i, ln := range batch {
		if w.f == nil || w.name != ln.file {
			if err := w.closeLocked(false); err != nil {
				return i, err
			}
			if err := w.openLocked(ln.file); err != nil {
				return i, err
			}
		}
		n, err := w.f.Write(ln.data)
		if err != nil {
			p, off := filepath.Join(w.dir, w.name), w.off
			_ = w.closeLocked(true)
			if n > 0 {
				_ = fixFile(p, off)
			}
			return i, fmt.Errorf("budget: write ledger file: %w", err)
		}
		w.off += int64(n)
		w.work.Records++
		w.work.Settled = addSat(w.work.Settled, ln.amount)
		w.work.LastHash = ln.hash
	}
	return len(batch), w.syncLocked()
}

// openLocked opens name for appending (after repairing a torn tail) and
// recomputes the working checkpoint from the records already in it.
func (w *writer) openLocked(name string) error {
	p := filepath.Join(w.dir, name)
	ents, _, err := readFile(p)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("budget: open ledger file: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("budget: stat ledger file: %w", err)
	}
	w.f, w.name, w.off = f, name, st.Size()
	w.work = checkpointOf(monthOf(name), ents)
	return nil
}

func (w *writer) syncLocked() error {
	if w.f == nil {
		return nil
	}
	if err := w.f.Sync(); err != nil {
		w.unsynced = true
		return fmt.Errorf("budget: sync ledger file: %w", err)
	}
	w.unsynced = false
	w.durable = w.work
	return nil
}

// closeLocked fsyncs and closes the file. If the fsync fails the file stays
// open, so the fsync can be retried, unless force is set.
func (w *writer) closeLocked(force bool) error {
	if w.f == nil {
		return nil
	}
	err := w.syncLocked()
	if err != nil && !force {
		return err
	}
	if cerr := w.f.Close(); err == nil && cerr != nil {
		err = fmt.Errorf("budget: close ledger file: %w", cerr)
	}
	w.f, w.name, w.off = nil, "", 0
	return err
}

// entry is one parsed ledger line and its raw bytes (without the newline).
type entry struct {
	rec record
	raw []byte
}

// checkpointOf summarises the records of one month file.
func checkpointOf(month string, ents []entry) Checkpoint {
	cp := Checkpoint{Month: month, Records: uint64(len(ents))}
	for _, e := range ents {
		cp.Settled = addSat(cp.Settled, e.rec.Amount)
	}
	if len(ents) > 0 {
		cp.LastHash = lineHash(ents[len(ents)-1].raw)
	}
	return cp
}

// chainHead returns the checkpoint at the end of the newest non-empty ledger
// file, which new records chain onto, and the number of torn lines it cut.
func chainHead(dir string) (Checkpoint, int, error) {
	names, err := ledgerFiles(dir)
	if err != nil {
		return Checkpoint{}, 0, err
	}
	torn := 0
	for i := len(names) - 1; i >= 0; i-- {
		ents, t, err := readFile(filepath.Join(dir, names[i]))
		torn += t
		if err != nil {
			return Checkpoint{}, torn, err
		}
		if len(ents) > 0 {
			return checkpointOf(monthOf(names[i]), ents), torn, nil
		}
	}
	return Checkpoint{}, torn, nil
}

// replay loads the charges needed to rebuild windows as of now: everything in
// the current calendar month and the last histTail before now. It also
// reports how many torn final lines it cut.
func replay(dir string, now time.Time, loc *time.Location) ([]*charge, int, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, 0, fmt.Errorf("budget: create ledger dir: %w", err)
	}
	monthStart := periodStart(WindowMonth, now, loc)
	cutoff := monthStart
	if t := now.Add(-histTail); t.Before(cutoff) {
		cutoff = t
	}
	prev := time.Date(monthStart.Year(), monthStart.Month()-1, 1, 0, 0, 0, 0, loc)
	var hist []*charge
	torn := 0
	for _, m := range []time.Time{prev, monthStart} {
		ents, t, err := readFile(filepath.Join(dir, fileName(m)))
		torn += t
		if err != nil {
			return nil, torn, err
		}
		for _, e := range ents {
			r := &e.rec
			if r.TS.Before(cutoff) {
				continue
			}
			hist = append(hist, &charge{t: r.TS, amount: r.Amount, scopes: r.Scopes, model: r.Model})
		}
	}
	slices.SortStableFunc(hist, func(a, b *charge) int { return a.t.Compare(b.t) })
	return hist, torn, nil
}

// readFile parses a ledger file. A missing file is empty. An unparsable final
// line without a trailing newline is a torn write: it is dropped, the file is
// truncated to the last complete line, and it is counted in the second
// result. A complete final line missing only its newline gets one appended.
// Anything else malformed is an error.
func readFile(p string) ([]entry, int, error) {
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("budget: read %s: %w", filepath.Base(p), err)
	}
	var ents []entry
	torn := 0
	rest := data
	off := 0
	for n := 1; len(rest) > 0; n++ {
		i := bytes.IndexByte(rest, '\n')
		last := i < 0
		ln := rest
		if !last {
			ln = rest[:i]
		}
		var r record
		perr := parseLine(ln, &r)
		switch {
		case perr == nil:
			if len(bytes.TrimSpace(ln)) > 0 {
				ents = append(ents, entry{rec: r, raw: ln})
			}
			if last {
				if err := fixFile(p, -1); err != nil {
					return nil, torn, err
				}
			}
		case last:
			torn++
			if err := fixFile(p, int64(off)); err != nil {
				return nil, torn, err
			}
		default:
			return nil, torn, fmt.Errorf("budget: %s line %d is corrupt: %v", filepath.Base(p), n, perr)
		}
		if last {
			break
		}
		off += i + 1
		rest = rest[i+1:]
	}
	return ents, torn, nil
}

func parseLine(ln []byte, r *record) error {
	if len(bytes.TrimSpace(ln)) == 0 {
		return nil
	}
	if err := json.Unmarshal(ln, r); err != nil {
		return errors.New("invalid JSON")
	}
	return r.validate()
}

// fixFile truncates p to size, or appends a newline when size < 0.
func fixFile(p string, size int64) error {
	// On Windows an O_APPEND handle lacks the access needed to truncate.
	flag := os.O_WRONLY
	if size < 0 {
		flag |= os.O_APPEND
	}
	f, err := os.OpenFile(p, flag, 0o600)
	if err != nil {
		return fmt.Errorf("budget: repair %s: %w", filepath.Base(p), err)
	}
	if size >= 0 {
		err = f.Truncate(size)
	} else {
		_, err = f.Write([]byte{'\n'})
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("budget: repair %s: %w", filepath.Base(p), err)
	}
	return nil
}
