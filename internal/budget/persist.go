package budget

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

// record is one line of ledger-YYYY-MM.jsonl. It holds no secrets.
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

type line struct {
	file string
	data []byte
}

// writer batches records and appends them to the month's file. pending is
// guarded by the Ledger's mu; file operations by writer.mu (taken before
// Ledger.mu when both are needed).
type writer struct {
	dir     string
	pending []line

	mu   sync.Mutex
	f    *os.File
	name string
}

func newWriter(dir string) *writer { return &writer{dir: dir} }

func (w *writer) enqueue(rec record, local time.Time) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("budget: encode record: %w", err)
	}
	w.pending = append(w.pending, line{file: fileName(local), data: append(b, '\n')})
	return nil
}

func (w *writer) take() []line {
	b := w.pending
	w.pending = nil
	return b
}

// putBack restores an unwritten batch ahead of newer records. Lines that were
// in fact written before the failure may be written twice; replay then
// over-counts, which is the fail-closed direction.
func (w *writer) putBack(b []line) { w.pending = append(b, w.pending...) }

func (w *writer) writeLocked(batch []line) error {
	if len(batch) == 0 {
		return nil
	}
	for _, ln := range batch {
		if w.f == nil || w.name != ln.file {
			if err := w.closeLocked(); err != nil {
				return err
			}
			f, err := os.OpenFile(filepath.Join(w.dir, ln.file), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
			if err != nil {
				return fmt.Errorf("budget: open ledger file: %w", err)
			}
			w.f, w.name = f, ln.file
		}
		if _, err := w.f.Write(ln.data); err != nil {
			return fmt.Errorf("budget: write ledger file: %w", err)
		}
	}
	if err := w.f.Sync(); err != nil {
		return fmt.Errorf("budget: sync ledger file: %w", err)
	}
	return nil
}

func (w *writer) closeLocked() error {
	if w.f == nil {
		return nil
	}
	err := w.f.Sync()
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	w.f, w.name = nil, ""
	if err != nil {
		return fmt.Errorf("budget: close ledger file: %w", err)
	}
	return nil
}

// replay loads the charges needed to rebuild windows as of now: everything in
// the current calendar month and the last histTail before now.
func replay(dir string, now time.Time, loc *time.Location) ([]*charge, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("budget: create ledger dir: %w", err)
	}
	monthStart := periodStart(WindowMonth, now, loc)
	cutoff := monthStart
	if t := now.Add(-histTail); t.Before(cutoff) {
		cutoff = t
	}
	prev := time.Date(monthStart.Year(), monthStart.Month()-1, 1, 0, 0, 0, 0, loc)
	var hist []*charge
	for _, m := range []time.Time{prev, monthStart} {
		recs, err := readFile(filepath.Join(dir, fileName(m)))
		if err != nil {
			return nil, err
		}
		for _, r := range recs {
			if r.TS.Before(cutoff) {
				continue
			}
			hist = append(hist, &charge{t: r.TS, amount: r.Amount, scopes: r.Scopes, model: r.Model})
		}
	}
	slices.SortStableFunc(hist, func(a, b *charge) int { return a.t.Compare(b.t) })
	return hist, nil
}

// readFile parses a ledger file. A missing file is empty. An unparsable final
// line without a trailing newline is a torn write: it is dropped and the file
// is truncated to the last complete line. A complete final line missing only
// its newline gets one appended. Anything else malformed is an error.
func readFile(p string) ([]record, error) {
	data, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("budget: read %s: %w", filepath.Base(p), err)
	}
	var recs []record
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
				recs = append(recs, r)
			}
			if last {
				if err := fixFile(p, -1); err != nil {
					return nil, err
				}
			}
		case last:
			if err := fixFile(p, int64(off)); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("budget: %s line %d is corrupt: %v", filepath.Base(p), n, perr)
		}
		if last {
			break
		}
		off += i + 1
		rest = rest[i+1:]
	}
	return recs, nil
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
