package budget

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

// A reservation lives in memory, so a process that dies takes it along, while
// the request it stands for may still be billed upstream. The journal keeps
// it on disk: a hold line before the request can leave, a done line once the
// reservation is released or its charge is durable. Whatever has no done line
// when the ledger opens waits for the MAC key (RecoverInFlight), and is charged
// unless its record is already in the ledger.
//
// Lines are written without an fsync: this guards against a process that dies,
// which leaves the OS's copy, not against losing power. A hold carries a MAC, so
// only what the daemon itself reserved can be charged, and at the amount it
// reserved; a line that fails the check charges nothing and is reported. Done
// lines carry none. So removing the file, or adding a done line, loses only the
// charges of requests in flight when the daemon died, and removing a done line
// charges a genuine released reservation at most.
const (
	journalName = "inflight.jsonl"
	// journalMax is the size above which the journal is rewritten to the holds
	// still open.
	journalMax = 1 << 20
)

// journalLine is a hold, or with Done the end of the hold with that id.
type journalLine struct {
	ID      string       `json:"id"`
	Done    bool         `json:"done,omitempty"`
	Scopes  []string     `json:"scopes,omitempty"`
	Amount  money.Micros `json:"amount_micros,omitempty"`
	Meta    *Meta        `json:"meta,omitempty"`
	Created time.Time    `json:"created,omitzero"`
	MAC     string       `json:"mac,omitempty"`
}

// journalMAC is a hold's MAC. The prefix keeps it from passing for a record's.
func journalMAC(key []byte, jl journalLine) string {
	jl.MAC = ""
	raw, err := json.Marshal(jl)
	if err != nil {
		return "" // never matches a line that parsed
	}
	return hex.EncodeToString(recordMAC(key, append([]byte("keyleash/v1/journal\x00"), raw...)))
}

// verified reports whether a hold carries its MAC under key.
func (jl journalLine) verified(key []byte) bool {
	return jl.MAC != "" && hmac.Equal([]byte(jl.MAC), []byte(journalMAC(key, jl)))
}

type journal struct {
	path   string
	f      *os.File // nil between a failed rewrite and the next write
	size   int64
	closed bool
}

// openJournal opens the journal in dir and returns the holds without a done
// line, oldest first. A line that does not parse is skipped. A final line with
// no newline (a torn write) is ended if whole and cut if not, so the next write
// cannot run into it.
func openJournal(dir string) (*journal, []journalLine, error) {
	p := filepath.Join(dir, journalName)
	data, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("budget: read journal: %w", err)
	}
	_ = os.Remove(p + ".tmp") // a rewrite that died; the journal itself is intact
	if n := len(data); n > 0 && data[n-1] != '\n' {
		keep := bytes.LastIndexByte(data, '\n') + 1
		if json.Valid(data[keep:]) {
			err = fixFile(p, -1)
			data = append(data, '\n')
		} else {
			err = fixFile(p, int64(keep))
			data = data[:keep]
		}
		if err != nil {
			return nil, nil, err
		}
	}
	var holds []journalLine
	for _, ln := range bytes.Split(data, []byte{'\n'}) {
		var jl journalLine
		if json.Unmarshal(ln, &jl) != nil || jl.ID == "" {
			continue
		}
		if !jl.Done {
			holds = append(holds, jl)
			continue
		}
		for i := range holds {
			if holds[i].ID == jl.ID {
				holds = append(holds[:i], holds[i+1:]...)
				break
			}
		}
	}
	j := &journal{path: p}
	if err := j.open(); err != nil {
		return nil, nil, err
	}
	return j, holds, nil
}

func (j *journal) open() error {
	f, err := os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("budget: open journal: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return fmt.Errorf("budget: open journal: %w", err)
	}
	j.f, j.size = f, st.Size()
	return nil
}

// write appends lines. A partly written batch is cut off so it cannot run into
// the next line.
func (j *journal) write(lines ...journalLine) error {
	if j.closed || len(lines) == 0 {
		return nil
	}
	if j.f == nil {
		if err := j.open(); err != nil {
			return err
		}
	}
	b, err := encodeJournal(lines)
	if err != nil {
		return err
	}
	n, err := j.f.Write(b)
	if err != nil {
		if n > 0 {
			_ = fixFile(j.path, j.size)
		}
		return fmt.Errorf("budget: write journal: %w", err)
	}
	j.size += int64(n)
	return nil
}

func encodeJournal(lines []journalLine) ([]byte, error) {
	var b bytes.Buffer
	for _, jl := range lines {
		raw, err := json.Marshal(jl)
		if err != nil {
			return nil, fmt.Errorf("budget: encode journal line: %w", err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

func (j *journal) oversized() bool { return !j.closed && j.size > journalMax }

// rewrite replaces the journal with holds, atomically, so a death at any point
// leaves all of them on disk. A failure leaves the journal as it was, to be
// tried again at the next flush; if it also cannot be reopened, the next write
// fails and nothing can be reserved.
func (j *journal) rewrite(holds []journalLine) {
	b, err := encodeJournal(holds)
	if err != nil {
		return
	}
	tmp := j.path + ".tmp"
	if err := writeSynced(tmp, b); err != nil {
		_ = os.Remove(tmp)
		return
	}
	if j.f != nil {
		_ = j.f.Close() // Windows cannot replace an open file
		j.f = nil
	}
	if err := os.Rename(tmp, j.path); err != nil {
		_ = os.Remove(tmp)
	}
	_ = j.open()
}

func (j *journal) close() error {
	j.closed = true
	if j.f == nil {
		return nil
	}
	err := j.f.Close()
	j.f = nil
	return err
}
