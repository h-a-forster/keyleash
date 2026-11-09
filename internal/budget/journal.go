package budget

import (
	"bytes"
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
// when the ledger opens is held again and stays in flight until someone
// settles it (the daemon, as soon as it has the MAC key: ExpireInFlight).
//
// Lines are written without an fsync: this guards against a process that dies,
// which leaves the OS's copy, not against losing power. The file is not
// authenticated. Removing it while the daemon is down loses only what would
// have been lost without it; adding to it can only charge more.
const (
	journalName = "inflight.jsonl"
	// journalMax is the size above which the journal is emptied once nothing
	// is in flight.
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
}

type journal struct {
	path string
	f    *os.File
	size int64
}

// openJournal opens the journal in dir and returns the holds without a done
// line, oldest first. A line that does not parse (a torn write) is skipped.
func openJournal(dir string) (*journal, []journalLine, error) {
	p := filepath.Join(dir, journalName)
	data, err := os.ReadFile(p)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, nil, fmt.Errorf("budget: read journal: %w", err)
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
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("budget: open journal: %w", err)
	}
	return &journal{path: p, f: f, size: int64(len(data))}, holds, nil
}

// write appends lines. A partly written batch is cut off so it cannot run into
// the next line.
func (j *journal) write(lines ...journalLine) error {
	if j.f == nil || len(lines) == 0 {
		return nil
	}
	var b bytes.Buffer
	for _, jl := range lines {
		raw, err := json.Marshal(jl)
		if err != nil {
			return fmt.Errorf("budget: encode journal line: %w", err)
		}
		b.Write(raw)
		b.WriteByte('\n')
	}
	n, err := j.f.Write(b.Bytes())
	if err != nil {
		if n > 0 {
			_ = fixFile(j.path, j.size)
		}
		return fmt.Errorf("budget: write journal: %w", err)
	}
	j.size += int64(n)
	return nil
}

// compact empties an oversized journal. The caller knows nothing is in flight
// and no charge is waiting to be written.
func (j *journal) compact() {
	if j.f == nil || j.size <= journalMax {
		return
	}
	if fixFile(j.path, 0) == nil {
		j.size = 0
	}
}

func (j *journal) close() error {
	if j.f == nil {
		return nil
	}
	err := j.f.Close()
	j.f = nil
	return err
}
