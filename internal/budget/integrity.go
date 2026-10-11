package budget

import (
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/h-a-forster/keyleash/internal/money"
)

// Checkpoint summarises the durable end of the ledger's hash chain. The daemon
// stores it in its own authenticated state (vault metadata or the audit log)
// — on lock, on shutdown and periodically — and passes it back to
// VerifyIntegrity to detect truncation, deletion or a rewritten chain. It
// holds no secrets.
type Checkpoint struct {
	// Month is "YYYY-MM" of the ledger file holding the last record.
	Month string `json:"month"`
	// Records is the number of records in that file up to and including
	// the last one.
	Records uint64 `json:"records"`
	// LastHash is the hex SHA-256 of the last record's line (the chain head).
	LastHash string `json:"last_hash"`
	// Settled is the sum of those records' amounts.
	Settled money.Micros `json:"settled_micros"`
}

// Checkpoint returns the chain state as of the last successful fsync (records
// still pending in memory are not included; call Flush first to include
// them). The zero Checkpoint means the ledger is empty.
func (l *Ledger) Checkpoint() Checkpoint {
	l.w.mu.Lock()
	defer l.w.mu.Unlock()
	return l.w.durable
}

// VerifyOptions configures VerifyIntegrity.
type VerifyOptions struct {
	// Checkpoint is a previously stored Checkpoint (nil: none). The ledger
	// must still contain that exact chain prefix.
	Checkpoint *Checkpoint
}

// maxProblems caps Integrity.Problems.
const maxProblems = 32

// Integrity is the result of VerifyIntegrity. Problems name files and line
// numbers only; they never contain record contents.
type Integrity struct {
	Files   int    // ledger files examined
	Records uint64 // well-formed records examined

	// ChainBreaks counts records whose prev does not match the hash of the
	// record before them: a record was edited, deleted, inserted or
	// reordered (or written after the clock moved back into an earlier
	// month).
	ChainBreaks int
	// MissingHistory: the oldest record chains to an earlier record that no
	// longer exists (older ledger files were deleted).
	MissingHistory bool
	// MissingMonths lists month files ("YYYY-MM") that must exist but do
	// not: the month before a file whose first record breaks the chain, and
	// a checkpoint's month.
	MissingMonths []string
	// Corrupt counts unparsable lines other than a torn final line.
	Corrupt int
	// TornLines counts torn final lines (crash mid-write): those cut when
	// the ledger was opened plus any found now. They are tolerated (not
	// counted by OK); a checkpoint detects a deliberate tail cut.
	TornLines int
	// Unauthenticated counts records without a mac (only when a key was
	// given). Records written before SetMACKey was first called have none.
	Unauthenticated int
	// MACFailures counts records whose mac does not verify under the key.
	MACFailures int
	// CheckpointMismatch: the stored checkpoint, or the chain state this
	// ledger itself last wrote, is no longer a prefix of the files (records
	// were truncated, deleted or rewritten).
	CheckpointMismatch bool
	// Problems describes the first few failures.
	Problems []string
}

// OK reports whether no integrity failure was found. The daemon must fail
// closed (trip) when OK is false or VerifyIntegrity returns an error.
func (in *Integrity) OK() bool {
	return in.ChainBreaks == 0 && !in.MissingHistory && len(in.MissingMonths) == 0 &&
		in.Corrupt == 0 && in.Unauthenticated == 0 && in.MACFailures == 0 && !in.CheckpointMismatch
}

func (in *Integrity) problem(format string, args ...any) {
	if len(in.Problems) < maxProblems {
		in.Problems = append(in.Problems, fmt.Sprintf(format, args...))
	}
}

func (in *Integrity) missing(month string) {
	if !slices.Contains(in.MissingMonths, month) {
		in.MissingMonths = append(in.MissingMonths, month)
	}
}

// monthFile is what verification keeps per ledger file for checkpoint checks.
type monthFile struct {
	hashes  []string
	amounts []money.Micros
}

// VerifyIntegrity flushes pending records and checks every ledger file in the
// directory, oldest first: the hash chain across all records and months, the
// mac of every record when key is non-empty, the chain state this ledger last
// wrote, and the stored checkpoint in opts (if any). It does not modify the
// files.
//
// Without key the chain only detects naive edits (anyone can recompute it);
// with key and a checkpoint, edits, insertions, deletions and truncation are
// all detected. The daemon calls it after unlock (after SetMACKey) and must
// trip when the result is not OK. An error (I/O, or a failed flush) also
// means integrity could not be established: fail closed.
func (l *Ledger) VerifyIntegrity(key []byte, opts ...VerifyOptions) (Integrity, error) {
	l.w.mu.Lock()
	defer l.w.mu.Unlock()
	var in Integrity
	if err := l.flushWLocked(); err != nil {
		return in, err
	}
	in.TornLines = l.tornAtOpen
	names, err := ledgerFiles(l.dir)
	if err != nil {
		return in, err
	}
	files := map[string]*monthFile{}
	for _, name := range names {
		files[monthOf(name)] = nil
	}
	prev, first := "", true
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(l.dir, name))
		if err != nil {
			return in, fmt.Errorf("budget: read %s: %w", name, err)
		}
		in.Files++
		month := monthOf(name)
		mf := &monthFile{}
		files[month] = mf
		firstInFile := true
		for n, rest := 1, data; len(rest) > 0; n++ {
			i := bytes.IndexByte(rest, '\n')
			ln := rest
			if i >= 0 {
				ln, rest = rest[:i], rest[i+1:]
			} else {
				rest = nil
			}
			if len(bytes.TrimSpace(ln)) == 0 {
				continue
			}
			h := lineHash(ln)
			var r record
			if perr := parseLine(ln, &r); perr != nil {
				if i < 0 {
					in.TornLines++
					in.problem("%s line %d: torn final line", name, n)
					continue
				}
				in.Corrupt++
				in.problem("%s line %d: corrupt record", name, n)
				mf.hashes, mf.amounts = append(mf.hashes, h), append(mf.amounts, 0)
				prev, first, firstInFile = h, false, false
				continue
			}
			in.Records++
			switch {
			case first:
				if r.Prev != "" {
					in.MissingHistory = true
					in.problem("%s line %d: earlier records are missing", name, n)
				}
			case r.Prev != prev:
				in.ChainBreaks++
				in.problem("%s line %d: hash chain broken", name, n)
				if firstInFile {
					if pm := prevMonth(month); pm != "" {
						if _, ok := files[pm]; !ok {
							in.missing(pm)
							in.problem("ledger-%s.jsonl is missing", pm)
						}
					}
				}
			}
			if len(key) > 0 {
				switch body, ok := macBody(ln, r.MAC); {
				case r.MAC == "":
					in.Unauthenticated++
					in.problem("%s line %d: record has no mac", name, n)
				case !ok:
					in.MACFailures++
					in.problem("%s line %d: mac does not verify", name, n)
				default:
					want := recordMAC(key, body)
					got, derr := hex.DecodeString(r.MAC)
					if derr != nil || !hmac.Equal(got, want) {
						in.MACFailures++
						in.problem("%s line %d: mac does not verify", name, n)
					}
				}
			}
			mf.hashes, mf.amounts = append(mf.hashes, h), append(mf.amounts, r.Amount)
			prev, first, firstInFile = h, false, false
		}
	}
	checkCP := func(cp Checkpoint, what string) {
		if cp.Records == 0 && cp.LastHash == "" {
			return
		}
		mf := files[cp.Month]
		switch {
		case cp.Records == 0 || monthOf("ledger-"+cp.Month+".jsonl") == "":
			in.CheckpointMismatch = true
			in.problem("%s is malformed", what)
		case mf == nil:
			in.CheckpointMismatch = true
			in.missing(cp.Month)
			in.problem("%s: ledger-%s.jsonl is missing", what, cp.Month)
		case uint64(len(mf.hashes)) < cp.Records:
			in.CheckpointMismatch = true
			in.problem("%s: ledger-%s.jsonl has %d records, want at least %d", what, cp.Month, len(mf.hashes), cp.Records)
		default:
			var sum money.Micros
			for _, a := range mf.amounts[:cp.Records] {
				sum = addSat(sum, a)
			}
			if mf.hashes[cp.Records-1] != cp.LastHash || sum != cp.Settled {
				in.CheckpointMismatch = true
				in.problem("%s: ledger-%s.jsonl was rewritten", what, cp.Month)
			}
		}
	}
	checkCP(l.w.durable, "chain state at last write")
	for _, o := range opts {
		if o.Checkpoint != nil {
			checkCP(*o.Checkpoint, "stored checkpoint")
		}
	}
	slices.Sort(in.MissingMonths)
	return in, nil
}

// prevMonth returns the "YYYY-MM" before month, or "".
func prevMonth(month string) string {
	t, err := time.Parse("2006-01", month)
	if err != nil {
		return ""
	}
	return t.AddDate(0, -1, 0).Format("2006-01")
}
