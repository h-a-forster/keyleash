package audit

import (
	"crypto/hmac"
	"fmt"
	"path/filepath"
)

// Problem locates the first record that failed verification.
type Problem struct {
	File   string // file name within the audit dir
	Line   int    // 1-based line number
	Seq    uint64 // expected sequence number at that point
	Reason string
}

func (p Problem) String() string {
	return fmt.Sprintf("%s:%d (expected seq %d): %s", p.File, p.Line, p.Seq, p.Reason)
}

// Report summarises a verification run. Counts cover records checked up to
// (not including) the first problem.
type Report struct {
	Records         int
	Files           int
	Anchors         int
	AnchorsVerified int
	FirstBad        *Problem
}

// Verify checks every audit file in dir: each line must parse, carry the next
// sequence number (starting at 1), chain to the previous record's hash
// (across files, oldest first) and hash correctly. This detects edited,
// deleted, inserted and reordered records, deleted leading files, and
// truncation anywhere but the very end. With anchorKey, every anchor's MAC
// must verify too, which defeats an attacker who rewrote the chain without
// the vault; without it anchors are only counted.
//
// Removing records from the end of the newest file (after the last anchor)
// cannot be detected from the files alone.
//
// A failed check returns the report with FirstBad set and an error wrapping
// ErrTampered; I/O failures return a plain error.
func Verify(dir string, anchorKey []byte) (Report, error) {
	var rep Report
	files, err := listFiles(dir)
	if err != nil {
		return rep, fmt.Errorf("audit: list: %w", err)
	}
	expectSeq := uint64(1)
	prev := ""
	for _, name := range files {
		rep.Files++
		var bad *Problem
		err := scanLines(filepath.Join(dir, name), func(n int, line []byte, complete bool) bool {
			fail := func(reason string) bool {
				bad = &Problem{File: name, Line: n, Seq: expectSeq, Reason: reason}
				return false
			}
			if !complete {
				return fail("truncated record (no trailing newline)")
			}
			if len(line) == 0 {
				return fail("empty line")
			}
			m, rec, err := parseLine(line)
			if err != nil {
				return fail("malformed record")
			}
			if rec.Seq != expectSeq {
				return fail(fmt.Sprintf("sequence %d out of order (records deleted, inserted or reordered)", rec.Seq))
			}
			if rec.Prev != prev {
				return fail("prev does not match previous record's hash (chain broken)")
			}
			h, err := computeHash(rec.Prev, m)
			if err != nil || h != rec.Hash {
				return fail("hash mismatch (record edited)")
			}
			if rec.Type == TypeAnchor {
				rep.Anchors++
				if anchorKey != nil {
					mac, _ := rec.Fields["mac"].(string)
					want, err := anchorMAC(anchorKey, rec.Prev)
					if err != nil || !hmac.Equal([]byte(mac), []byte(want)) {
						return fail("anchor MAC mismatch")
					}
					rep.AnchorsVerified++
				}
			}
			rep.Records++
			expectSeq++
			prev = rec.Hash
			return true
		})
		if err != nil {
			return rep, err
		}
		if bad != nil {
			rep.FirstBad = bad
			return rep, fmt.Errorf("%w at %s", ErrTampered, bad)
		}
	}
	return rep, nil
}
