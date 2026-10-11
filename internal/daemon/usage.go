package daemon

import (
	"bufio"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/money"
)

// usageRecord mirrors the fields of a budget ledger record that usage
// reports need (see internal/budget/persist.go). Reading is display-only:
// integrity is established by budget.VerifyIntegrity, not here.
type usageRecord struct {
	TS        time.Time    `json:"ts"`
	Amount    money.Micros `json:"amount_micros"`
	Estimated bool         `json:"estimated"`
	Pass      string       `json:"pass"`
	Provider  string       `json:"provider"`
	Model     string       `json:"model"`
	Client    string       `json:"client"`
}

// readUsage aggregates settled spend since a time from the ledger files.
// Unparsable lines (e.g. a torn final line) are skipped.
func readUsage(dir, by string, since time.Time) (client.Usage, error) {
	out := client.Usage{By: by, Since: since, Rows: []client.UsageRow{}}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	// Only months that can contain records at or after since.
	firstMonth := since.AddDate(0, -1, 0).Format("2006-01")
	rows := map[string]*client.UsageRow{}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "ledger-") || !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		if month := strings.TrimSuffix(strings.TrimPrefix(name, "ledger-"), ".jsonl"); month < firstMonth {
			continue
		}
		if err := scanUsage(filepath.Join(dir, name), func(r usageRecord) {
			if r.TS.Before(since) {
				return
			}
			var key string
			switch by {
			case "pass":
				key = r.Pass
			case "provider":
				key = r.Provider
			case "process":
				key = r.Client
			default:
				key = r.Model
			}
			if key == "" {
				key = "(unknown)"
			}
			row := rows[key]
			if row == nil {
				row = &client.UsageRow{Key: key}
				rows[key] = row
			}
			row.Requests++
			row.Amount += r.Amount
			if r.Estimated {
				row.Estimated++
			}
			out.Total += r.Amount
		}); err != nil {
			return out, err
		}
	}
	for _, r := range rows {
		out.Rows = append(out.Rows, *r)
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Amount != out.Rows[j].Amount {
			return out.Rows[i].Amount > out.Rows[j].Amount
		}
		return out.Rows[i].Key < out.Rows[j].Key
	})
	return out, nil
}

func scanUsage(path string, fn func(usageRecord)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var r usageRecord
		if json.Unmarshal(sc.Bytes(), &r) != nil || r.Amount < 0 {
			continue
		}
		fn(r)
	}
	return sc.Err()
}
