// Package approval implements step-up approval (spec §9): a queue that holds
// requests open while an approver (Windows Hello, console, or deny) or an
// external decision through the admin API answers, with coalescing of
// identical pending requests and a timeout.
package approval

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/h-a-forster/keyleash/internal/money"
)

// Request describes what needs approving. CoalesceKey groups identical
// requests (e.g. pass id + reason): while one is pending, later requests with
// the same non-empty key wait for the same decision instead of prompting
// again.
type Request struct {
	Kind, Title, Detail, PassID, Model string
	Amount                             money.Micros
	CoalesceKey                        string
}

// Grant is an allowance attached to an approval (e.g. "+$10 for 1 h") so one
// approval does not become a prompt storm. Applying it is the caller's job.
type Grant struct {
	Amount money.Micros
	For    time.Duration
}

// Decision is the outcome of a request. Method says who decided: the
// approver's method name ("hello", "console", "deny", or "approver" for
// approvers without a name), "external" (Decide), "timeout" or "cancelled".
type Decision struct {
	Approved bool
	Grant    *Grant
	Method   string
	ID       string
}

// Approver asks someone to approve a request. It must honour ctx
// cancellation: the queue cancels it when an external decision or the
// timeout wins.
type Approver interface {
	Approve(ctx context.Context, req Request) (bool, error)
}

// Confirmer performs a user-presence confirmation such as a Windows Hello
// prompt. A nil error means the user confirmed; any error means not
// confirmed.
type Confirmer interface {
	Confirm(ctx context.Context, prompt string) error
}

// Errors.
var (
	ErrTimeout  = errors.New("approval: timed out")
	ErrNotFound = errors.New("approval: no such pending request")
	ErrApprover = errors.New("approval: approver failed")
)

// methodNamer is optionally implemented by approvers to name themselves in
// Decision.Method.
type methodNamer interface{ Method() string }

func methodOf(a Approver) string {
	if m, ok := a.(methodNamer); ok {
		return m.Method()
	}
	return "approver"
}

// --- prompt text --------------------------------------------------------

const (
	maxFieldRunes  = 120
	maxPromptRunes = 300
)

// clean makes untrusted text safe to show in a prompt: control, format
// (bidi overrides, zero-width) and invalid characters are dropped, runs of
// whitespace collapse to one space, and the result is capped at max runes.
func clean(s string, max int) string {
	var b strings.Builder
	space := false
	n := 0
	for _, r := range s {
		if n > max {
			break // enough to know it will be truncated
		}
		switch {
		case r == utf8.RuneError:
		case unicode.IsSpace(r):
			space = b.Len() > 0
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || !unicode.IsPrint(r):
		default:
			if space {
				b.WriteByte(' ')
				space = false
				n++
			}
			b.WriteRune(r)
			n++
		}
	}
	rs := []rune(b.String())
	if len(rs) > max {
		return string(rs[:max-1]) + "…"
	}
	return string(rs)
}

// PromptText builds the short, sanitised prompt shown to the user for req.
func PromptText(req Request) string {
	parts := make([]string, 0, 5)
	title := clean(req.Title, maxFieldRunes)
	if title == "" {
		title = clean(req.Kind, maxFieldRunes)
	}
	if title == "" {
		title = "keyleash approval"
	}
	parts = append(parts, title)
	if d := clean(req.Detail, maxFieldRunes); d != "" {
		parts = append(parts, d)
	}
	if req.Amount > 0 {
		parts = append(parts, req.Amount.String())
	}
	if m := clean(req.Model, 64); m != "" {
		parts = append(parts, "model "+m)
	}
	if p := clean(req.PassID, 32); p != "" {
		parts = append(parts, "pass "+p)
	}
	return clean(strings.Join(parts, " · "), maxPromptRunes)
}

// --- approvers ----------------------------------------------------------

// HelloApprover approves when c confirms (e.g. a Windows Hello prompt whose
// text describes the request). A failed confirmation is a denial, not an
// error; only ctx cancellation is returned as an error.
func HelloApprover(c Confirmer) Approver { return helloApprover{c} }

type helloApprover struct{ c Confirmer }

func (h helloApprover) Method() string { return "hello" }

func (h helloApprover) Approve(ctx context.Context, req Request) (bool, error) {
	if h.c == nil {
		return false, errors.New("approval: no confirmer")
	}
	if err := h.c.Confirm(ctx, PromptText(req)); err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		return false, nil
	}
	return true, nil
}

// DenyApprover denies everything (CI, servers).
type DenyApprover struct{}

// Method implements the optional method name.
func (DenyApprover) Method() string { return "deny" }

// Approve always returns false.
func (DenyApprover) Approve(context.Context, Request) (bool, error) { return false, nil }

// ConsoleApprover prompts on out and reads a y/N answer from in (development
// and headless use). Prompts are serialised. Only "y" or "yes"
// (case-insensitive) approves; anything else, EOF or a read error denies.
// Answers typed between prompts are discarded before the next prompt, so a
// late "y" cannot approve the next request.
//
// in is read by one background goroutine that lives until in reaches EOF.
func ConsoleApprover(in io.Reader, out io.Writer) Approver {
	return &consoleApprover{in: in, out: out}
}

type consoleApprover struct {
	in    io.Reader
	out   io.Writer
	mu    sync.Mutex // serialises prompts
	once  sync.Once
	lines chan string
	// prompted is set once the first prompt has been shown (guarded by mu).
	prompted bool
}

func (c *consoleApprover) Method() string { return "console" }

const maxAnswerLen = 256

func (c *consoleApprover) start() {
	c.lines = make(chan string, 1)
	go func() {
		defer close(c.lines)
		r := bufio.NewReaderSize(c.in, 1024)
		for {
			var line []byte
			for {
				frag, err := r.ReadSlice('\n')
				if len(line) < maxAnswerLen {
					line = append(line, frag...)
				}
				if err == bufio.ErrBufferFull {
					continue
				}
				if err != nil {
					if len(line) > 0 {
						c.lines <- string(line)
					}
					return
				}
				break
			}
			c.lines <- string(line)
		}
	}()
}

func (c *consoleApprover) Approve(ctx context.Context, req Request) (bool, error) {
	c.once.Do(c.start)
	c.mu.Lock()
	defer c.mu.Unlock()
	// Drop stale answers typed after the previous prompt closed. Input that
	// precedes the very first prompt is kept so piped answers still work.
	for drained := !c.prompted; !drained; {
		select {
		case _, ok := <-c.lines:
			if !ok {
				return false, nil // input closed: deny
			}
		default:
			drained = true
		}
	}
	c.prompted = true
	if _, err := fmt.Fprintf(c.out, "\nkeyleash approval: %s\nApprove? [y/N]: ", PromptText(req)); err != nil {
		return false, fmt.Errorf("approval: console write: %w", err)
	}
	select {
	case <-ctx.Done():
		_, _ = fmt.Fprintln(c.out, "\n(approval request closed)")
		return false, ctx.Err()
	case line, ok := <-c.lines:
		if !ok {
			return false, nil
		}
		ans := strings.ToLower(strings.TrimSpace(line))
		return ans == "y" || ans == "yes", nil
	}
}
