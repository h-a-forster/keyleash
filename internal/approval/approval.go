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
	"strconv"
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
// again. Callers must only coalesce requests whose approval means exactly
// the same thing for every waiter (the daemon never coalesces admin
// step-ups, spec §9).
type Request struct {
	// Kind and Title name the request. Detail is the risk-relevant text
	// (limits, amounts, bindings, ...): it is always shown in full, and a
	// request whose prompt could not show it in full is refused (see Fits).
	// Note is optional explanatory text that may be shortened.
	Kind, Title, Detail, Note, PassID, Model string
	Amount                                   money.Micros
	CoalesceKey                              string
	// Requester is the verified PID of the admin-channel caller whose call
	// triggered the request (0 for proxy requests or when unknown). It lets
	// a CLI recognise the approval its own call is waiting for.
	Requester int
	// RequesterName is the requesting process's image name; with Requester
	// it is shown in the prompt ("by agent.exe pid 1234").
	RequesterName string
	// Scope, Window and Limit describe the exceeded limit of an over_limit
	// request; Limit bounds the grant an approval may carry.
	Scope, Window string
	Limit         money.Micros
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
	maxDetailRunes = 200
	// maxPromptRunes is the whole prompt. It must not exceed what the
	// Windows Hello dialog shows (winhello caps its text at 200 runes).
	maxPromptRunes = 200
)

// ErrPromptTooLong is returned by Fits when the risk-relevant part of a
// prompt would be truncated.
var ErrPromptTooLong = errors.New("approval: the request is too long to show in full in an approval prompt")

// clean makes untrusted text safe to show in a prompt: control, format
// (bidi overrides, zero-width) and invalid characters are dropped, runs of
// whitespace collapse to one space, and the result is capped at max runes.
func clean(s string, max int) string {
	c, _ := cleanFit(s, max)
	return c
}

// cleanFit is clean that also reports whether s fitted without truncation.
func cleanFit(s string, max int) (string, bool) {
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
		return string(rs[:max-1]) + "…", false
	}
	return string(rs), true
}

const promptSep = " · "

// buildPrompt renders req: the risk-relevant parts first (title, requester,
// detail, amount, model, pass), then the optional note in whatever room is
// left. fits is false when a risk-relevant part had to be shortened.
func buildPrompt(req Request) (text string, fits bool) {
	fits = true
	add := func(parts []string, s string, max int) []string {
		c, ok := cleanFit(s, max)
		fits = fits && ok
		if c == "" {
			return parts
		}
		return append(parts, c)
	}
	parts := make([]string, 0, 7)
	title, ok := cleanFit(req.Title, maxFieldRunes)
	fits = fits && ok
	if title == "" {
		title = clean(req.Kind, maxFieldRunes)
	}
	if title == "" {
		title = "keyleash approval"
	}
	parts = append(parts, title)
	if req.Requester > 0 {
		name := clean(req.RequesterName, 48)
		if name == "" {
			name = "process"
		}
		parts = append(parts, "by "+name+" pid "+strconv.Itoa(req.Requester))
	}
	parts = add(parts, req.Detail, maxDetailRunes)
	if req.Amount > 0 {
		parts = append(parts, req.Amount.String())
	}
	if req.Model != "" {
		parts = add(parts, "model "+req.Model, 72)
	}
	if req.PassID != "" {
		parts = add(parts, "pass "+req.PassID, 40)
	}
	head := strings.Join(parts, promptSep)
	if utf8.RuneCountInString(head) > maxPromptRunes {
		return clean(head, maxPromptRunes), false
	}
	if room := maxPromptRunes - utf8.RuneCountInString(head) - utf8.RuneCountInString(promptSep); room >= 8 {
		if note := clean(req.Note, room); note != "" {
			head += promptSep + note
		}
	}
	return head, fits
}

// PromptText builds the short, sanitised prompt shown to the user for req.
// It never exceeds maxPromptRunes; use Fits to make sure nothing
// risk-relevant was cut.
func PromptText(req Request) string {
	s, _ := buildPrompt(req)
	return s
}

// Fits reports ErrPromptTooLong when the prompt for req could not show its
// title, requester, detail, amount, model and pass in full. Callers refuse
// such requests instead of asking the owner to approve text they cannot
// see.
func Fits(req Request) error {
	if _, ok := buildPrompt(req); !ok {
		return ErrPromptTooLong
	}
	return nil
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

// PassphraseApprover never decides on its own: requests wait for an
// external decision (the daemon's admin API, which requires re-entering a
// vault secret, spec §9) or the timeout.
func PassphraseApprover() Approver { return waitApprover{} }

type waitApprover struct{}

func (waitApprover) Method() string { return "passphrase" }

func (waitApprover) Approve(ctx context.Context, _ Request) (bool, error) {
	<-ctx.Done()
	return false, ctx.Err()
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
