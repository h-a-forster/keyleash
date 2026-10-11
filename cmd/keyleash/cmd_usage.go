package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/h-a-forster/keyleash/internal/audit"
	"github.com/h-a-forster/keyleash/internal/client"
	"github.com/h-a-forster/keyleash/internal/daemon"
)

// usageDimensions are the groupings `usage` can report.
var usageDimensions = []string{"pass", "model", "provider", "process"}

var cmdUsage = &command{
	name:    "usage",
	args:    "[--by pass|model|provider|process] [--since 7d|2026-10-01] [--json]",
	summary: "show spend grouped by pass, model, provider and process",
	help: `
Shows settled spend since the start of the month (or --since: a date, an
RFC 3339 time, or a duration back from now such as 7d). Without --by it
prints one table per grouping. "est." counts requests charged at their
reserved worst case because the real usage could not be read.`,
	run: runUsage,
}

func runUsage(ctx context.Context, a *app, args []string) error {
	fs := newFlagSet("usage")
	by := fs.String("by", "", "pass, model, provider or process (default: all)")
	since := fs.String("since", "", "start: date, RFC 3339 time or duration (default: start of month)")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, err := parseFlags(fs, args, true); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("usage", "unexpected argument")
	}
	dims := usageDimensions
	if *by != "" {
		d := strings.ToLower(*by)
		if !containsString(usageDimensions, d) {
			return usagef("usage", "--by must be pass, model, provider or process")
		}
		dims = []string{d}
	}
	t, err := parseSince(*since, time.Now())
	if err != nil {
		return usagef("usage", "%v", err)
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	var reports []client.Usage
	for _, d := range dims {
		u, err := c.Usage(cctx, d, t)
		if err != nil {
			return err
		}
		reports = append(reports, u)
	}
	if *asJSON {
		if len(reports) == 1 {
			return a.printJSON(reports[0])
		}
		return a.printJSON(reports)
	}
	for i, u := range reports {
		if i > 0 {
			fmt.Fprintln(a.stdout)
		}
		printUsage(a.stdout, u)
	}
	return nil
}

// printUsage prints one usage report, most expensive first.
func printUsage(w io.Writer, u client.Usage) {
	rows := append([]client.UsageRow(nil), u.Rows...)
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Amount != rows[j].Amount {
			return rows[i].Amount > rows[j].Amount
		}
		return rows[i].Key < rows[j].Key
	})
	fmt.Fprintf(w, "By %s since %s: %s\n", u.By, u.Since.Local().Format("2006-01-02 15:04"), u.Total)
	if len(rows) == 0 {
		fmt.Fprintln(w, "  (no requests)")
		return
	}
	tw := newTable(w)
	fmt.Fprintf(tw, "%s\tREQUESTS\tCOST\tEST.\n", strings.ToUpper(u.By))
	for _, r := range rows {
		key := r.Key
		if key == "" {
			key = "(unknown)"
		}
		if u.By == "process" {
			key = filepath.Base(strings.ReplaceAll(key, `\`, "/"))
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%d\n", key, r.Requests, r.Amount, r.Estimated)
	}
	tw.Flush()
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var cmdApprovals = &command{
	name:    "approvals",
	args:    "[list|approve <id> [--grant <amount> --for <duration>]|deny <id>] [--json]",
	summary: "list, approve or deny pending step-up requests",
	help: `
Step-up requests (unknown model, over-limit with on_exceed = "approve",
unattended grants, resume) wait up to approval.timeout for a decision.

  keyleash approvals                     list pending requests
  keyleash approvals approve <id> [--grant 10 --for 1h]
  keyleash approvals deny <id>

When approval.method is "hello", requests can only be approved with the
Windows Hello prompt; this command can still deny them. --grant attaches an
allowance so that one approval covers follow-up requests.`,
	run: runApprovals,
}

func runApprovals(ctx context.Context, a *app, args []string) error {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := newFlagSet("approvals")
	asJSON := fs.Bool("json", false, "print JSON")
	var grant moneyFlag
	var grantFor durationFlag
	fs.Var(&grant, "grant", "allowance attached to the approval")
	fs.Var(&grantFor, "for", "how long the allowance lasts")
	pos, err := parseFlags(fs, args, true)
	if err != nil {
		return err
	}
	c, err := a.client()
	if err != nil {
		return err
	}
	defer c.Close()
	cctx, cancel := withTimeout(ctx)
	defer cancel()
	switch sub {
	case "list", "ls":
		if len(pos) > 0 {
			return usagef("approvals", "unexpected argument")
		}
		list, err := c.Approvals(cctx)
		if err != nil {
			return err
		}
		if *asJSON {
			return a.printJSON(list)
		}
		if len(list) == 0 {
			fmt.Fprintln(a.stdout, "No pending approvals.")
			return nil
		}
		now := time.Now()
		tw := newTable(a.stdout)
		fmt.Fprintln(tw, "ID\tKIND\tAMOUNT\tPASS\tMODEL\tEXPIRES IN\tREQUEST")
		for _, ap := range list {
			amt := "-"
			if ap.Amount > 0 {
				amt = ap.Amount.String()
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", ap.ID, ap.Kind, amt, dash(ap.Pass), dash(ap.Model),
				fmtDuration(ap.Deadline.Sub(now)), oneLine(ap.Prompt))
		}
		return tw.Flush()
	case "approve", "deny":
		if len(pos) != 1 {
			return usagef("approvals", "%s takes exactly one approval id", sub)
		}
		req := client.DecideRequest{Approved: sub == "approve"}
		if grant.set != grantFor.set {
			return usagef("approvals", "--grant and --for go together")
		}
		if grant.set {
			if sub == "deny" {
				return usagef("approvals", "--grant only applies to approve")
			}
			req.Grant = &client.ApprovalGrant{Amount: grant.v, For: grantFor.v}
		}
		if err := c.Decide(cctx, pos[0], req); err != nil {
			if client.IsCode(err, client.CodeForbidden) {
				return errors.New("approval.method is hello: approve at the Windows Hello prompt (this command can only deny)")
			}
			return err
		}
		verb := map[bool]string{true: "Approved", false: "Denied"}[req.Approved]
		fmt.Fprintf(a.stdout, "%s %s.\n", verb, pos[0])
		return nil
	}
	return usagef("approvals", "unknown subcommand %q (want list, approve or deny)", sanitizeArg(sub))
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// oneLine flattens a prompt for a table cell.
func oneLine(s string) string { return oneLineN(s, 80) }

var cmdAudit = &command{
	name:    "audit",
	args:    "verify|tail [-n N] [--json]",
	summary: "verify the hash-chained audit log or show its tail",
	help: `
  keyleash audit verify   check the hash chain (and the keyed anchors when
                          unlocked); exits 1 if the log was tampered with.
                          Works offline (chain only) when the daemon is down.
  keyleash audit tail [-n 20]
                          show the latest records.`,
	run: runAudit,
}

func runAudit(ctx context.Context, a *app, args []string) error {
	if len(args) == 0 {
		return usagef("audit", "missing subcommand: verify or tail")
	}
	sub, args := args[0], args[1:]
	fs := newFlagSet("audit")
	asJSON := fs.Bool("json", false, "print JSON")
	n := fs.Int("n", 20, "number of records for tail")
	if pos, err := parseFlags(fs, args, true); err != nil {
		return err
	} else if len(pos) > 0 {
		return usagef("audit", "unexpected argument")
	}
	switch sub {
	case "verify":
		return a.auditVerify(ctx, *asJSON)
	case "tail":
		if *n < 1 {
			return usagef("audit", "-n must be positive")
		}
		c, err := a.client()
		if err != nil {
			return err
		}
		defer c.Close()
		cctx, cancel := withTimeout(ctx)
		defer cancel()
		recs, err := c.AuditTail(cctx, *n)
		if err != nil {
			return err
		}
		if *asJSON {
			return a.printJSON(recs)
		}
		now := time.Now()
		tw := newTable(a.stdout)
		fmt.Fprintln(tw, "SEQ\tTIME\tTYPE\tDETAILS")
		for _, r := range recs {
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\n", r.Seq, fmtTime(r.TS, now), r.Type, fmtFields(r.Fields))
		}
		return tw.Flush()
	}
	return usagef("audit", "unknown subcommand %q (want verify or tail)", sanitizeArg(sub))
}

// auditVerify verifies through the daemon (with anchors when unlocked), or
// offline (chain only) when the daemon is not running.
func (a *app) auditVerify(ctx context.Context, asJSON bool) error {
	var res client.AuditVerify
	offline := false
	c, err := a.client()
	if err == nil {
		defer c.Close()
		cctx, cancel := withTimeout(ctx)
		res, err = c.AuditVerify(cctx)
		cancel()
	}
	if err != nil {
		if friendly(err) != errDaemonDown {
			return err
		}
		dir, derr := a.dataDir()
		if derr != nil {
			return derr
		}
		rep, verr := audit.Verify(filepath.Join(dir, daemon.AuditDir), nil)
		res = client.AuditVerify{OK: verr == nil, Records: rep.Records, Files: rep.Files, Anchors: rep.Anchors}
		if rep.FirstBad != nil {
			res.Problem = rep.FirstBad.String()
		} else if verr != nil {
			res.Problem = verr.Error()
		}
		offline = true
	}
	if asJSON {
		if err := a.printJSON(res); err != nil {
			return err
		}
	} else {
		mode := "chain and anchors"
		if !res.KeyUsed {
			mode = "chain only (unlock to check the keyed anchors)"
		}
		if offline {
			mode = "chain only, offline (daemon not running)"
		}
		if res.OK {
			fmt.Fprintf(a.stdout, "Audit log OK: %d records in %d files, %d anchors (%d verified); checked %s.\n",
				res.Records, res.Files, res.Anchors, res.AnchorsVerified, mode)
		} else {
			fmt.Fprintf(a.stdout, "Audit log FAILED verification after %d good records: %s\n", res.Records, res.Problem)
		}
	}
	if !res.OK {
		return &exitCodeError{code: exitError}
	}
	return nil
}

// fmtFields renders audit fields as sorted key=value pairs.
func fmtFields(f map[string]any) string {
	keys := sortedKeys(f)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		var v string
		switch x := f[k].(type) {
		case string:
			v = x
			if strings.ContainsAny(v, " \t") {
				v = strconv.Quote(v)
			}
		case float64:
			v = strconv.FormatFloat(x, 'f', -1, 64)
		case nil:
			v = "null"
		default:
			v = fmt.Sprint(x)
		}
		parts = append(parts, k+"="+v)
	}
	return oneLineN(strings.Join(parts, " "), 160)
}

func oneLineN(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n-3] + "..."
	}
	return s
}
