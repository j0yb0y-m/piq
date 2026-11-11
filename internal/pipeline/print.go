package pipeline

import (
	"fmt"
	"io"
	"strings"

	"github.com/j0yb0y-m/piq/internal/scanner"
	"github.com/j0yb0y-m/piq/internal/ui"
)

// PrintFindings renders a scored result grouped by finding, followed by
// the verdict line. Callers choose the writer so JSON mode can keep
// stdout clean.
func PrintFindings(w io.Writer, res *Result) {
	if res == nil || res.Score == nil {
		return
	}
	score := res.Score
	verdict := verdictStyle(score.Verdict)
	fmt.Fprintf(w, "\n%s — verdict %s, risk score %d, %d findings\n",
		ui.Notice(res.Pkgbase), verdict(score.Verdict.String()), score.Total, len(score.Findings))
	fmt.Fprintln(w, ui.Muted(strings.Repeat("-", 60)))
	for _, f := range score.Findings {
		style := severityStyle(f.Severity)
		where := "PKGBUILD"
		if f.File != "" {
			where = f.File
		}
		fmt.Fprintf(w, "  %s %s\n", style(fmt.Sprintf("[%s]", f.Severity)), f.Message)
		if f.Line > 0 {
			fmt.Fprintf(w, "    %s\n", ui.Muted(fmt.Sprintf("→ %s:%d (%s)", where, f.Line, f.Rule)))
		} else {
			fmt.Fprintf(w, "    %s\n", ui.Muted(fmt.Sprintf("→ %s (%s)", where, f.Rule)))
		}
	}
}

func severityStyle(s scanner.Severity) func(string) string {
	switch s {
	case scanner.Critical:
		return ui.Critical
	case scanner.Warning:
		return ui.Warning
	default:
		return plain
	}
}

func verdictStyle(v scanner.Verdict) func(string) string {
	switch v {
	case scanner.Malicious, scanner.Suspicious:
		return ui.Critical
	case scanner.Sketchy:
		return ui.Warning
	case scanner.OK, scanner.Trusted:
		return ui.Success
	default:
		return plain
	}
}

func plain(s string) string { return s }
