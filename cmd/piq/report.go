package main

import (
	"time"

	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/pipeline"
	"github.com/j0yb0y-m/piq/internal/report"
)

// scanReport builds the JSON report for the scan command.
func scanReport(res *pipeline.Result) report.Scan {
	return scanReportFor(res, "scan")
}

// scanReportFor builds the JSON report for a command that scans a package.
// Commands keep their own identity while sharing the same shape.
func scanReportFor(res *pipeline.Result, command string) report.Scan {
	r := report.Scan{
		SchemaVersion: report.SchemaVersion,
		Command:       command,
		Findings:      []report.Finding{},
		GeneratedAt:   time.Now().UTC(),
	}
	if res == nil {
		return r
	}
	r.Package = res.Pkgbase
	if res.Score != nil {
		r.Verdict = res.Score.Verdict.String()
		r.Score = res.Score.Total
		r.Blocked = res.Score.Blocked
		r.BlockReason = res.Score.BlockReason
		for _, f := range res.Score.Findings {
			r.Findings = append(r.Findings, report.Finding{
				Rule:     f.Rule,
				Severity: f.Severity.String(),
				File:     f.File,
				Line:     f.Line,
				Message:  f.Message,
			})
		}
	}
	if res.Provenance != nil {
		r.Provenance = &report.Provenance{
			CommitCount:     res.Provenance.CommitCount,
			Maintainer:      res.Provenance.Maintainer,
			HeadCommitter:   res.Provenance.HeadCommitter,
			HeadCommittedAt: res.Provenance.HeadCommittedAt,
		}
	}
	return r
}

// searchReport builds the JSON report for search results.
func searchReport(results []aur.Package) report.Search {
	r := report.Search{
		SchemaVersion: report.SchemaVersion,
		Command:       "search",
		Results:       []report.PackageSummary{},
	}
	for _, p := range results {
		r.Results = append(r.Results, report.PackageSummary{
			Name:        p.Name,
			Version:     p.Version,
			Description: p.Description,
			Votes:       p.NumVotes,
		})
	}
	return r
}
