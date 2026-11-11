package main

import (
	"testing"
	"time"

	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/history"
	"github.com/j0yb0y-m/piq/internal/pipeline"
	"github.com/j0yb0y-m/piq/internal/report"
	"github.com/j0yb0y-m/piq/internal/scanner"
)

func TestScanReportIncludesBlockReason(t *testing.T) {
	res := &pipeline.Result{Pkgbase: "x", Score: &scanner.Score{Verdict: scanner.Suspicious, Total: 90, Blocked: true, BlockReason: "score 90 >= threshold 80"}}
	r := scanReport(res)
	if !r.Blocked || r.BlockReason == "" || r.Package != "x" {
		t.Fatalf("%+v", r)
	}
}

func TestScanReportMapsFindingsAndProvenance(t *testing.T) {
	committed := time.Date(2024, 5, 1, 12, 30, 0, 0, time.FixedZone("UTC+2", 2*60*60))
	res := &pipeline.Result{
		Pkgbase: "demo",
		Score: &scanner.Score{
			Verdict:     scanner.Suspicious,
			Total:       80,
			Blocked:     true,
			BlockReason: "score 80 >= threshold 80",
			Findings: []scanner.Finding{{
				Rule:     "pipe-to-shell",
				Severity: scanner.Critical,
				File:     "PKGBUILD",
				Line:     12,
				Message:  "pipes a download into a shell",
			}},
		},
		Provenance: &history.Provenance{
			CommitCount:     7,
			Maintainer:      "maint@example.com",
			HeadCommitter:   "head@example.com",
			HeadCommittedAt: committed,
		},
	}

	r := scanReport(res)
	if r.SchemaVersion != report.SchemaVersion {
		t.Fatalf("schema_version = %d", r.SchemaVersion)
	}
	if r.Command != "scan" || r.Package != "demo" {
		t.Fatalf("command/package = %q/%q", r.Command, r.Package)
	}
	if r.Verdict != "SUSPICIOUS" || r.Score != 80 || !r.Blocked {
		t.Fatalf("verdict/score/blocked = %q/%d/%v", r.Verdict, r.Score, r.Blocked)
	}
	if r.BlockReason != "score 80 >= threshold 80" {
		t.Fatalf("block_reason = %q", r.BlockReason)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("findings = %v", r.Findings)
	}
	f := r.Findings[0]
	if f.Rule != "pipe-to-shell" || f.Severity != "CRITICAL" || f.File != "PKGBUILD" || f.Line != 12 || f.Message != "pipes a download into a shell" {
		t.Fatalf("finding = %+v", f)
	}
	if r.Provenance == nil {
		t.Fatal("provenance is nil")
	}
	if r.Provenance.CommitCount != 7 || r.Provenance.Maintainer != "maint@example.com" || r.Provenance.HeadCommitter != "head@example.com" {
		t.Fatalf("provenance = %+v", r.Provenance)
	}
	if !r.Provenance.HeadCommittedAt.Equal(committed) {
		t.Fatalf("head_committed_at = %v", r.Provenance.HeadCommittedAt)
	}
	if r.Provenance.HeadCommittedAt.Location() != time.UTC {
		t.Fatalf("head_committed_at is not UTC: %v", r.Provenance.HeadCommittedAt)
	}
	if r.GeneratedAt.IsZero() || r.GeneratedAt.Location() != time.UTC {
		t.Fatalf("generated_at = %v", r.GeneratedAt)
	}
}

func TestSearchReportMapsResultsAndEmptySlice(t *testing.T) {
	r := searchReport([]aur.Package{{
		Name:        "paru",
		Version:     "2.0.0",
		Description: "AUR helper",
		NumVotes:    123,
	}})
	if r.SchemaVersion != report.SchemaVersion || r.Command != "search" {
		t.Fatalf("schema/command = %d/%q", r.SchemaVersion, r.Command)
	}
	if len(r.Results) != 1 {
		t.Fatalf("results = %v", r.Results)
	}
	got := r.Results[0]
	if got.Name != "paru" || got.Version != "2.0.0" || got.Description != "AUR helper" || got.Votes != 123 {
		t.Fatalf("result = %+v", got)
	}

	empty := searchReport(nil)
	if empty.Results == nil {
		t.Fatal("empty results slice is nil")
	}
	if len(empty.Results) != 0 {
		t.Fatalf("empty results = %v", empty.Results)
	}
}

func TestScanReportNilScore(t *testing.T) {
	r := scanReport(&pipeline.Result{Pkgbase: "x"})
	if r.Package != "x" || r.Findings == nil || len(r.Findings) != 0 {
		t.Fatalf("%+v", r)
	}
	if r.Command != "scan" {
		t.Fatalf("command = %q", r.Command)
	}
}

func TestScanReportForInstallCommand(t *testing.T) {
	res := &pipeline.Result{Pkgbase: "x", Score: &scanner.Score{Verdict: scanner.Malicious, Total: 100, Blocked: true}}
	r := scanReportFor(res, "install")
	if r.Command != "install" {
		t.Fatalf("command = %q", r.Command)
	}
	if !r.Blocked || r.Score != 100 {
		t.Fatalf("%+v", r)
	}
}
