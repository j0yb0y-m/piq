package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/review"
)

func testTime() time.Time {
	return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
}

func TestFormatInfo(t *testing.T) {
	pkg := aur.Package{Name: "paru", Version: "2.0.4-1", NumVotes: 100, Popularity: 1.5, Maintainer: "m", FirstSubmitted: 0}
	got := formatInfo(pkg, nil)
	for _, want := range []string{"paru", "2.0.4-1", "100", "unreviewed"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestFormatInfoShowsReviewDate(t *testing.T) {
	rec := &review.Record{ReviewedAt: testTime()}
	got := formatInfo(aur.Package{Name: "paru", Version: "1.0-1"}, rec)
	if !strings.Contains(got, "reviewed") || !strings.Contains(got, "2026-11-10") {
		t.Fatalf("got %q", got)
	}
}

func TestAuditLineFlagsOutdatedAndUnreviewed(t *testing.T) {
	got := auditLine("paru", "1.0-1", "2.0-1", nil)
	if !strings.Contains(got, "outdated") || !strings.Contains(got, "unreviewed") {
		t.Fatalf("got %q", got)
	}
}

func TestAuditLineCurrentAndReviewed(t *testing.T) {
	got := auditLine("paru", "2.0-1", "2.0-1", &review.Record{})
	if !strings.Contains(got, "current") || !strings.Contains(got, "reviewed") {
		t.Fatalf("got %q", got)
	}
	if strings.Contains(got, "outdated") || strings.Contains(got, "unreviewed") {
		t.Fatalf("wrong status in %q", got)
	}
}

func TestAuditLineMissingFromAUR(t *testing.T) {
	got := auditLine("local-only", "1.0-1", "", nil)
	if !strings.Contains(got, "not in AUR") {
		t.Fatalf("got %q", got)
	}
}

func TestCompletionProducesScript(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	var out, errb bytes.Buffer
	if code := execute([]string{"completion", "bash"}, &out, &errb); code != exitOK {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "piq") {
		t.Fatal("empty completion script")
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Fatal("ANSI in piped completion output")
	}
}

func TestCompletionUnknownShellIsUsageError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	var out, errb bytes.Buffer
	if code := execute([]string{"completion", "nushell"}, &out, &errb); code != exitUsage {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitUsage, errb.String())
	}
}

func TestVersionJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	var out, errb bytes.Buffer
	if code := execute([]string{"version", "--json"}, &out, &errb); code != exitOK {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out.String())
	}
	if got["schema_version"] != float64(1) || got["command"] != "version" {
		t.Fatalf("unexpected report: %v", got)
	}
	if got["version"] == "" || got["commit"] == "" || got["date"] == "" {
		t.Fatalf("missing build metadata: %v", got)
	}
}

func TestConfigJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	var out, errb bytes.Buffer
	if code := execute([]string{"config", "--json"}, &out, &errb); code != exitOK {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out.String())
	}
	if got["schema_version"] != float64(1) || got["command"] != "config" {
		t.Fatalf("unexpected report: %v", got)
	}
	if got["cache_path"] == "" || got["config_path"] == "" {
		t.Fatalf("missing paths: %v", got)
	}
	if got["severity"] != "warning" || got["threshold"] != float64(80) {
		t.Fatalf("unexpected defaults: %v", got)
	}
}

func TestRootHelpListsCommands(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)

	var out, errb bytes.Buffer
	if code := execute([]string{"--help"}, &out, &errb); code != exitOK {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	for _, name := range []string{"scan", "install", "info", "search", "audit", "config", "version", "completion"} {
		if !strings.Contains(out.String(), name) {
			t.Errorf("help missing %q", name)
		}
	}
	if strings.Contains(out.String(), "system") {
		t.Error("help still lists the removed system command")
	}
}
