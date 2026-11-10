package scanner

import (
	"strings"
	"testing"
	"time"

	"github.com/j0yb0y-m/piq/internal/history"
	"github.com/morganamilo/go-srcinfo"
)

func TestSrcinfoDivergenceExpandsVariables(t *testing.T) {
	src := `pkgname=paru
pkgver=2.0.4
source=("$pkgname-$pkgver.tar.gz::https://github.com/Morganamilo/paru/archive/v$pkgver.tar.gz")`
	meta := &srcinfo.Srcinfo{
		Pkgbase: "paru", Pkgver: "2.0.4", Pkgrel: "1",
		Source: []srcinfo.ArchString{{Value: "paru-2.0.4.tar.gz::https://github.com/Morganamilo/paru/archive/v2.0.4.tar.gz"}},
	}
	if f := findingsFor(srcinfoDivergenceRule{}.Check(parseContextWithMeta(t, src, meta)), "srcinfo-divergence"); len(f) != 0 {
		t.Fatalf("false positive: %v", f)
	}
}

func TestSrcinfoDivergenceSkipsUnresolvable(t *testing.T) {
	src := `source=("$unknownvar.tar.gz")`
	meta := &srcinfo.Srcinfo{
		Source: []srcinfo.ArchString{{Value: "$unknownvar.tar.gz"}},
	}
	if f := findingsFor(srcinfoDivergenceRule{}.Check(parseContextWithMeta(t, src, meta)), "srcinfo-divergence"); len(f) != 0 {
		t.Fatalf("unresolvable expansion flagged: %v", f)
	}
}

func TestSrcinfoDivergenceSkipsNonLiteralSource(t *testing.T) {
	src := `source=("$(curl https://e/x)")`
	meta := &srcinfo.Srcinfo{}
	if f := findingsFor(srcinfoDivergenceRule{}.Check(parseContextWithMeta(t, src, meta)), "srcinfo-divergence"); len(f) != 0 {
		t.Fatalf("non-literal source flagged: %v", f)
	}
}

func TestSrcinfoDivergenceRealMismatch(t *testing.T) {
	src := `source=(https://evil/x.tar.gz)`
	meta := &srcinfo.Srcinfo{
		Source: []srcinfo.ArchString{{Value: "https://good/x.tar.gz"}},
	}
	f := findingsFor(srcinfoDivergenceRule{}.Check(parseContextWithMeta(t, src, meta)), "srcinfo-divergence")
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(f), f)
	}
	if f[0].Severity != Critical {
		t.Errorf("severity = %v, want Critical", f[0].Severity)
	}
	if got := (srcinfoDivergenceRule{}).Points(); got != 95 {
		t.Errorf("points = %d, want 95", got)
	}
}

func TestExpandPkgVarsEpochEmpty(t *testing.T) {
	meta := &srcinfo.Srcinfo{Pkgbase: "foo", Pkgver: "1.2.3", Pkgrel: "2"}
	got, ok := expandPkgVars("$epoch:$pkgver-${pkgrel}", meta)
	if !ok {
		t.Fatal("expected expansion to resolve")
	}
	if got != ":1.2.3-2" {
		t.Errorf("expanded = %q, want %q", got, ":1.2.3-2")
	}
	if _, ok := expandPkgVars("$missing", meta); ok {
		t.Error("expected unresolved variable to fail")
	}
}

func TestChecksumCompletenessMentionsSkip(t *testing.T) {
	meta := &srcinfo.Srcinfo{
		Source:     []srcinfo.ArchString{{Value: "https://example.com/file.tar.gz"}},
		SHA256Sums: []srcinfo.ArchString{{Value: "SKIP"}},
	}
	f := findingsFor(checksumCompletenessRule{}.Check(&Context{Metadata: meta}), "checksum-completeness")
	if len(f) != 1 {
		t.Fatalf("got %d findings, want 1: %v", len(f), f)
	}
	if !strings.Contains(f[0].Message, "SKIP") {
		t.Errorf("message does not mention SKIP: %s", f[0].Message)
	}
	if !strings.Contains(f[0].Message, "VCS") {
		t.Errorf("message does not explain the VCS exception: %s", f[0].Message)
	}
}

func TestParuFixtureHasNoConsistencyOrProvenanceFindings(t *testing.T) {
	ctx := parseFixturePair(t, "testdata/benign/paru.PKGBUILD", "testdata/benign/paru.SRCINFO")
	ctx.History = &history.Provenance{
		HeadCommitter: "a@x", PreviousCommitter: "a@x", Maintainer: "a@x",
		CommitCount: 200, Committers: map[string]int{"a@x": 200},
		HeadCommittedAt: time.Now(),
	}
	for _, rule := range []string{"srcinfo-divergence", "undeclared-fetch", "maintainer-change", "maintainer-drift"} {
		if f := findingsFor(ScoreWith(ctx, Options{}).Findings, rule); len(f) != 0 {
			t.Errorf("%s: %v", rule, f)
		}
	}
}
