package scanner

import (
	"strings"
	"testing"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
)

func TestSplitPackageDetection(t *testing.T) {
	src := `pkgname=(foo bar)
pkgver=1.0
package_foo() {
  install -Dm644 foo.txt "$pkgdir/usr/share/foo.txt"
}`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	findings := splitPackageRule{}.Check(ctx)
	// foo has package_foo(), bar has no package_bar() — should find 1
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding (missing package_bar), got %d", len(findings))
	}
}

func TestSplitPackageAllCovered(t *testing.T) {
	src := `pkgname=(foo bar)
package_foo() { true; }
package_bar() { true; }`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	findings := findingsFor(splitPackageRule{}.Check(ctx), "split-package-missing")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(findings))
	}
}

func TestSinglePackageNoFinding(t *testing.T) {
	src := `pkgname=hello
pkgver=1.0`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	findings := findingsFor(splitPackageRule{}.Check(ctx), "split-package-missing")
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for single package, got %d", len(findings))
	}
}
