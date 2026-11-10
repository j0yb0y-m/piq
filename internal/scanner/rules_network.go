package scanner

import (
	"regexp"
	"strings"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(undeclaredFetchRule{})
	Register(insecureURLRule{})
}

type undeclaredFetchRule struct{}

func (undeclaredFetchRule) Name() string { return "undeclared-fetch" }

func (undeclaredFetchRule) Points() int { return 50 }

func (undeclaredFetchRule) Gate() bool { return false }

var fetchCommands = map[string]bool{
	"npm": true, "npx": true, "pip": true, "pip3": true,
	"cargo": true, "go": true, "gem": true, "yarn": true, "pnpm": true, "bun": true,
}

func (undeclaredFetchRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, _ string) []Finding {
		var findings []Finding
		syntax.Walk(file, func(n syntax.Node) bool {
			call, ok := n.(*syntax.CallExpr)
			if !ok {
				return true
			}
			name := pkgbuild.CommandName(call)
			if !fetchCommands[name] {
				return true
			}
			if !fetchingSubcommand(call.Args) {
				return true
			}
			rendered := pkgbuild.Render(call)
			findings = append(findings, Finding{
				Rule:     "undeclared-fetch",
				Severity: Warning,
				Line:     lineOf(n),
				Message:  "In " + fname + ": runs `" + name + "` in a way that fetches new packages at build time (`" + rendered + "`), outside the checksummed `source=()` array. The June 2026 Atomic Arch campaign used exactly this pattern (`npm install atomic-lockfile` / `bun install js-digest`). Prefer vendoring or a proper checksummed `source=` entry.",
			})
			return true
		})
		return findings
	})
}

// fetchingSubcommand reports whether a package-manager call installs or
// downloads new packages at build time. Locked fetches (cargo fetch,
// go mod download, npm ci, ...) only materialise dependencies already
// pinned by a lockfile in the checksummed source tree, so they are not
// evidence of an undeclared network fetch.
func fetchingSubcommand(args []*syntax.Word) bool {
	if len(args) < 2 {
		return false
	}
	switch pkgbuild.WordText(args[1]) {
	case "fetch", "download", "ci":
		return false
	case "mod":
		return false // go mod download: locked dependency fetch
	case "install", "add", "i", "get":
		return true
	default:
		return false
	}
}

type insecureURLRule struct{}

func (insecureURLRule) Name() string { return "insecure-source-url" }

func (insecureURLRule) Points() int { return 50 }

func (insecureURLRule) Gate() bool { return false }

var suspiciousHost = regexp.MustCompile(`(?i)(pastebin\.com/raw|hastebin|ghostbin|bit\.ly|tinyurl\.com|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)

func (insecureURLRule) Check(ctx *Context) []Finding {
	meta := ctx.Metadata
	if meta == nil {
		return nil
	}
	var findings []Finding
	for _, src := range meta.Source {
		val := src.Value
		if strings.HasPrefix(val, "http://") {
			findings = append(findings, Finding{
				Rule:     "insecure-source-url",
				Severity: Warning,
				Message:  "Source fetched over plain HTTP, not HTTPS: " + val + ". A checksum mitigates tampering but doesn't stop a MITM from serving something else silently.",
			})
		}
		if suspiciousHost.MatchString(val) {
			findings = append(findings, Finding{
				Rule:     "insecure-source-url",
				Severity: Critical,
				Message:  "Source URL points at a paste site, URL shortener, or bare IP address: " + val + ". Legitimate upstream releases essentially never ship this way — a strong signal of a hastily-set-up payload host.",
			})
		}
	}
	return findings
}
