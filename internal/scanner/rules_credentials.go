package scanner

import (
	"strings"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(credentialRule{})
	Register(exfilRule{})
}

// credentialRule flags code that attempts to read or exfiltrate
// credentials, SSH keys, browser cookies, environment secrets, or
// cryptocurrency wallets.
type credentialRule struct{}

func (credentialRule) Name() string { return "credential-theft" }

func (credentialRule) Points() int { return 100 }

func (credentialRule) Gate() bool { return true }

var credentialPatterns = []string{
	"$HOME/.ssh", "~/.ssh", "id_rsa", "id_ed25519", "known_hosts",
	".aws/credentials", "~/.aws", ".kube/config", "~/.kube",
	"cookie.db", "~/Library/Application Support",
	"wallet.dat", "keystore", "seedphrase", "mnemonic",
	"~/.gnupg", "$HOME/.gnupg", "secret", "token",
	".npmrc", "~/.netrc", "passwd", "shadow",
}

func (credentialRule) Check(ctx *Context) []Finding {
	// Regex match is unreliable for shell text; use substring matching
	// but only when the context also implies reading/copying/uploading.
	lower := strings.ToLower(ctx.Raw)
	for _, s := range ctx.Scriptlets {
		lower += "\n" + strings.ToLower(s.Raw)
	}

	var findings []Finding
	already := map[string]bool{}
	for _, pat := range credentialPatterns {
		if !strings.Contains(lower, pat) {
			continue
		}
		if already[pat] {
			continue
		}
		already[pat] = true
		findings = append(findings, Finding{
			Rule:     "credential-theft",
			Severity: Critical,
			Message:  "Package content references a credential or wallet path: `" + pat + "`. Malware that steals SSH keys, cloud credentials, cookies, or crypto wallets uses exactly these paths.",
		})
	}
	return findings
}

// exfilRule flags a network-transfer of locally-sourced data (not a
// declared source download): piping local files or command output
// into curl/wget/nc.
type exfilRule struct{}

func (exfilRule) Name() string { return "data-exfiltration" }

func (exfilRule) Points() int { return 100 }

func (exfilRule) Gate() bool { return true }

var exfilCommands = map[string]bool{"curl": true, "wget": true, "nc": true, "ncat": true, "socat": true}

func (exfilRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, _ string) []Finding {
		var findings []Finding
		syntax.Walk(file, func(n syntax.Node) bool {
			bc, ok := n.(*syntax.BinaryCmd)
			if !ok {
				return true
			}
			if bc.Op != syntax.Pipe && bc.Op != syntax.PipeAll {
				return true
			}
			right := strings.ToLower(pkgbuild.Render(bc.Y))
			left := strings.ToLower(pkgbuild.Render(bc.X))
			uploads := exfilCommands[commandWord(right)]
			localData := strings.Contains(left, "~") || strings.Contains(left, "$HOME") ||
				strings.Contains(left, "/etc") || strings.Contains(left, "find ") ||
				strings.HasPrefix(strings.TrimSpace(left), "cat ")
			if uploads && localData {
				findings = append(findings, Finding{
					Rule:     "data-exfiltration",
					Severity: Critical,
					File:     fname,
					Message:  "Pipes local/system data (`" + trimExcerpt(left) + "`) into `" + trimExcerpt(right) + "`. Uploading local files to a remote endpoint is data exfiltration — there is no legitimate reason for a package to do this.",
				})
			}
			return true
		})
		return findings
	})
}

// commandWord extracts the first word of a rendered command line.
func commandWord(s string) string {
	s = strings.TrimSpace(s)
	// strip leading redirects/assignments
	fields := strings.Fields(s)
	for _, f := range fields {
		if strings.HasPrefix(f, "<") || strings.HasPrefix(f, ">") {
			continue
		}
		if strings.Contains(f, "=") {
			continue
		}
		if f == "2>&1" || f == "&" || f == "|" {
			continue
		}
		name := strings.ToLower(f)
		// keep just the command name
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		return name
	}
	return ""
}
