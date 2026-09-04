package scanner

import (
	"regexp"
	"strings"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(knownCampaignRule{})
	Register(reverseShellRule{})
	Register(obfuscationRule{})
}

// knownCampaignRule flags hard indicators-of-compromise from real,
// documented AUR supply-chain attacks. Each entry is a short filename
// or package-name fragment that, if referenced from a PKGBUILD or
// scriptlet, marks the project as matching a known campaign.
type knownCampaignRule struct{}

func (knownCampaignRule) Name() string { return "known-campaign" }

func (knownCampaignRule) Points() int { return 100 }

func (knownCampaignRule) Gate() bool { return true }

var campaignIOCs = []string{
	// June 2026 Atomic Arch campaign — empty packages with install
	// hooks pointing at an "atomic-lockfile" / "js-digest" dep chain.
	"atomic-lockfile",
	"js-digest",
	"chausson_banane",
	"chausson-banane",
	// xsnow worm / XZ-utils backdoor particulars.
	"liblzma-dev-unstable",
	"liblzma-unstable",
}

func (knownCampaignRule) Check(ctx *Context) []Finding {
	blob := strings.ToLower(ctx.Raw)
	for _, s := range ctx.Scriptlets {
		blob += "\n" + strings.ToLower(s.Raw)
	}
	blob += "\n" + strings.ToLower(metaInstall(ctx))
	var findings []Finding
	for _, ioc := range campaignIOCs {
		if strings.Contains(blob, ioc) {
			findings = append(findings, Finding{
				Rule:     "known-campaign",
				Severity: Critical,
				Message:  "Package text references `" + ioc + "`, an indicator of compromise from a documented AUR supply-chain campaign. This is unambiguous — do not install.",
			})
		}
	}
	return findings
}

func metaInstall(ctx *Context) string {
	if ctx.Metadata != nil {
		return ctx.Metadata.Install
	}
	return ""
}

// reverseShellRule detects the classic reverse-shell one-liners: a
// TCP/UDP connection fed into a shell, or bash -i /dev/tcp patterns.
type reverseShellRule struct{}

func (reverseShellRule) Name() string { return "reverse-shell" }

func (reverseShellRule) Points() int { return 100 }

func (reverseShellRule) Gate() bool { return true }

var reverseShellRe = regexp.MustCompile(`(?i)(bash|sh|zsh)\b[^\n]*(/dev/tcp|/dev/udp)|\b(bash|sh|zsh)\b[^\n]*-[^\n]*(connect|nc)\b`)

var connectCmds = map[string]bool{"nc": true, "ncat": true, "netcat": true, "socat": true, "telnet": true}

func (reverseShellRule) Check(ctx *Context) []Finding {
	var findings []Finding
	appendFind := ctx.ForEachFile(func(file *syntax.File, fname, raw string) []Finding {
		var fs []Finding
		if reverseShellRe.MatchString(raw) {
			fs = append(fs, Finding{
				Rule:     "reverse-shell",
				Severity: Critical,
				File:     fname,
				Message:  "Pattern matches a reverse shell (`" + trimExcerpt(raw) + "`). This opens an outbound shell to an external host — unambiguous malice.",
			})
			return fs
		}
		syntax.Walk(file, func(n syntax.Node) bool {
			call, ok := n.(*syntax.CallExpr)
			if !ok {
				return true
			}
			if !connectCmds[pkgbuild.CommandName(call)] {
				return true
			}
			fs = append(fs, Finding{
				Rule:     "reverse-shell",
				Severity: Critical,
				File:     fname,
				Message:  "Calls a netcat/connect utility (`" + pkgbuild.Render(call) + "`); commonly used to exfiltrate data or open reverse shells.",
			})
			return true
		})
		return fs
	})
	findings = append(findings, appendFind...)
	return findings
}

func trimExcerpt(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

// obfuscationRule flags techniques used to hide malicious intent from
// exactly the kind of static analysis piq performs: base64/xxd
// decodes into a shell, nested command substitution, excessive
// escaping, and trivially-obfuscated hex payloads.
type obfuscationRule struct{}

func (obfuscationRule) Name() string { return "obfuscation" }

func (obfuscationRule) Points() int { return 70 }

func (obfuscationRule) Gate() bool { return false }

var decodeRe = regexp.MustCompile(`(?i)\b(base64|b64|xxd -r|openssl enc|uudecode)\b`)
var hexRe = regexp.MustCompile(`\$\s*'[0-9a-fA-F]{8,}'|printf[^\n]*\\x[0-9a-fA-F]`)

func (obfuscationRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, raw string) []Finding {
		var findings []Finding
		lower := strings.ToLower(raw)
		if decodeRe.MatchString(lower) && (strings.Contains(lower, "sh") || strings.Contains(lower, "eval")) {
			findings = append(findings, Finding{
				Rule:     "obfuscation",
				Severity: Critical,
				File:     fname,
				Message:  "Decodes/decrypts embedded content (`" + trimExcerpt(raw) + "`) and feeds it to a shell or eval. This is how malware hides its payload from review — a very strong red flag.",
			})
		}
		if hexRe.MatchString(raw) {
			findings = append(findings, Finding{
				Rule:     "obfuscation",
				Severity: Warning,
				File:     fname,
				Message:  "Contains hex-escaped/encoded strings, a common obfuscation trick. Verify anything here is genuinely a build artifact and not a hidden payload.",
			})
		}
		return findings
	})
}
