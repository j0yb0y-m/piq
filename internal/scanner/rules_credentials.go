package scanner

import (
	"strings"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(credentialReferenceRule{})
	Register(credentialTheftRule{})
	Register(exfilRule{})
}

// credentialCategory groups the path fragments that point at one kind
// of secret. A file that mentions several fragments of the same kind
// (say ~/.ssh and id_rsa) produces one finding, not several.
type credentialCategory struct {
	label    string
	patterns []string
}

var credentialCategories = []credentialCategory{
	{
		label:    "SSH keys",
		patterns: []string{"$HOME/.ssh", "~/.ssh", "id_rsa", "id_ed25519", "known_hosts"},
	},
	{
		label:    "AWS credentials",
		patterns: []string{"$HOME/.aws", "~/.aws", ".aws/credentials"},
	},
	{
		label:    "Kubernetes config",
		patterns: []string{"$HOME/.kube", "~/.kube", ".kube/config"},
	},
	{
		label:    "browser cookies",
		patterns: []string{"cookie.db", "~/library/application support"},
	},
	{
		label:    "cryptocurrency wallets",
		patterns: []string{"wallet.dat", "keystore", "seedphrase", "mnemonic"},
	},
	{
		label:    "GnuPG keyrings",
		patterns: []string{"$HOME/.gnupg", "~/.gnupg"},
	},
	{
		label:    "registry credentials",
		patterns: []string{".npmrc", "~/.netrc", "$HOME/.netrc"},
	},
}

// credentialReferenceRule flags a package that merely names a
// credential path. Reading one is worth reviewing, but it is not by
// itself theft: legitimate tooling occasionally inspects these paths.
type credentialReferenceRule struct{}

func (credentialReferenceRule) Name() string { return "credential-reference" }

func (credentialReferenceRule) Points() int { return 20 }

func (credentialReferenceRule) Gate() bool { return false }

func (credentialReferenceRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(_ *syntax.File, fname, raw string) []Finding {
		lower := strings.ToLower(raw)
		var findings []Finding
		for _, cat := range credentialCategories {
			pat, ok := matchCredentialCategory(lower, cat)
			if !ok {
				continue
			}
			findings = append(findings, Finding{
				Rule:     "credential-reference",
				Severity: Warning,
				File:     fname,
				Message:  "References " + cat.label + " (`" + pat + "`). A clean package build has no reason to read this path; treat it as a prompt to inspect the surrounding code.",
			})
		}
		return findings
	})
}

// credentialTheftRule escalates the reference to theft only when the
// same file also carries a network command that could send the data
// out. The gated data-exfiltration rule still catches a local file
// piped straight into curl/wget.
type credentialTheftRule struct{}

func (credentialTheftRule) Name() string { return "credential-theft" }

func (credentialTheftRule) Points() int { return 100 }

func (credentialTheftRule) Gate() bool { return false }

var credentialEgressCommands = map[string]bool{
	"curl": true, "wget": true, "nc": true, "ncat": true,
	"socat": true, "scp": true, "rsync": true, "ssh": true,
}

func (credentialTheftRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, raw string) []Finding {
		lower := strings.ToLower(raw)
		cat, pat, ok := firstCredentialMatch(lower)
		if !ok {
			return nil
		}
		if !hasNetworkCommand(file) {
			return nil
		}
		return []Finding{{
			Rule:     "credential-theft",
			Severity: Critical,
			File:     fname,
			Message:  "References " + cat.label + " (`" + pat + "`) in a file that also invokes a network command. Reading a credential path and having egress in the same package is the shape of credential theft — do not install.",
		}}
	})
}

func firstCredentialMatch(lower string) (credentialCategory, string, bool) {
	for _, cat := range credentialCategories {
		if pat, ok := matchCredentialCategory(lower, cat); ok {
			return cat, pat, true
		}
	}
	return credentialCategory{}, "", false
}

func matchCredentialCategory(lower string, cat credentialCategory) (string, bool) {
	for _, pat := range cat.patterns {
		// The haystack is lowercased, so normalize the pattern too.
		// Return the original spelling for the human-facing message.
		if strings.Contains(lower, strings.ToLower(pat)) {
			return pat, true
		}
	}
	return "", false
}

func hasNetworkCommand(file *syntax.File) bool {
	if file == nil {
		return false
	}
	found := false
	syntax.Walk(file, func(n syntax.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*syntax.CallExpr)
		if !ok {
			return true
		}
		if credentialEgressCommands[effectiveCommandName(call)] {
			found = true
			return false
		}
		return true
	})
	return found
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

// effectiveCommandName returns the lowercased basename of the command
// a call invokes, looking through sudo/env-style wrappers.
func effectiveCommandName(c *syntax.CallExpr) string {
	return commandWord(pkgbuild.EffectiveCommand(c))
}
