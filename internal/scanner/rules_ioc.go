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
	Register(hexPayloadRule{})
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
// /dev/tcp device opened from a shell, an interactive shell paired
// with a connect utility, or a connect utility told to execute a
// shell. Plain nc connections are common in diagnostics and are not
// flagged on their own.
type reverseShellRule struct{}

func (reverseShellRule) Name() string { return "reverse-shell" }

func (reverseShellRule) Points() int { return 100 }

func (reverseShellRule) Gate() bool { return true }

var connectCommands = map[string]bool{"nc": true, "ncat": true, "netcat": true, "socat": true, "telnet": true}

var shellInTextRe = regexp.MustCompile(`(?i)(?:^|[\s|;&()/])(?:sh|bash|zsh|dash|ksh)(?:\s|$|;|&|\||>|<)`)
var interactiveShellRe = regexp.MustCompile(`(?i)(?:^|[\s|;&()])(?:sh|bash|zsh)\s+-i(?:\s|$|>|<)`)

func (reverseShellRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, raw string) []Finding {
		lower := strings.ToLower(raw)
		hasDevTCP := strings.Contains(lower, "/dev/tcp")
		hasInteractiveShell := interactiveShellRe.MatchString(lower)

		hasConnect := false
		hasConnectExec := false
		if file != nil {
			syntax.Walk(file, func(n syntax.Node) bool {
				call, ok := n.(*syntax.CallExpr)
				if !ok {
					return true
				}
				if !connectCommands[effectiveCommandName(call)] {
					return true
				}
				hasConnect = true
				if connectCallExecsShell(call) {
					hasConnectExec = true
				}
				return true
			})
		}

		if !(hasDevTCP && shellInTextRe.MatchString(lower)) &&
			!(hasInteractiveShell && hasConnect) && !hasConnectExec {
			return nil
		}
		return []Finding{{
			Rule:     "reverse-shell",
			Severity: Critical,
			File:     fname,
			Message:  "Pattern matches a reverse shell (`" + trimExcerpt(raw) + "`). This opens an outbound shell to an external host — unambiguous malice.",
		}}
	})
}

// connectCallExecsShell reports whether a connect utility is told to
// execute a shell command (-e/-c) or a shell binary (socat exec:).
func connectCallExecsShell(call *syntax.CallExpr) bool {
	hasExec := false
	for _, arg := range call.Args {
		rendered := strings.ToLower(pkgbuild.Render(arg))
		if rendered == "-e" || rendered == "-c" || strings.Contains(rendered, "exec") {
			hasExec = true
			break
		}
	}
	return hasExec && shellInTextRe.MatchString(strings.ToLower(pkgbuild.Render(call)))
}

func trimExcerpt(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		return s[:160] + "…"
	}
	return s
}

// obfuscationRule flags content that is decoded and fed straight into
// a shell, hiding the payload from exactly the kind of static
// analysis piq performs.
type obfuscationRule struct{}

func (obfuscationRule) Name() string { return "obfuscation" }

func (obfuscationRule) Points() int { return 70 }

func (obfuscationRule) Gate() bool { return true }

var decoderPatterns = []string{
	"base64 -d", "base64 --decode", "xxd -r", "openssl enc -d", "uudecode",
}

func containsDecoder(s string) bool {
	lower := strings.ToLower(s)
	for _, pat := range decoderPatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func (obfuscationRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, raw string) []Finding {
		if !decodingReachesShell(file, 0) {
			return nil
		}
		return []Finding{{
			Rule:     "obfuscation",
			Severity: Critical,
			File:     fname,
			Message:  "Decodes/decrypts embedded content (`" + trimExcerpt(raw) + "`) and feeds it to a shell or eval. This is how malware hides its payload from review — a very strong red flag.",
		}}
	})
}

// decodingReachesShell reports whether decoded output is actually
// executed in this file: piped into a shell, evaluated, or used as a
// shell -c script. Writing decoded bytes to a file is not execution.
func decodingReachesShell(file *syntax.File, depth int) bool {
	if file == nil || depth > 8 {
		return false
	}
	found := false
	syntax.Walk(file, func(n syntax.Node) bool {
		if found {
			return false
		}
		switch v := n.(type) {
		case *syntax.BinaryCmd:
			if (v.Op == syntax.Pipe || v.Op == syntax.PipeAll) &&
				containsDecoder(pkgbuild.Render(v.X)) &&
				shellCommands[effectiveCommandName(firstCall(v.Y))] {
				found = true
				return false
			}
		case *syntax.CallExpr:
			rendered := pkgbuild.Render(v)
			cmd := effectiveCommandName(v)
			if cmd == "eval" && containsDecoder(rendered) {
				found = true
				return false
			}
			if shellCommands[cmd] && callHasArg(v, "-c") {
				if script, ok := dashCScript(v); ok &&
					decodedScriptReachesShell(script, depth+1) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}

// decodedScriptReachesShell inspects the argument to `sh -c`. It
// covers a bare command substitution (whose output becomes the script)
// and recursively parses the script for pipes/eval/nested -c.
func decodedScriptReachesShell(script string, depth int) bool {
	script = strings.TrimSpace(unquote(script))
	if script == "" {
		return false
	}
	if containsDecoder(script) && isCommandSubstitutionScript(script) {
		return true
	}
	file, err := pkgbuild.Parse(strings.NewReader(script), "sh -c")
	if err != nil {
		return false
	}
	return decodingReachesShell(file, depth)
}

func isCommandSubstitutionScript(script string) bool {
	if strings.HasPrefix(script, "$(") && strings.HasSuffix(script, ")") {
		return true
	}
	return len(script) >= 2 && strings.HasPrefix(script, "`") && strings.HasSuffix(script, "`")
}

// dashCScript returns the word following -c in a shell invocation.
func dashCScript(call *syntax.CallExpr) (string, bool) {
	for i, arg := range call.Args {
		if strings.EqualFold(pkgbuild.Render(arg), "-c") && i+1 < len(call.Args) {
			return pkgbuild.Render(call.Args[i+1]), true
		}
	}
	return "", false
}

func callHasArg(call *syntax.CallExpr, want string) bool {
	for _, arg := range call.Args {
		if strings.EqualFold(pkgbuild.Render(arg), want) {
			return true
		}
	}
	return false
}

// hexPayloadRule is a non-gating warning for hex-escaped payloads.
// It stays outside obfuscationRule so that this softer signal can
// never trip a block on its own.
type hexPayloadRule struct{}

func (hexPayloadRule) Name() string { return "obfuscation-hex" }

func (hexPayloadRule) Points() int { return 25 }

func (hexPayloadRule) Gate() bool { return false }

var hexRe = regexp.MustCompile(`\$\s*'[0-9a-fA-F]{8,}'|printf[^\n]*\\x[0-9a-fA-F]`)

func (hexPayloadRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(_ *syntax.File, fname, raw string) []Finding {
		if !hexRe.MatchString(raw) {
			return nil
		}
		return []Finding{{
			Rule:     "obfuscation-hex",
			Severity: Warning,
			File:     fname,
			Message:  "Contains hex-escaped/encoded strings, a common obfuscation trick. Verify anything here is genuinely a build artifact and not a hidden payload.",
		}}
	})
}
