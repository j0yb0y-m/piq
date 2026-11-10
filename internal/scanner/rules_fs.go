package scanner

import (
	"strings"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(suspiciousWriteRule{})
}

type suspiciousWriteRule struct{}

func (suspiciousWriteRule) Name() string { return "suspicious-write-path" }

func (suspiciousWriteRule) Points() int { return 75 }

func (suspiciousWriteRule) Gate() bool { return false }

// sensitivePaths are places a well-behaved PKGBUILD has no legitimate
// reason to touch directly — it should only write inside $srcdir and
// $pkgdir.
var sensitivePaths = []string{
	"/etc/systemd/system", "/etc/cron.d", "/var/spool/cron",
	"$HOME/.ssh", "~/.ssh", "/root", "/etc/sudoers",
	"$HOME/.bashrc", "$HOME/.profile", "$HOME/.config/fish",
	"~/.bashrc", "~/.profile", "~/.config/fish",
}

func (suspiciousWriteRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, _ string) []Finding {
		var findings []Finding
		syntax.Walk(file, func(n syntax.Node) bool {
			stmt, ok := n.(*syntax.Stmt)
			if !ok {
				return true
			}
			seen := map[string]bool{}
			add := func(path, rendered string) {
				pat, ok := sensitivePath(path)
				if !ok || seen[pat] {
					return
				}
				seen[pat] = true
				findings = append(findings, Finding{
					Rule:     "suspicious-write-path",
					Severity: Critical,
					Line:     lineOf(stmt),
					Message:  "In " + fname + ": appears to write to " + pat + " (`" + rendered + "`), well outside anything a package build should touch. This is a classic persistence technique — cron jobs, systemd units, and shell rc files are exactly how malware survives a reboot.",
				})
			}

			// Only output redirections are destinations. Input
			// redirections, here-documents, and fd duplication are
			// reads/handles, not writes. `<>` opens a file for
			// read/write but is ignored by default: the common shape
			// is still a read, and we do not want to flag it.
			for _, redir := range stmt.Redirs {
				if redir == nil || redir.Word == nil || !isWriteRedirect(redir.Op) {
					continue
				}
				add(unquote(pkgbuild.Render(redir.Word)), pkgbuild.Render(stmt))
			}

			call, ok := stmt.Cmd.(*syntax.CallExpr)
			if !ok {
				return true
			}
			rendered := pkgbuild.Render(call)
			switch effectiveCommandName(call) {
			case "tee":
				for _, arg := range call.Args {
					add(unquote(pkgbuild.Render(arg)), rendered)
				}
			case "cp", "mv", "install":
				// The final argument is the destination.
				if len(call.Args) > 0 {
					add(unquote(pkgbuild.Render(call.Args[len(call.Args)-1])), rendered)
				}
			case "chmod", "chown":
				for _, arg := range call.Args {
					add(unquote(pkgbuild.Render(arg)), rendered)
				}
			}
			return true
		})
		return findings
	})
}

// sensitivePath reports the sensitive prefix that a destination path
// matches, if any.
func sensitivePath(path string) (string, bool) {
	lower := strings.ToLower(path)
	for _, p := range sensitivePaths {
		if strings.Contains(lower, strings.ToLower(p)) {
			return p, true
		}
	}
	return "", false
}

func unquote(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`)
}

// isWriteRedirect reports whether a redirection operator writes to its
// word. Input redirects, here-documents, and descriptor duplication
// are deliberately excluded.
func isWriteRedirect(op syntax.RedirOperator) bool {
	switch op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob,
		syntax.RdrAll, syntax.AppAll,
		syntax.RdrAllClob, syntax.AppAllClob:
		return true
	default:
		return false
	}
}
