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

// writeCommands are commands that commonly write to the filesystem.
var writeCommands = map[string]bool{
	"cp": true, "mv": true, "echo": true, "install": true, "tee": true,
	"cat": true, "printf": true, "mkdir": true, "chmod": true, "chown": true,
}

func (suspiciousWriteRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, _ string) []Finding {
		var findings []Finding
		syntax.Walk(file, func(n syntax.Node) bool {
			stmt, ok := n.(*syntax.Stmt)
			if !ok {
				return true
			}
			call, ok := stmt.Cmd.(*syntax.CallExpr)
			if !ok {
				return true
			}
			name := pkgbuild.CommandName(call)
			if !writeCommands[name] {
				return true
			}
			rendered := pkgbuild.Render(stmt)
			for _, p := range sensitivePaths {
				if strings.Contains(rendered, p) {
					findings = append(findings, Finding{
						Rule:     "suspicious-write-path",
						Severity: Critical,
						Line:     lineOf(stmt),
						Message:  "In " + fname + ": appears to write to " + p + " (`" + rendered + "`), well outside anything a package build should touch. This is a classic persistence technique — cron jobs, systemd units, and shell rc files are exactly how malware survives a reboot.",
					})
				}
			}
			return true
		})
		return findings
	})
}
