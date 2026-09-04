package scanner

import (
	"strings"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(destructiveRule{})
}

// destructiveRule flags commands or paths that, if run at build or
// install time, could destroy the user's system: wiping home, the OS
// tree, or arbitrary mounted volumes.
type destructiveRule struct{}

func (destructiveRule) Name() string { return "destructive" }

func (destructiveRule) Points() int { return 100 }

func (destructiveRule) Gate() bool { return true }

var destructiveCommands = map[string]bool{
	"rm": true, "rmdir": true, "mkfs": true, "dd": true, "fdisk": true,
	"parted": true, "shred": true, "wipefs": true, "pv": true,
}

// destructiveTargets are paths a clean build never touches; combined
// with a destructive command they imply deliberate damage.
var destructiveTargets = []string{
	"/", "$HOME", "~", "/home", "/etc", "/usr", "/boot", "/srv", "/var",
	"$srcdir/..", "$pkgdir/..",
}

func (destructiveRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, _ string) []Finding {
		var findings []Finding
		syntax.Walk(file, func(n syntax.Node) bool {
			call, ok := n.(*syntax.CallExpr)
			if !ok {
				return true
			}
			name := pkgbuild.CommandName(call)
			if !destructiveCommands[name] {
				return true
			}
			rendered := strings.TrimSpace(pkgbuild.Render(call))
			// rm inside $srcdir/$pkgdir cleanup is normal; only flag
			// destructive ops aimed outside the build dirs.
			for _, t := range destructiveTargets {
				if rendered == name+" "+t || strings.HasSuffix(rendered, " "+t) {
					findings = append(findings, Finding{
						Rule:     "destructive",
						Severity: Critical,
						File:     fname,
						Message:  "Destructive command targets " + t + " (`" + rendered + "`). This can delete or overwrite the user's data or OS — a hallmark of destructive malware.",
					})
					break
				}
			}
			return true
		})
		return findings
	})
}
