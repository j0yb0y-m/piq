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
	"rm": true, "rmdir": true, "dd": true, "fdisk": true,
	"parted": true, "shred": true, "wipefs": true, "pv": true,
}

// destructiveTargets are paths a clean build never touches; combined
// with a destructive command they imply deliberate damage.
var destructiveTargets = []string{
	"/", "/*", "~", "~/", "$HOME", "${HOME}", "/home", "/etc", "/usr",
	"/boot", "/srv", "/var", "--no-preserve-root",
	// Escaping the build sandbox is not "cleanup".
	"$srcdir/..", "${srcdir}/..", "$pkgdir/..", "${pkgdir}/..",
	"$BUILDDIR/..", "${BUILDDIR}/..",
}

// buildDirMarkers identify tokens that belong to makepkg's sandbox
// directories. Removing anything below them is normal build cleanup.
var buildDirMarkers = []string{
	"$srcdir", "${srcdir}", "$pkgdir", "${pkgdir}",
	"$BUILDDIR", "${BUILDDIR}",
}

func (destructiveRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, _ string) []Finding {
		var findings []Finding
		syntax.Walk(file, func(n syntax.Node) bool {
			call, ok := n.(*syntax.CallExpr)
			if !ok {
				return true
			}
			name := effectiveCommandName(call)
			// mkfs.ext4, mkfs.xfs and friends are destructive by
			// definition: they overwrite a filesystem.
			if strings.HasPrefix(name, "mkfs") {
				findings = append(findings, Finding{
					Rule:     "destructive",
					Severity: Critical,
					File:     fname,
					Message:  "Runs `" + name + "` (`" + trimExcerpt(pkgbuild.Render(call)) + "`). Formatting a filesystem from a package build destroys whatever is on that device — a hallmark of destructive malware.",
				})
				return true
			}
			if !destructiveCommands[name] {
				return true
			}
			rendered := strings.Join(strings.Fields(pkgbuild.Render(call)), " ")
			if target, hit := destructiveTarget(rendered, name); hit {
				findings = append(findings, Finding{
					Rule:     "destructive",
					Severity: Critical,
					File:     fname,
					Message:  "Destructive command targets " + target + " (`" + rendered + "`). This can delete or overwrite the user's data or OS — a hallmark of destructive malware.",
				})
			}
			return true
		})
		return findings
	})
}

// destructiveTarget finds a dangerous path token in a normalized
// command line. Tokens under $srcdir/$pkgdir/$BUILDDIR are ignored.
func destructiveTarget(rendered, command string) (string, bool) {
	for _, field := range strings.Fields(rendered) {
		token := strings.Trim(field, `"'`)
		if underBuildDir(token) {
			continue
		}
		if command == "dd" && strings.HasPrefix(token, "of=/dev/") {
			return token, true
		}
		for _, target := range destructiveTargets {
			if matchesDestructiveTarget(token, target) {
				return target, true
			}
		}
	}
	return "", false
}

func underBuildDir(token string) bool {
	// A path that walks up out of the build directory is not inside it.
	if strings.Contains(token, "..") {
		return false
	}
	for _, marker := range buildDirMarkers {
		if strings.Contains(token, marker) {
			return true
		}
	}
	return false
}

func matchesDestructiveTarget(token, target string) bool {
	if token == target {
		return true
	}
	// Avoid treating every absolute path as "/" and every glob as "/*".
	if target == "/" || target == "/*" || target == "--no-preserve-root" {
		return false
	}
	if strings.HasSuffix(target, "/") {
		return strings.HasPrefix(token, target)
	}
	return strings.HasPrefix(token, target+"/")
}
