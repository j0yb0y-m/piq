package scanner

import (
	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(pipeToShellRule{})
	Register(evalRule{})
	Register(privescRule{})
}

type pipeToShellRule struct{}

func (pipeToShellRule) Name() string { return "pipe-to-shell" }

func (pipeToShellRule) Points() int { return 95 }

func (pipeToShellRule) Gate() bool { return true }

var shellCommands = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
}

var downloadCommands = map[string]bool{"curl": true, "wget": true}

func (pipeToShellRule) Check(ctx *Context) []Finding {
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
			fetches := downloadCommands[effectiveCommandName(firstCall(bc.X))]
			runsShell := shellCommands[effectiveCommandName(firstCall(bc.Y))]

			if fetches && runsShell {
				findings = append(findings, Finding{
					Rule:     "pipe-to-shell",
					Severity: Critical,
					Line:     lineOf(n),
					Message:  "In " + fname + ": downloads content and pipes it directly into a shell (`" + pkgbuild.Render(n) + "`). This is the single most common pattern in real AUR supply-chain attacks — the fetched content is never written to disk or reviewable before it runs.",
				})
			}
			return true
		})
		return findings
	})
}

// firstCall returns the call expression at the head of a statement.
func firstCall(stmt *syntax.Stmt) *syntax.CallExpr {
	if stmt == nil {
		return nil
	}
	call, _ := stmt.Cmd.(*syntax.CallExpr)
	return call
}

type evalRule struct{}

func (evalRule) Name() string { return "eval-usage" }

func (evalRule) Points() int { return 50 }

func (evalRule) Gate() bool { return false }

func (evalRule) Check(ctx *Context) []Finding {
	return ctx.ForEachFile(func(file *syntax.File, fname, _ string) []Finding {
		var findings []Finding
		syntax.Walk(file, func(n syntax.Node) bool {
			call, ok := n.(*syntax.CallExpr)
			if !ok {
				return true
			}
			if pkgbuild.CommandName(call) == "eval" {
				findings = append(findings, Finding{
					Rule:     "eval-usage",
					Severity: Warning,
					Line:     lineOf(n),
					Message:  "In " + fname + ": uses `eval` (`" + pkgbuild.Render(n) + "`), which runs a dynamically-built string as code. Not automatically malicious, but it defeats static analysis — deserves a manual look.",
				})
			}
			return true
		})
		return findings
	})
}

type privescRule struct{}

func (privescRule) Name() string { return "privilege-escalation" }

func (privescRule) Points() int { return 75 }

func (privescRule) Gate() bool { return false }

func (privescRule) Check(ctx *Context) []Finding {
	dangerous := map[string]bool{"sudo": true, "su": true, "pkexec": true, "doas": true}
	return ctx.ForEachFile(func(file *syntax.File, fname, _ string) []Finding {
		var findings []Finding
		syntax.Walk(file, func(n syntax.Node) bool {
			call, ok := n.(*syntax.CallExpr)
			if !ok {
				return true
			}
			if name := pkgbuild.CommandName(call); dangerous[name] {
				findings = append(findings, Finding{
					Rule:     "privilege-escalation",
					Severity: Critical,
					Line:     lineOf(n),
					Message:  "In " + fname + ": calls `" + name + "` from inside a PKGBUILD function. makepkg is designed to never require root during build/package — a package that tries to escalate here is either broken or hostile.",
				})
			}
			return true
		})
		return findings
	})
}
