package scanner

import (
	"strings"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(splitPackageRule{})
}

// splitPackageRule checks that every element in a split pkgname=()
// array has a corresponding package_<name>() function. Missing
// functions mean the build will silently skip packaging that
// sub-package — the user thinks they're getting everything but
// only half of it shows up.
type splitPackageRule struct{}

func (splitPackageRule) Name() string { return "split-package-missing" }

func (splitPackageRule) Points() int { return 30 }

func (splitPackageRule) Gate() bool { return false }

func (splitPackageRule) Check(ctx *Context) []Finding {
	if ctx.AST == nil {
		return nil
	}
	names := splitPkgNames(ctx.AST)
	if len(names) <= 1 {
		return nil // single package, nothing to check
	}
	fns := definedFunctions(ctx.AST)
	var findings []Finding
	for _, name := range names {
		fn := "package_" + name
		if !fns[fn] {
			findings = append(findings, Finding{
				Rule:     "split-package-missing",
				Severity: Warning,
				File:     "PKGBUILD",
				Message:  "Split package declares pkgname entry `" + name + "` but no `" + fn + "()` function is defined. This sub-package will silently not be built/installed.",
			})
		}
	}
	return findings
}

// splitPkgNames extracts names from pkgname=(a b c) or returns
// nil for a single pkgname=foo.
func splitPkgNames(file *syntax.File) []string {
	if file == nil {
		return nil
	}
	for _, stmt := range file.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) > 0 {
			continue
		}
		for _, assign := range call.Assigns {
			if assign.Name == nil || assign.Name.Value != "pkgname" {
				continue
			}
			if assign.Array == nil {
				// single pkgname=value
				return nil
			}
			var names []string
			for _, elem := range assign.Array.Elems {
				if elem.Value != nil {
					names = append(names, strings.Trim(pkgbuild.Render(elem.Value), `"'`))
				}
			}
			return names
		}
	}
	return nil
}

// definedFunctions returns the set of top-level function names in the
// AST.
func definedFunctions(file *syntax.File) map[string]bool {
	fns := map[string]bool{}
	if file == nil {
		return fns
	}
	for _, stmt := range file.Stmts {
		fn, ok := stmt.Cmd.(*syntax.FuncDecl)
		if !ok {
			continue
		}
		if fn.Name != nil {
			fns[fn.Name.Value] = true
		}
	}
	return fns
}
