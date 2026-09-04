package scanner

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(missingScriptletRule{})
	Register(installFunctionMissingRule{})
}

// missingScriptletRule verifies that any install= referenced by the
// PKGBUILD was actually received on disk, and that it's parseable.
type missingScriptletRule struct{}

func (missingScriptletRule) Name() string { return "missing-scriptlet" }

func (missingScriptletRule) Points() int { return 90 }

func (missingScriptletRule) Gate() bool { return false }

func (missingScriptletRule) Check(ctx *Context) []Finding {
	meta := ctx.Metadata
	if meta == nil || meta.Install == "" {
		return nil
	}
	// Two failure modes:
	//  1. an entry in Sources with the same name but Present=false.
	//  2. the install= name not among the received local files at all.
	var findings []Finding
	sp := strings.TrimSpace(meta.Install)
	found := false
	for _, s := range ctx.Sources {
		if s.Name == sp {
			found = true
			if !s.Present {
				findings = append(findings, Finding{
					Rule:     "missing-scriptlet",
					Severity: Critical,
					File:     "PKGBUILD",
					Message:  "install= references `" + sp + "`, but that file was not actually present when the package repo was fetched. A missing scriptlet means the build metadata is incomplete — do not install.",
				})
			}
		}
	}
	if !found {
		findings = append(findings, Finding{
			Rule:     "missing-scriptlet",
			Severity: Critical,
			File:     "PKGBUILD",
			Message:  "install= references `" + sp + "`, but no such local file is accounted for in the fetched source. The scriptlet that would run as root on install is missing or hidden — review carefully.",
		})
	}
	return findings
}

// installFunctionMissingRule checks that a non-empty .install scriptlet
// actually defines at least the pre_install/post_install/pre_upgrade/
// post_upgrade/pre_remove/post_remove function it claims to handle.
type installFunctionMissingRule struct{}

func (installFunctionMissingRule) Name() string { return "scriptlet-no-functions" }

func (installFunctionMissingRule) Points() int { return 30 }

func (installFunctionMissingRule) Gate() bool { return false }

func (installFunctionMissingRule) Check(ctx *Context) []Finding {
	var findings []Finding
	for _, s := range ctx.Scriptlets {
		if s.AST == nil {
			continue
		}
		hasFn := false
		syntax.Walk(s.AST, func(n syntax.Node) bool {
			if fn, ok := n.(*syntax.FuncDecl); ok {
				_ = fn
				hasFn = true
				return false
			}
			return true
		})
		if !hasFn {
			findings = append(findings, Finding{
				Rule:     "scriptlet-no-functions",
				Severity: Warning,
				File:     s.Name,
				Message:  "Scriptlet `" + s.Name + "` defines no functions. A normal install scriptlet defines pre/post install/remove functions; content at top level runs on every pacman transaction.",
			})
		}
	}
	return findings
}
