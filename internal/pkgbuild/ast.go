package pkgbuild

import (
	"io"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Parse turns PKGBUILD source into a syntax tree. This never
// executes anything — it's a pure parse, structurally the same
// operation as parsing JSON or XML.
func Parse(r io.Reader, name string) (*syntax.File, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	return parser.Parse(r, name)
}

// Render turns any node back into its original shell source text.
// Useful whenever a scanner rule wants to run a plain string/regex
// check against a specific subtree (a single command, a single
// pipeline) instead of manually walking word-part types.
func Render(n syntax.Node) string {
	var b strings.Builder
	syntax.NewPrinter().Print(&b, n)
	return b.String()
}

// CommandName returns the literal command being invoked by a call
// expression — "curl", "eval", "sudo", whatever Args[0] renders to.
// Returns "" for a bare variable assignment with no command.
func CommandName(c *syntax.CallExpr) string {
	if len(c.Args) == 0 {
		return ""
	}
	return Render(c.Args[0])
}
