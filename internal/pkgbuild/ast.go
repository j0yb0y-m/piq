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

// commandWrappers are commands that only modify how the real command
// runs; scan rules care about the command underneath them.
var commandWrappers = map[string]bool{
	"sudo": true, "doas": true, "env": true, "command": true,
	"exec": true, "setsid": true,
}

// EffectiveCommand returns the command a call actually invokes,
// looking through wrappers such as sudo/doas/env and leading
// VAR=value assignments. A wrapper is only skipped when another
// argument follows it: `command -v foo` stays `command`, because -v
// is a flag for command itself rather than a wrapped command.
func EffectiveCommand(c *syntax.CallExpr) string {
	if c == nil {
		return ""
	}
	args := c.Args
	for i := 0; i < len(args); i++ {
		if isAssignmentWord(args[i]) {
			continue
		}
		rendered := Render(args[i])
		if !commandWrappers[baseName(rendered)] {
			return rendered
		}
		j := i + 1
		for j < len(args) && isAssignmentWord(args[j]) {
			j++
		}
		if j >= len(args) || strings.HasPrefix(Render(args[j]), "-") {
			return rendered
		}
		i = j - 1
	}
	return ""
}

// isAssignmentWord reports whether a word is a VAR=value prefix such
// as the FOO=1 in `env FOO=1 curl`.
func isAssignmentWord(w *syntax.Word) bool {
	if w == nil {
		return false
	}
	text := Render(w)
	eq := strings.IndexByte(text, '=')
	if eq <= 0 {
		return false
	}
	for i, r := range text[:eq] {
		if i == 0 {
			if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
				return false
			}
			continue
		}
		if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// baseName strips any directory prefix from a command name.
func baseName(name string) string {
	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		return name[idx+1:]
	}
	return name
}
