package scanner

import (
	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"mvdan.cc/sh/v3/syntax"
)

type Severity int

const (
	Info Severity = iota
	Warning
	Critical
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRITICAL"
	case Warning:
		return "WARNING"
	default:
		return "INFO"
	}
}

type Finding struct {
	Rule     string // short machine-readable id, e.g. "pipe-to-shell"
	Severity Severity
	Line     int
	Message  string // human-readable explanation, shown in the report
	File     string // which file the finding came from (PKGBUILD or a scriptlet)
}

// Scriptlet is a companion shell file shipped alongside a PKGBUILD —
// typically a *.install scriptlet (e.g. foo.install) that pacman runs
// as root on install/upgrade/remove. These run outside the build
// sandbox, with root privileges, so they are a prime attack surface.
type Scriptlet struct {
	Name string       // e.g. "foo.install"
	Raw  string       // literal source text
	AST  *syntax.File // parsed shell AST (nil if unparseable)
}

// LocalSource is a local file referenced by a PKGBUILD's source=() or
// install= arrays — a scriptlet, a patch, etc. If a referenced file is
// missing, the scan is incomplete and can never be considered OK.
type LocalSource struct {
	Name     string // referenced name as written (e.g. "foo.patch")
	Present  bool   // whether the file was actually received on disk
	Path     string // absolute path if Present
	Raw      string // contents if Present
	AST      *syntax.File
	IsScript bool // whether it's a *.install scriptlet
}

// Context bundles everything a scanner rule might need: the PKGBUILD
// itself, its parsed AST and metadata, any companion scriptlets and
// referenced local files, AUR reputation info, and provenance history.
type Context struct {
	Raw        string            // PKGBUILD literal source text
	AST        *syntax.File      // PKGBUILD shell AST
	Metadata   *pkgbuild.Metadata
	AURInfo    *aur.Package      // may be nil for a purely-local scan
	Scriptlets []Scriptlet       // *.install companion scriptlets
	Sources    []LocalSource     // local files referenced by the PKGBUILD
	History    interface{}       // *history.Provenance, if inspected
	File       string            // path of the PKGBUILD on disk, if any
}

// ScoredRule is a Rule that contributes risk points toward a verdict.
type ScoredRule interface {
	Rule
	Points() int // risk this rule contributes when it fires (0-100)
	Gate() bool  // true if a single finding forces MALICIOUS regardless of score
}

// Rule is anything that inspects a parsed PKGBUILD (and its companion
// files) and produces zero or more findings. Implement ScoredRule to
// contribute toward the aggregate verdict.
type Rule interface {
	Name() string
	Check(ctx *Context) []Finding
}

var registry []Rule

func Register(r Rule) { registry = append(registry, r) }

func RunAll(ctx *Context) []Finding {
	var findings []Finding
	for _, r := range registry {
		findings = append(findings, r.Check(ctx)...)
	}
	return findings
}

// ScriptletByName returns the first scriptlet with the given name.
func (c *Context) ScriptletByName(name string) (*Scriptlet, bool) {
	for i := range c.Scriptlets {
		if c.Scriptlets[i].Name == name {
			return &c.Scriptlets[i], true
		}
	}
	return nil, false
}

// ForEachFile runs fn over the PKGBUILD AST and every companion
// scriptlet AST, so AST-walking rules can be written once and applied
// to both.
func (c *Context) ForEachFile(fn func(ast *syntax.File, name, raw string) []Finding) []Finding {
	var findings []Finding
	if c.AST != nil {
		findings = append(findings, fn(c.AST, "PKGBUILD", c.Raw)...)
	}
	for _, s := range c.Scriptlets {
		if s.AST != nil {
			findings = append(findings, fn(s.AST, s.Name, s.Raw)...)
		}
	}
	return findings
}

// lineOf extracts a 1-based line number from a node's position for
// human-friendly reports. Returns 0 when the position is invalid.
func lineOf(n syntax.Node) int {
	if n == nil || !n.Pos().IsValid() {
		return 0
	}
	return int(n.Pos().Line())
}
