package main

import (
	"github.com/j0yb0y-m/piq/internal/scanner"
	"github.com/j0yb0y-m/piq/internal/ui"
)

// verdictStyle returns the style helper for a verdict.
func verdictStyle(v scanner.Verdict) func(string) string {
	switch v {
	case scanner.Malicious, scanner.Suspicious:
		return ui.Critical
	case scanner.Sketchy:
		return ui.Warning
	case scanner.OK, scanner.Trusted:
		return ui.Success
	default:
		return plain
	}
}

// plain returns text unchanged; it is the default for unstyled findings.
func plain(s string) string { return s }
