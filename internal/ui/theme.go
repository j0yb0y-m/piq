// Package ui is piq's single output layer. Every user-facing write goes
// through it so color can be disabled consistently for pipes, NO_COLOR,
// and JSON output.
package ui

import (
	"fmt"
	"io"
	"os"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

// Catppuccin Mocha — https://catppuccin.com/palette/
const (
	red      = "#f38ba8"
	peach    = "#fab387"
	blue     = "#89b4fa"
	green    = "#a6e3a1"
	mauve    = "#cba6f7"
	text     = "#cdd6f4"
	overlay0 = "#6c7086"
)

var (
	stdout       io.Writer = os.Stdout
	stderr       io.Writer = os.Stderr
	colorEnabled           = colorAllowed(os.Stdout)
	renderer               = newRenderer(os.Stdout, colorEnabled)
)

// Init stores the writers used by Printf, Println, and Errorf and derives
// the color setting from stdout. A nil writer falls back to the process
// stdout/stderr.
func Init(out, errOut io.Writer) {
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	stdout = out
	stderr = errOut
	colorEnabled = colorAllowed(out)
	renderer = newRenderer(out, colorEnabled)
}

// SetColor overrides the computed color setting. Tests use it to force
// ANSI output even when the writer is not a terminal.
func SetColor(enabled bool) {
	colorEnabled = enabled
	renderer = newRenderer(stdout, enabled)
}

// Out returns the writer for normal command output. Use it for JSON
// encoders; human-readable output should go through Printf/Println.
func Out() io.Writer { return stdout }

// Err returns the writer for errors and progress messages.
func Err() io.Writer { return stderr }

// Printf writes formatted output to the configured stdout.
func Printf(format string, args ...any) {
	fmt.Fprintf(stdout, format, args...)
}

// Println writes arguments followed by a newline to the configured stdout.
func Println(args ...any) {
	fmt.Fprintln(stdout, args...)
}

// Errorf writes formatted output to the configured stderr.
func Errorf(format string, args ...any) {
	fmt.Fprintf(stderr, format, args...)
}

// colorAllowed reports whether ANSI styling should be emitted to w.
func colorAllowed(w io.Writer) bool {
	if w == nil {
		return false
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func newRenderer(w io.Writer, color bool) *lipgloss.Renderer {
	r := lipgloss.NewRenderer(w)
	if color {
		r.SetColorProfile(termenv.TrueColor)
	} else {
		r.SetColorProfile(termenv.Ascii)
	}
	return r
}

func apply(style lipgloss.Style, s string) string {
	if !colorEnabled {
		return s
	}
	return style.Render(s)
}

// Critical styles text as a high-severity problem (red).
func Critical(s string) string {
	return apply(renderer.NewStyle().Foreground(lipgloss.Color(red)), s)
}

// Warning styles text as something that needs attention (peach).
func Warning(s string) string {
	return apply(renderer.NewStyle().Foreground(lipgloss.Color(peach)), s)
}

// Notice styles text as neutral informational output (blue).
func Notice(s string) string {
	return apply(renderer.NewStyle().Foreground(lipgloss.Color(blue)), s)
}

// Success styles text as a positive result (green).
func Success(s string) string {
	return apply(renderer.NewStyle().Foreground(lipgloss.Color(green)), s)
}

// Accent styles headings and emphasized text (mauve).
func Accent(s string) string {
	return apply(renderer.NewStyle().Foreground(lipgloss.Color(mauve)), s)
}

// Muted styles dimmed metadata (overlay0).
func Muted(s string) string {
	return apply(renderer.NewStyle().Foreground(lipgloss.Color(overlay0)), s)
}

// Bold styles text with the bold attribute.
func Bold(s string) string {
	return apply(renderer.NewStyle().Bold(true), s)
}
