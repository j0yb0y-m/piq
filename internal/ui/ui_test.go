package ui

import (
	"bytes"
	"strings"
	"testing"
)

func styles() map[string]func(string) string {
	return map[string]func(string) string{
		"critical": Critical, "warning": Warning, "notice": Notice,
		"success": Success, "accent": Accent, "muted": Muted, "bold": Bold,
	}
}

func TestStylesDisabled(t *testing.T) {
	SetColor(false)
	for name, fn := range styles() {
		if got := fn("x"); got != "x" {
			t.Errorf("%s: got %q, want plain x", name, got)
		}
	}
}

func TestStylesEnabled(t *testing.T) {
	SetColor(true)
	for name, fn := range styles() {
		got := fn("x")
		if !strings.Contains(got, "\x1b[") || !strings.Contains(got, "x") {
			t.Errorf("%s: got %q, want ANSI-wrapped x", name, got)
		}
	}
}

func TestWriters(t *testing.T) {
	var out, errb bytes.Buffer
	Init(&out, &errb)
	Printf("hello %s", "world")
	Errorf("bad %d", 1)
	if out.String() != "hello world" {
		t.Errorf("stdout = %q", out.String())
	}
	if errb.String() != "bad 1" {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestColorDisabledByNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	if colorAllowed(&bytes.Buffer{}) {
		t.Error("NO_COLOR must disable color")
	}
	if colorAllowed(nil) {
		t.Error("nil writer must disable color")
	}
}
