package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestWriteIsPureJSON(t *testing.T) {
	var b bytes.Buffer
	err := Write(&b, Scan{SchemaVersion: SchemaVersion, Command: "scan", Package: "paru", Verdict: "OK"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b") {
		t.Fatal("ANSI in JSON")
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["schema_version"] != float64(1) {
		t.Fatalf("schema_version = %v", got["schema_version"])
	}
	if got["command"] != "scan" {
		t.Fatalf("command = %v", got["command"])
	}
}

func TestScanFindingsRoundTrip(t *testing.T) {
	var b bytes.Buffer
	err := Write(&b, Scan{
		SchemaVersion: SchemaVersion,
		Command:       "scan",
		Package:       "paru",
		Verdict:       "SUSPICIOUS",
		Findings: []Finding{{
			Rule:     "pipe-to-shell",
			Severity: "CRITICAL",
			File:     "PKGBUILD",
			Line:     7,
			Message:  "downloads and executes a remote script",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("findings = %v, want one", got.Findings)
	}
	f := got.Findings[0]
	if f["file"] != "PKGBUILD" {
		t.Fatalf("file = %v", f["file"])
	}
	if f["line"] != float64(7) {
		t.Fatalf("line = %v", f["line"])
	}
	if f["message"] != "downloads and executes a remote script" {
		t.Fatalf("message = %v", f["message"])
	}
}

func TestScanWithNoFindingsEncodesEmptyArray(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, Scan{SchemaVersion: SchemaVersion, Findings: []Finding{}}); err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if string(raw["findings"]) != "[]" {
		t.Fatalf("findings = %s, want []", raw["findings"])
	}
}

func TestWriteDoesNotEscapeHTML(t *testing.T) {
	var b bytes.Buffer
	err := Write(&b, Scan{
		SchemaVersion: SchemaVersion,
		Findings: []Finding{{
			Message: "<script> & \"quotes\"",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "<script> &") {
		t.Fatalf("HTML characters were escaped: %s", b.String())
	}
	if strings.Contains(b.String(), `\u003c`) || strings.Contains(b.String(), `\u0026`) {
		t.Fatalf("HTML escape sequence in output: %s", b.String())
	}
}
