package scanner

import "testing"

func TestParseSeverity(t *testing.T) {
	for in, want := range map[string]Severity{"info": Info, "Warning": Warning, " CRITICAL ": Critical} {
		got, err := ParseSeverity(in)
		if err != nil || got != want {
			t.Errorf("%q -> %v, %v", in, got, err)
		}
	}
	if _, err := ParseSeverity("nope"); err == nil {
		t.Fatal("expected error")
	}
}
