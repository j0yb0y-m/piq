package scanner

import "testing"

func TestUndeclaredFetchIgnoresLockedFetch(t *testing.T) {
	if f := findingsFor(undeclaredFetchRule{}.Check(parseContext(t, `cargo fetch --locked`)), "undeclared-fetch"); len(f) != 0 {
		t.Fatalf("cargo fetch flagged: %v", f)
	}
	if f := findingsFor(undeclaredFetchRule{}.Check(parseContext(t, `npm install atomic-lockfile`)), "undeclared-fetch"); len(f) == 0 {
		t.Fatal("expected npm install finding")
	}
}

func TestUndeclaredFetchSubcommands(t *testing.T) {
	skipped := []string{
		`cargo fetch --locked`,
		`go mod download`,
		`npm ci`,
		`pip download foo`,
		`yarn fetch`,
	}
	for _, src := range skipped {
		if f := findingsFor(undeclaredFetchRule{}.Check(parseContext(t, src)), "undeclared-fetch"); len(f) != 0 {
			t.Errorf("%q flagged: %v", src, f)
		}
	}

	flagged := []string{
		`npm install atomic-lockfile`,
		`bun add js-digest`,
		`pip install foo`,
		`pip3 i foo`,
		`go get github.com/evil/x`,
		`yarn add left-pad`,
	}
	for _, src := range flagged {
		if f := findingsFor(undeclaredFetchRule{}.Check(parseContext(t, src)), "undeclared-fetch"); len(f) == 0 {
			t.Errorf("%q missed", src)
		}
	}
}

func TestUndeclaredFetchGuardsShortArgs(t *testing.T) {
	for _, src := range []string{`cargo`, `npm`, `go`} {
		if f := findingsFor(undeclaredFetchRule{}.Check(parseContext(t, src)), "undeclared-fetch"); len(f) != 0 {
			t.Errorf("%q flagged with no subcommand: %v", src, f)
		}
	}
}
