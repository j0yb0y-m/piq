package pkgbuild

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// firstArrayWord returns the first element of the named top-level array
// assignment, for tests that need a *syntax.Word from a parsed file.
func firstArrayWord(t *testing.T, file *syntax.File, name string) *syntax.Word {
	t.Helper()
	var word *syntax.Word
	syntax.Walk(file, func(n syntax.Node) bool {
		if word != nil {
			return false
		}
		call, ok := n.(*syntax.CallExpr)
		if !ok {
			return true
		}
		for _, assign := range call.Assigns {
			if assign.Name != nil && assign.Name.Value == name && assign.Array != nil && len(assign.Array.Elems) > 0 {
				word = assign.Array.Elems[0].Value
				return false
			}
		}
		return true
	})
	if word == nil {
		t.Fatalf("no %s=() array in parsed file", name)
	}
	return word
}

func TestWordText(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"plain", `source=(foo.tar.gz)`, "foo.tar.gz"},
		{"double-quoted", `source=("$pkgname-$pkgver.tar.gz::https://e/x")`, "$pkgname-$pkgver.tar.gz::https://e/x"},
		{"single-quoted", `source=('literal $dollar')`, "literal $dollar"},
		{"braced-expansion", `source=("${pkgname}-x")`, "$pkgname-x"},
		{"mixed", `source=(foo-"$pkgver".tar.gz)`, "foo-$pkgver.tar.gz"},
		{"command-substitution", `source=("$(curl https://e/x)")`, ""},
		{"arithmetic", `source=("$((1+1))")`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse(strings.NewReader(c.src), "t")
			if err != nil {
				t.Fatal(err)
			}
			if got := WordText(firstArrayWord(t, p, "source")); got != c.want {
				t.Errorf("WordText(%s) = %q, want %q", c.src, got, c.want)
			}
		})
	}
}

func TestEffectiveCommand(t *testing.T) {
	cases := map[string]string{
		`sudo bash -c true`:     "bash",
		`doas env FOO=1 curl x`: "curl",
		`command -v foo`:        "command",
		`bash script.sh`:        "bash",
	}
	for src, want := range cases {
		p, err := Parse(strings.NewReader(src), "t")
		if err != nil {
			t.Fatal(err)
		}
		var got string
		syntax.Walk(p, func(n syntax.Node) bool {
			if c, ok := n.(*syntax.CallExpr); ok && got == "" {
				got = EffectiveCommand(c)
			}
			return got == ""
		})
		if got != want {
			t.Errorf("%q -> %q, want %q", src, got, want)
		}
	}
}
