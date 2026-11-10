package pkgbuild

import (
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

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
