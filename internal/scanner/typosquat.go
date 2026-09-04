package scanner

import (
	_ "embed"
	"strconv"
	"strings"
)

//go:embed popular_packages.txt
var popularPackagesRaw string

func popularPackages() []string {
	return strings.Split(strings.TrimSpace(popularPackagesRaw), "\n")
}

// levenshtein computes edit distance with the textbook DP approach.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			del := d[i-1][j] + 1
			ins := d[i][j-1] + 1
			sub := d[i-1][j-1] + cost
			d[i][j] = min3(del, ins, sub)
		}
	}
	return d[la][lb]
}

func min3(a, b, c int) int {
	m := a
	if b < m {
		m = b
	}
	if c < m {
		m = c
	}
	return m
}

func init() {
	Register(typosquatRule{})
}

type typosquatRule struct{}

func (typosquatRule) Name() string { return "typosquat" }

func (typosquatRule) Points() int { return 50 }

func (typosquatRule) Gate() bool { return false }

func (typosquatRule) Check(ctx *Context) []Finding {
	meta := ctx.Metadata
	if meta == nil {
		return nil
	}
	name := meta.Pkgbase
	var findings []Finding
	for _, popular := range popularPackages() {
		if name == popular {
			continue
		}
		dist := levenshtein(name, popular)
		if dist > 0 && dist <= 2 && len(popular) > 4 {
			findings = append(findings, Finding{
				Rule:     "typosquat",
				Severity: Warning,
				Message:  "Package name `" + name + "` is very close (edit distance " + strconv.Itoa(dist) + ") to the well-known package `" + popular + "`. Confirm this is genuinely a different project and not name squatting.",
			})
			break
		}
	}
	return findings
}
