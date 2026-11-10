package scanner

import (
	"strings"

	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"github.com/morganamilo/go-srcinfo"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(srcinfoDivergenceRule{})
	Register(checksumCompletenessRule{})
}

// isVCSSource reports whether a source=() entry is fetched with a VCS
// scheme, where the commit pin replaces a content checksum.
func isVCSSource(src string) bool {
	return strings.Contains(src, "git+") || strings.Contains(src, "svn+") ||
		strings.Contains(src, "hg+") || strings.Contains(src, "bzr+")
}

// extractArrayLiteral walks the top-level statements of a parsed shell
// file looking for a bare array assignment like source=(foo bar).
func extractArrayLiteral(file *syntax.File, name string) []string {
	if file == nil {
		return nil
	}
	for _, stmt := range file.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) > 0 {
			continue
		}
		for _, assign := range call.Assigns {
			if assign.Name == nil || assign.Name.Value != name {
				continue
			}
			if assign.Array == nil {
				continue
			}
			var elems []string
			for _, elem := range assign.Array.Elems {
				if elem.Value != nil {
					elems = append(elems, pkgbuild.WordText(elem.Value))
				}
			}
			return elems
		}
	}
	return nil
}

// containsSource reports whether a source string exists in metadata.
func containsSource(meta *pkgbuild.Metadata, src string) bool {
	for _, s := range meta.Source {
		if s.Value == src {
			return true
		}
	}
	return false
}

// checksumFor returns the SHA256 checksum at the given index. To
// check other algorithms, use checksumsAt (returning the strongest
// available sum for a source index).
func checksumFor(meta *pkgbuild.Metadata, i int) string {
	if i < len(meta.SHA256Sums) {
		return meta.SHA256Sums[i].Value
	}
	return ""
}

// strongestSum returns the strongest non-empty checksum available for
// source index i, preferring b2 > sha512 > sha384 > sha256 > sha1 >
// md5. Returns "" if none are set.
func strongestSum(meta *pkgbuild.Metadata, i int) string {
	tiers := []struct {
		sums []srcinfo.ArchString
	}{
		{meta.B2Sums}, {meta.SHA512Sums}, {meta.SHA384Sums}, {meta.SHA256Sums},
		{meta.SHA224Sums}, {meta.SHA1Sums}, {meta.MD5Sums},
	}
	for _, tier := range tiers {
		if i < len(tier.sums) && tier.sums[i].Value != "" && tier.sums[i].Value != "SKIP" {
			return tier.sums[i].Value
		}
	}
	return ""
}

// weakSum algorithm detection: returns true if the strongest checksum
// present for the source is MD5 or SHA1 (considered weak).
func weakSum(meta *pkgbuild.Metadata, i int) (weak bool, algo string) {
	pairs := []struct {
		sums []srcinfo.ArchString
		algo string
	}{
		{meta.B2Sums, ""}, {meta.SHA512Sums, ""}, {meta.SHA384Sums, ""},
		{meta.SHA256Sums, ""}, {meta.SHA224Sums, ""}, {meta.SHA1Sums, "sha1"},
		{meta.MD5Sums, "md5"},
	}
	for _, p := range pairs {
		if i < len(p.sums) && p.sums[i].Value != "" && p.sums[i].Value != "SKIP" {
			return p.algo != "", p.algo
		}
	}
	return false, ""
}

type srcinfoDivergenceRule struct{}

func (srcinfoDivergenceRule) Name() string { return "srcinfo-divergence" }

func (srcinfoDivergenceRule) Points() int { return 95 }

func (srcinfoDivergenceRule) Gate() bool { return false }

func (srcinfoDivergenceRule) Check(ctx *Context) []Finding {
	meta := ctx.Metadata
	if meta == nil || ctx.AST == nil {
		return nil
	}
	var findings []Finding
	pkgbuildSources := extractArrayLiteral(ctx.AST, "source")
	for _, s := range pkgbuildSources {
		if s == "" {
			// WordText reports non-literal words (command substitution,
			// arithmetic) as empty; there is nothing safe to compare.
			continue
		}
		expanded, ok := expandPkgVars(s, meta)
		if !ok {
			// A source we cannot fully resolve is not evidence of
			// divergence; skip it rather than guess.
			continue
		}
		if !containsSource(meta, expanded) {
			findings = append(findings, Finding{
				Rule:     "srcinfo-divergence",
				Severity: Critical,
				Message:  "PKGBUILD declares source `" + expanded + "`, but .SRCINFO does not list it. Either the maintainer forgot to regenerate .SRCINFO, or the two were deliberately made to disagree. Review the actual PKGBUILD text.",
			})
		}
	}
	return findings
}

// expandPkgVars resolves the standard version variables in a PKGBUILD
// source string so it can be compared against .SRCINFO, which stores
// the already-expanded value. It reports false when a variable is
// unknown or malformed, leaving the caller to skip the comparison.
func expandPkgVars(s string, meta *srcinfo.Srcinfo) (string, bool) {
	if meta == nil {
		return "", false
	}
	pkgname := meta.Pkgname
	if pkgname == "" {
		pkgname = meta.Pkgbase
	}
	values := map[string]string{
		"pkgbase": meta.Pkgbase,
		"pkgname": pkgname,
		"pkgver":  meta.Pkgver,
		"pkgrel":  meta.Pkgrel,
		"epoch":   meta.Epoch,
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '$' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i + 1
		var name string
		if j < len(s) && s[j] == '{' {
			end := strings.IndexByte(s[j:], '}')
			if end < 0 {
				return "", false
			}
			name = s[j+1 : j+end]
			j += end + 1
		} else {
			start := j
			for j < len(s) && (s[j] == '_' ||
				s[j] >= 'a' && s[j] <= 'z' ||
				s[j] >= 'A' && s[j] <= 'Z' ||
				j > start && s[j] >= '0' && s[j] <= '9') {
				j++
			}
			name = s[start:j]
			if name == "" {
				return "", false
			}
		}
		val, ok := values[name]
		if !ok {
			return "", false
		}
		b.WriteString(val)
		i = j
	}
	return b.String(), true
}

// checksumCompletenessRule flags sources that ship without any usable
// checksum, or rely on a weak algorithm (MD5/SHA1). This is the
// integrity backbone of the whole AUR trust model.
type checksumCompletenessRule struct{}

func (checksumCompletenessRule) Name() string { return "checksum-completeness" }

func (checksumCompletenessRule) Points() int { return 60 }

func (checksumCompletenessRule) Gate() bool { return false }

func (checksumCompletenessRule) Check(ctx *Context) []Finding {
	meta := ctx.Metadata
	if meta == nil {
		return nil
	}
	var findings []Finding
	seen := map[string]bool{}
	for i, src := range meta.Source {
		if seen[src.Value] {
			continue
		}
		seen[src.Value] = true

		if isVCSSource(src.Value) {
			continue // VCS sources are pinned by commit, not checksum
		}

		if weakest := strongestSum(meta, i); weakest != "" {
			if weak, algo := weakSum(meta, i); weak {
				findings = append(findings, Finding{
					Rule:     "checksum-completeness",
					Severity: Warning,
					Message:  "Source `" + src.Value + "` is verified only with the weak `" + algo + "` algorithm. Prefer sha256/blake2b to survive collision attacks.",
				})
			}
			continue
		}

		switch sum := checksumFor(meta, i); sum {
		case "SKIP":
			findings = append(findings, Finding{
				Rule:     "checksum-completeness",
				Severity: Warning,
				Message:  "Source `" + src.Value + "` has its strongest checksum set to `SKIP`. SKIP is normal for VCS sources (git/svn/hg are pinned by commit), but on a plain tarball it disables integrity verification entirely — the fetched content is never checked.",
			})
		case "":
			findings = append(findings, Finding{
				Rule:     "checksum-completeness",
				Severity: Warning,
				Message:  "Source `" + src.Value + "` has no real checksum (`" + quoteOrEmpty(sum) + "`). Content is fetched with zero integrity verification — the single biggest integrity risk in AUR packages.",
			})
		}
	}
	return findings
}

func quoteOrEmpty(s string) string {
	if s == "" {
		return "<none>"
	}
	return s
}
