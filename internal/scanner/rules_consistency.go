package scanner

import (
	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"github.com/morganamilo/go-srcinfo"
	"mvdan.cc/sh/v3/syntax"
)

func init() {
	Register(skippedChecksumRule{})
	Register(srcinfoDivergenceRule{})
	Register(checksumCompletenessRule{})
}

type skippedChecksumRule struct{}

func (skippedChecksumRule) Name() string { return "skipped-checksum" }

func (skippedChecksumRule) Points() int { return 50 }

func (skippedChecksumRule) Gate() bool { return false }

func (skippedChecksumRule) Check(ctx *Context) []Finding {
	meta := ctx.Metadata
	if meta == nil {
		return nil
	}
	var findings []Finding
	for i, src := range meta.Source {
		isVCS := containsAny(src.Value, "git+", "svn+", "hg+", "bzr+")
		sum := checksumFor(meta, i)
		if sum == "SKIP" && !isVCS {
			findings = append(findings, Finding{
				Rule:     "skipped-checksum",
				Severity: Warning,
				Message:  "Checksum for `" + src.Value + "` is set to SKIP on a non-VCS source. SKIP is normal for git/svn/hg (pinned by commit), but on a plain tarball it disables integrity verification entirely.",
			})
		}
	}
	return findings
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(s) >= len(sub) && (s[:len(sub)] == sub || indexOf(s, sub)) {
			return true
		}
	}
	return false
}

func indexOf(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
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
					elems = append(elems, pkgbuild.Render(elem.Value))
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
		if !containsSource(meta, s) {
			findings = append(findings, Finding{
				Rule:     "srcinfo-divergence",
				Severity: Critical,
				Message:  "PKGBUILD declares source `" + s + "`, but .SRCINFO does not list it. Either the maintainer forgot to regenerate .SRCINFO, or the two were deliberately made to disagree. Review the actual PKGBUILD text.",
			})
		}
	}
	return findings
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

		isVCS := containsAny(src.Value, "git+", "svn+", "hg+", "bzr+")
		if isVCS {
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

		if sum := checksumFor(meta, i); sum == "" || sum == "SKIP" {
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
