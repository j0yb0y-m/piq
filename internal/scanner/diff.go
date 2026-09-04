package scanner

import (
	"strings"

	"github.com/aymanbagabas/go-udiff"
	"github.com/j0yb0y-m/piq/internal/pkgbuild"
)

// PKGBUILDDiff returns a unified diff between the last-reviewed and
// current PKGBUILD text, and separately, findings for any newly
// -introduced dangerous line (so an update that ADDS a `curl | bash`
// to a package you already trusted gets flagged loudly, not buried
// in a wall of unrelated diff noise).
func PKGBUILDDiff(oldSrc, newSrc string) (unified string, newFindings []Finding) {
	unified = udiff.Unified("PKGBUILD (previous)", "PKGBUILD (new)", oldSrc, newSrc)

	oldFile, errOld := pkgbuild.Parse(strings.NewReader(oldSrc), "old")
	newFile, errNew := pkgbuild.Parse(strings.NewReader(newSrc), "new")
	if errOld != nil || errNew != nil {
		return unified, nil
	}

	oldFindings := RunAll(&Context{AST: oldFile})
	newAllFindings := RunAll(&Context{AST: newFile})

	oldRules := map[string]bool{}
	for _, f := range oldFindings {
		oldRules[f.Rule] = true
	}
	for _, f := range newAllFindings {
		if !oldRules[f.Rule] {
			newFindings = append(newFindings, f)
		}
	}
	return unified, newFindings
}
