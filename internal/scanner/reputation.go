package scanner

import (
	"time"
)

func init() {
	Register(reputationRule{})
}

type reputationRule struct{}

func (reputationRule) Name() string { return "reputation" }

func (reputationRule) Points() int { return 40 }

func (reputationRule) Gate() bool { return false }

func (reputationRule) Check(ctx *Context) []Finding {
	pkg := ctx.AURInfo
	if pkg == nil {
		return nil // e.g. scanning a purely-local PKGBUILD
	}
	var findings []Finding

	age := time.Since(time.Unix(pkg.FirstSubmitted, 0))
	brandNew := age < 30*24*time.Hour
	lowTrust := pkg.NumVotes < 3 && pkg.Popularity < 0.05

	if brandNew && lowTrust {
		findings = append(findings, Finding{
			Rule:     "reputation",
			Severity: Warning,
			Message:  "Package was first submitted less than 30 days ago and has almost no votes/popularity yet. New, obscure packages are the AUR's most common attack surface. Weigh this more heavily combined with anything else found.",
		})
	}

	if pkg.OutOfDate != nil {
		findings = append(findings, Finding{
			Rule:     "reputation",
			Severity: Info,
			Message:  "Flagged out-of-date on the AUR. Not a security issue by itself, but an unmaintained package is one nobody's actively reviewing either.",
		})
	}

	return findings
}
