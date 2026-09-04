package scanner

import (
	"strconv"
	"time"

	"github.com/j0yb0y-m/piq/internal/history"
)

func init() {
	Register(maintainerChangeRule{})
	Register(recentCommitsRule{})
	Register(authorDriftRule{})
}

func provOf(ctx *Context) *history.Provenance {
	if p, ok := ctx.History.(*history.Provenance); ok {
		return p
	}
	return nil
}

// maintainerChangeRule flags repos where the committer(s) differ from
// the current maintainer — i.e. the package changed hands recently,
// which is exactly how takeovers of abandoned packages get shipped.
type maintainerChangeRule struct{}

func (maintainerChangeRule) Name() string { return "maintainer-change" }

func (maintainerChangeRule) Points() int { return 65 }

func (maintainerChangeRule) Gate() bool { return false }

func (maintainerChangeRule) Check(ctx *Context) []Finding {
	p := provOf(ctx)
	if p == nil || p.AuthorChanged() == nil {
		return nil
	}
	if len(p.AuthorChanged()) == 0 {
		return nil
	}
	return []Finding{{
		Rule:     "maintainer-change",
		Severity: Warning,
		Message:  "Package history shows commits from maintainer(s) other than the current one (" + joinStr(p.AuthorChanged()) + "). If this project recently changed hands, treat the modern history with extra caution — abandoned-package takeovers are a leading AUR attack vector.",
	}}
}

func joinStr(ss []string) string {
	out := ""
	for i, s := range ss {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}

// recentCommitsRule flags packages whose newest commit is very fresh —
// a loud signal combined with anything else, innocent on its own.
type recentCommitsRule struct{}

func (recentCommitsRule) Name() string { return "recent-commits" }

func (recentCommitsRule) Points() int { return 25 }

func (recentCommitsRule) Gate() bool { return false }

func (recentCommitsRule) Check(ctx *Context) []Finding {
	p := provOf(ctx)
	if p == nil || p.NewestCommit.IsZero() {
		return nil
	}
	if time.Since(p.NewestCommit) < 7*24*time.Hour && p.CommitCount > 1 {
		return []Finding{{
			Rule:     "recent-commits",
			Severity: Info,
			Message:  "Package had a commit within the last 7 days and has more than one commit in its history. Recent churn on a small package warrants a look at what changed.",
		}}
	}
	return nil
}

// authorDriftRule flags the specific takeover pattern: the current
// maintainer has authored very few commits relative to the whole
// history, i.e. the maintainer identity is newer than the code.
type authorDriftRule struct{}

func (authorDriftRule) Name() string { return "maintainer-drift" }

func (authorDriftRule) Points() int { return 50 }

func (authorDriftRule) Gate() bool { return false }

func (authorDriftRule) Check(ctx *Context) []Finding {
	p := provOf(ctx)
	if p == nil {
		return nil
	}
	total := p.CommitCount
	if total < 3 {
		return nil
	}
	mainCount := p.Committers[p.Maintainer]
	if mainCount < total/3 {
		return []Finding{{
			Rule:     "maintainer-drift",
			Severity: Warning,
			Message:  "The current maintainer has authored only " + strconv.Itoa(mainCount) + " of " + strconv.Itoa(total) + " commits. The maintainer identity appears newer than most of the code — a takeover/abandonment pattern worth reviewing before trusting.",
		}}
	}
	return nil
}
