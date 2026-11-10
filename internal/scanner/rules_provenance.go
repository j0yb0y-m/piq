package scanner

import (
	"strconv"
	"time"

	"github.com/j0yb0y-m/piq/internal/history"
)

func init() {
	Register(maintainerChangeRule{})
	Register(recentCommitsRule{})
	Register(maintainerDriftRule{})
}

func provOf(ctx *Context) *history.Provenance {
	if p, ok := ctx.History.(*history.Provenance); ok {
		return p
	}
	return nil
}

// provenanceWindow bounds how recent a handover or drift signal must be.
// A real takeover is interesting right after it happens; the same shape
// in ancient history is normal project churn.
const provenanceWindow = 180 * 24 * time.Hour

// maintainerChangeRule flags a recent handover: HEAD's committer
// differs from the previous distinct committer and HEAD is fresh.
// Abandoned-package takeovers are a leading AUR attack vector.
type maintainerChangeRule struct{}

func (maintainerChangeRule) Name() string { return "maintainer-change" }

func (maintainerChangeRule) Points() int { return 65 }

func (maintainerChangeRule) Gate() bool { return false }

func (maintainerChangeRule) Check(ctx *Context) []Finding {
	p := provOf(ctx)
	if p == nil || p.HeadCommitter == "" || p.PreviousCommitter == "" {
		return nil
	}
	if p.HeadCommitter == p.PreviousCommitter {
		return nil
	}
	if p.HeadCommittedAt.IsZero() || time.Since(p.HeadCommittedAt) >= provenanceWindow {
		return nil
	}
	return []Finding{{
		Rule:     "maintainer-change",
		Severity: Warning,
		Message:  "Package history shows a recent committer change from " + p.PreviousCommitter + " to " + p.HeadCommitter + " within the last 180 days. Abandoned-package takeovers are a leading AUR attack vector; review what changed at and after the handover.",
	}}
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

// maintainerDriftRule flags the specific takeover pattern: the head
// committer has committed very few of the commits relative to the whole
// history, i.e. the maintainer identity is newer than the code. Only a
// recent head commit makes this interesting.
type maintainerDriftRule struct{}

func (maintainerDriftRule) Name() string { return "maintainer-drift" }

func (maintainerDriftRule) Points() int { return 50 }

func (maintainerDriftRule) Gate() bool { return false }

func (maintainerDriftRule) Check(ctx *Context) []Finding {
	p := provOf(ctx)
	if p == nil || p.HeadCommitter == "" || p.CommitCount <= 0 {
		return nil
	}
	if p.HeadCommittedAt.IsZero() || time.Since(p.HeadCommittedAt) >= provenanceWindow {
		return nil
	}
	count := p.Committers[p.HeadCommitter]
	if count*10 >= p.CommitCount {
		return nil
	}
	return []Finding{{
		Rule:     "maintainer-drift",
		Severity: Warning,
		Message:  "The current maintainer (" + p.HeadCommitter + ") has committed only " + strconv.Itoa(count) + " of " + strconv.Itoa(p.CommitCount) + " commits. The maintainer identity appears newer than most of the code — a takeover/abandonment pattern worth reviewing before trusting.",
	}}
}
