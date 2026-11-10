// Package history inspects a package's git history for provenance
// signals: sudden changes in committer identity (a classic sign the
// AUR maintainer was taken over), brand-new commits, and authorship
// that never matches the current maintainer. These are strong, cheap
// indicators that are invisible to a static scan of the current file.
package history

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// Provenance summarizes the git history of a package repo.
type Provenance struct {
	RepoPath     string
	CommitCount  int
	Committers   map[string]int // email -> number of commits
	Maintainer   string         // committer email of HEAD
	RecentLog    []LogEntry     // most recent commits, newest first
	NewestCommit time.Time
	OldestCommit time.Time

	HeadHash             string    // full hash of HEAD
	HeadCommitter        string    // committer email of HEAD
	PreviousCommitter    string    // first committer after HEAD that differs from HeadCommitter
	HeadCommittedAt      time.Time // committer timestamp of HEAD
	HeadCommitterFirstAt time.Time // oldest committer timestamp for HeadCommitter in the walked window
}

// LogEntry is a single history entry.
type LogEntry struct {
	Hash      string
	Author    string // name <email>
	Committer string // name <email>
	Message   string
	When      time.Time
}

// Inspect walks the local clone at repoDir and produces a Provenance.
func Inspect(repoDir string) (*Provenance, error) {
	return inspect(repoDir, 500, 5*365*24*time.Hour)
}

// errStopWalk lets the commit walk stop cleanly once a bound is reached.
var errStopWalk = errors.New("stop history walk")

// inspect walks at most maxCommits commits and, after recording HEAD, stops
// before the first commit older than maxAge. A non-positive bound disables
// it. The commit that trips either bound is not included; HEAD itself is
// always recorded.
func inspect(repoDir string, maxCommits int, maxAge time.Duration) (*Provenance, error) {
	repo, err := git.PlainOpen(repoDir)
	if err != nil {
		if errors.Is(err, git.ErrRepositoryNotExists) {
			return nil, fmt.Errorf("no git repo at %q: %w", repoDir, err)
		}
		return nil, err
	}

	head, err := repo.Head()
	if err != nil {
		return nil, err
	}
	iter, err := repo.Log(&git.LogOptions{From: head.Hash(), Order: git.LogOrderCommitterTime})
	if err != nil {
		return nil, err
	}

	prov := &Provenance{RepoPath: repoDir, Committers: map[string]int{}}
	var lastCommitTime time.Time
	err = iter.ForEach(func(c *object.Commit) error {
		committedAt := c.Committer.When
		// HEAD is always recorded so callers can identify the repo even
		// when its newest commit predates the age bound.
		if prov.CommitCount > 0 && maxAge > 0 && time.Since(committedAt) > maxAge {
			return errStopWalk
		}
		if prov.CommitCount == 0 {
			prov.HeadHash = c.Hash.String()
			prov.HeadCommitter = c.Committer.Email
			prov.HeadCommittedAt = committedAt
			prov.NewestCommit = committedAt
		} else if prov.PreviousCommitter == "" && c.Committer.Email != prov.HeadCommitter {
			prov.PreviousCommitter = c.Committer.Email
		}
		if c.Committer.Email == prov.HeadCommitter {
			// The walk is newest-first, so every match overwrites the
			// previous one: the last assignment is the oldest commit by
			// the current committer in the walked window.
			prov.HeadCommitterFirstAt = committedAt
		}
		lastCommitTime = committedAt
		prov.CommitCount++
		prov.Committers[c.Committer.Email]++
		prov.RecentLog = append(prov.RecentLog, LogEntry{
			Hash:      c.Hash.String()[:8],
			Author:    c.Author.Name + " <" + c.Author.Email + ">",
			Committer: c.Committer.Name + " <" + c.Committer.Email + ">",
			Message:   firstLine(c.Message),
			When:      committedAt,
		})
		if maxCommits > 0 && prov.CommitCount >= maxCommits {
			return errStopWalk
		}
		return nil
	})
	iter.Close()
	if err != nil && !errors.Is(err, errStopWalk) {
		return nil, err
	}

	prov.OldestCommit = lastCommitTime
	if len(prov.RecentLog) > 20 {
		prov.RecentLog = prov.RecentLog[:20]
	}

	// The AUR sets the committer to the current maintainer on every push,
	// so the HEAD committer is who holds the package now.
	prov.Maintainer = prov.HeadCommitter
	return prov, nil
}

func firstLine(s string) string {
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			return s[:i]
		}
	}
	return s
}

// AuthorChanged returns the set of committer emails other than the current
// maintainer, i.e. who held the repo before it (apparently) moved hands.
func (p *Provenance) AuthorChanged() []string {
	var diff []string
	for email := range p.Committers {
		if email != p.Maintainer {
			diff = append(diff, email)
		}
	}
	return diff
}
