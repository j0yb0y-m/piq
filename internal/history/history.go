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
	Maintainer   string         // primary/current maintainer email (mode)
	RecentLog    []LogEntry     // most recent commits, newest first
	NewestCommit time.Time
	OldestCommit time.Time
}

// LogEntry is a single history entry.
type LogEntry struct {
	Hash    string
	Author  string // name <email>
	Message string
	When    time.Time
}

// Inspect walks the local clone at repoDir and produces a Provenance.
func Inspect(repoDir string) (*Provenance, error) {
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
	iter, err := repo.Log(&git.LogOptions{From: head.Hash()})
	if err != nil {
		return nil, err
	}

	prov := &Provenance{RepoPath: repoDir, Committers: map[string]int{}}
	var firstCommitTime time.Time
	err = iter.ForEach(func(c *object.Commit) error {
		if prov.NewestCommit.IsZero() {
			prov.NewestCommit = c.Author.When
		}
		firstCommitTime = c.Author.When
		prov.CommitCount++
		email := c.Author.Email
		prov.Committers[email]++
		prov.RecentLog = append(prov.RecentLog, LogEntry{
			Hash:    c.Hash.String()[:8],
			Author:  c.Author.Name + " <" + c.Author.Email + ">",
			Message: firstLine(c.Message),
			When:    c.Author.When,
		})
		return nil
	})
	iter.Close()
	if err != nil {
		return nil, err
	}

	prov.OldestCommit = firstCommitTime
	if len(prov.RecentLog) > 20 {
		prov.RecentLog = prov.RecentLog[:20]
	}

	// maintainer = committer with the most commits (the AUR sets the
	// committer to the current maintainer on every push).
	prov.Maintainer = mode(prov.Committers)
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

func mode(counts map[string]int) string {
	best, n := "", -1
	for email, c := range counts {
		if c > n {
			best, n = email, c
		}
	}
	return best
}

// AuthorChanged returns the set of emails that have committed but are
// different from the current maintainer, i.e. who held the repo before
// it (apparently) moved hands.
func (p *Provenance) AuthorChanged() []string {
	var diff []string
	for email := range p.Committers {
		if email != p.Maintainer {
			diff = append(diff, email)
		}
	}
	return diff
}
