package history

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test Author",
			"GIT_AUTHOR_EMAIL=author@test.com",
			"GIT_COMMITTER_NAME=Test Committer",
			"GIT_COMMITTER_EMAIL=committer@test.com",
			"GIT_TERMINAL_PROMPT=0",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}

	git("init")
	git("config", "user.name", "Test User")
	git("config", "user.email", "test@test.com")

	// first commit
	os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=test\npkgver=1.0"), 0o644)
	git("add", ".")
	git("commit", "-m", "initial commit")

	// second commit
	os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=test\npkgver=1.1"), 0o644)
	git("add", ".")
	git("commit", "-m", "bump version")

	return dir
}

func TestInspect(t *testing.T) {
	dir := setupTestRepo(t)
	prov, err := Inspect(dir)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if prov.CommitCount != 2 {
		t.Errorf("expected 2 commits, got %d", prov.CommitCount)
	}
	if prov.Maintainer == "" {
		t.Error("expected non-empty maintainer")
	}
	if prov.NewestCommit.IsZero() {
		t.Error("expected non-zero newest commit time")
	}
	if prov.OldestCommit.IsZero() {
		t.Error("expected non-zero oldest commit time")
	}
	if len(prov.RecentLog) != 2 {
		t.Errorf("expected 2 log entries, got %d", len(prov.RecentLog))
	}
}

func TestInspectNonexistent(t *testing.T) {
	_, err := Inspect("/nonexistent/path")
	if err == nil {
		t.Error("expected error for nonexistent repo")
	}
}

func TestAuthorChanged(t *testing.T) {
	dir := setupTestRepo(t)
	prov, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Same author and committer — no change
	if len(prov.AuthorChanged()) != 0 {
		t.Errorf("expected no author changes, got %v", prov.AuthorChanged())
	}
}

func TestCommitterCounts(t *testing.T) {
	dir := setupTestRepo(t)
	prov, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Both commits should have the same committer
	total := 0
	for _, count := range prov.Committers {
		total += count
	}
	if total != 2 {
		t.Errorf("expected 2 total commits, got %d", total)
	}
}

// gitEnv runs git in dir with extra environment variables, failing the test
// on a non-zero exit.
func gitEnv(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), append(env, "GIT_TERMINAL_PROMPT=0")...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func initTestRepo(t *testing.T, dir string) {
	t.Helper()
	gitEnv(t, dir, nil, "init")
	gitEnv(t, dir, nil, "config", "user.name", "Test User")
	gitEnv(t, dir, nil, "config", "user.email", "test@test.com")
}

func commitFile(t *testing.T, dir string, env []string, name, content, msg string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	gitEnv(t, dir, env, "add", ".")
	gitEnv(t, dir, env, "commit", "-m", msg)
}

// setupRepoWithDifferentAuthorAndCommitter creates a repo whose author and
// committer identities are deliberately different, like an AUR package where
// the patch author is not the current maintainer.
func setupRepoWithDifferentAuthorAndCommitter(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	initTestRepo(t, dir)
	commitFile(t, dir, []string{
		"GIT_AUTHOR_NAME=Test Author",
		"GIT_AUTHOR_EMAIL=author@test.com",
		"GIT_COMMITTER_NAME=Test Committer",
		"GIT_COMMITTER_EMAIL=committer@test.com",
	}, "PKGBUILD", "pkgname=test\npkgver=1.0", "initial commit")
	return dir
}

// setupRepoWithTwoCommitters creates a repo with two commits by different
// committers, newest commit by bob@test.com. Dates are recent so the default
// age bound does not exclude them.
func setupRepoWithTwoCommitters(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	initTestRepo(t, dir)
	old := time.Now().Add(-2 * time.Hour).UTC().Format("2006-01-02T15:04:05+0000")
	recent := time.Now().Add(-1 * time.Hour).UTC().Format("2006-01-02T15:04:05+0000")
	commitFile(t, dir, []string{
		"GIT_AUTHOR_NAME=Alice",
		"GIT_AUTHOR_EMAIL=author-alice@test.com",
		"GIT_COMMITTER_NAME=Alice",
		"GIT_COMMITTER_EMAIL=alice@test.com",
		"GIT_AUTHOR_DATE=" + old,
		"GIT_COMMITTER_DATE=" + old,
	}, "PKGBUILD", "pkgname=test\npkgver=1.0", "initial commit")
	commitFile(t, dir, []string{
		"GIT_AUTHOR_NAME=Bob",
		"GIT_AUTHOR_EMAIL=author-bob@test.com",
		"GIT_COMMITTER_NAME=Bob",
		"GIT_COMMITTER_EMAIL=bob@test.com",
		"GIT_AUTHOR_DATE=" + recent,
		"GIT_COMMITTER_DATE=" + recent,
	}, "PKGBUILD", "pkgname=test\npkgver=2.0", "bump version")
	return dir
}

// setupRepoWithOldCommit creates a two-commit repo where the first commit is
// far older than the age bound.
func setupRepoWithOldCommit(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	initTestRepo(t, dir)
	commitFile(t, dir, []string{
		"GIT_AUTHOR_NAME=Test Author",
		"GIT_AUTHOR_EMAIL=author@test.com",
		"GIT_COMMITTER_NAME=Test Committer",
		"GIT_COMMITTER_EMAIL=committer@test.com",
		"GIT_AUTHOR_DATE=2010-01-01T00:00:00+0000",
		"GIT_COMMITTER_DATE=2010-01-01T00:00:00+0000",
	}, "PKGBUILD", "pkgname=test\npkgver=1.0", "initial commit")
	now := time.Now().UTC().Format("2006-01-02T15:04:05-0700")
	commitFile(t, dir, []string{
		"GIT_AUTHOR_NAME=Test Author",
		"GIT_AUTHOR_EMAIL=author@test.com",
		"GIT_COMMITTER_NAME=Test Committer",
		"GIT_COMMITTER_EMAIL=committer@test.com",
		"GIT_AUTHOR_DATE=" + now,
		"GIT_COMMITTER_DATE=" + now,
	}, "PKGBUILD", "pkgname=test\npkgver=1.1", "bump version")
	return dir
}

func TestInspectUsesCommitterNotAuthor(t *testing.T) {
	dir := setupRepoWithDifferentAuthorAndCommitter(t)
	p, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p.Maintainer != "committer@test.com" {
		t.Fatalf("Maintainer = %q, want committer@test.com", p.Maintainer)
	}
}

func TestInspectBounded(t *testing.T) {
	dir := setupTestRepo(t) // 2 commits
	p, err := inspect(dir, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.CommitCount != 1 {
		t.Fatalf("CommitCount = %d, want 1", p.CommitCount)
	}
}

func TestInspectMaxAge(t *testing.T) {
	dir := setupRepoWithOldCommit(t)
	p, err := inspect(dir, 0, 5*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if p.CommitCount != 1 {
		t.Fatalf("CommitCount = %d, want 1 (old commit must not be included)", p.CommitCount)
	}
	if p.OldestCommit.IsZero() || time.Since(p.OldestCommit) > 24*time.Hour {
		t.Fatalf("OldestCommit = %v, want the recent commit", p.OldestCommit)
	}
}

func TestHeadCommitterTracked(t *testing.T) {
	dir := setupRepoWithTwoCommitters(t)
	p, _ := Inspect(dir)
	if p.HeadHash == "" {
		t.Fatal("expected a head commit hash")
	}
	if p.HeadCommitter == "" || p.PreviousCommitter == "" {
		t.Fatal("expected head and previous committers")
	}
}

func TestHeadProvenanceFields(t *testing.T) {
	dir := setupRepoWithTwoCommitters(t)
	p, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := gitEnv(t, dir, nil, "rev-parse", "HEAD")
	if p.HeadHash != wantHash {
		t.Errorf("HeadHash = %q, want %q", p.HeadHash, wantHash)
	}
	if p.HeadCommitter != "bob@test.com" {
		t.Errorf("HeadCommitter = %q, want bob@test.com", p.HeadCommitter)
	}
	if p.PreviousCommitter != "alice@test.com" {
		t.Errorf("PreviousCommitter = %q, want alice@test.com", p.PreviousCommitter)
	}
	if p.Maintainer != p.HeadCommitter {
		t.Errorf("Maintainer = %q, want head committer %q", p.Maintainer, p.HeadCommitter)
	}
	if p.HeadCommittedAt.IsZero() || !p.HeadCommittedAt.Equal(p.NewestCommit) {
		t.Errorf("HeadCommittedAt = %v, NewestCommit = %v, want equal and non-zero", p.HeadCommittedAt, p.NewestCommit)
	}
}

func TestLogEntryRecordsCommitter(t *testing.T) {
	dir := setupRepoWithDifferentAuthorAndCommitter(t)
	p, err := Inspect(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.RecentLog) != 1 {
		t.Fatalf("RecentLog length = %d, want 1", len(p.RecentLog))
	}
	e := p.RecentLog[0]
	if e.Author != "Test Author <author@test.com>" {
		t.Errorf("Author = %q, want Test Author <author@test.com>", e.Author)
	}
	if e.Committer != "Test Committer <committer@test.com>" {
		t.Errorf("Committer = %q, want Test Committer <committer@test.com>", e.Committer)
	}
}

// setupRepoWithOldHead creates a repo whose only commit is older than any
// sane age bound.
func setupRepoWithOldHead(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	initTestRepo(t, dir)
	commitFile(t, dir, []string{
		"GIT_AUTHOR_NAME=Old Author",
		"GIT_AUTHOR_EMAIL=old-author@test.com",
		"GIT_COMMITTER_NAME=Old Committer",
		"GIT_COMMITTER_EMAIL=old-committer@test.com",
		"GIT_AUTHOR_DATE=2010-01-01T00:00:00+0000",
		"GIT_COMMITTER_DATE=2010-01-01T00:00:00+0000",
	}, "PKGBUILD", "pkgname=test\npkgver=1.0", "initial commit")
	return dir
}

func TestInspectOldHeadStillExposed(t *testing.T) {
	dir := setupRepoWithOldHead(t)
	p, err := inspect(dir, 0, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if p.HeadHash == "" {
		t.Error("expected HeadHash for an old HEAD")
	}
	if p.HeadCommitter == "" {
		t.Error("expected HeadCommitter for an old HEAD")
	}
	if p.CommitCount != 1 {
		t.Errorf("CommitCount = %d, want 1", p.CommitCount)
	}
	if p.Maintainer == "" {
		t.Error("expected non-empty Maintainer for an old HEAD")
	}
}
