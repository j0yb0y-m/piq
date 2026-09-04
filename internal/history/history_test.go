package history

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
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
