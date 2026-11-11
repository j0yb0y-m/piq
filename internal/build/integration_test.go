//go:build integration

package build

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const fixturePKGBUILD = `pkgname=piq-fixture
pkgver=1.0
pkgrel=1
pkgdesc="piq integration fixture"
arch=('any')
url="https://example.invalid/piq-fixture"
license=('MIT')

pkgver() {
  echo ran > "$LOGDEST/pkgver-marker"
  echo 1.1
}

prepare() {
  echo ran > "$LOGDEST/prepare-marker"
}

package() {
  install -Dm644 /dev/null "$pkgdir/usr/share/piq-fixture/hello"
}
`

func integrationLayout(t *testing.T) Layout {
	t.Helper()
	l, err := NewLayout(t.TempDir(), "piq-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.PackageDir, "PKGBUILD"), []byte(fixturePKGBUILD), 0o644); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestIntegrationFetchPreparesAndUpdatesVersion(t *testing.T) {
	if os.Getenv("PIQ_INTEGRATION") == "" {
		t.Skip("set PIQ_INTEGRATION=1")
	}
	l := integrationLayout(t)
	pkgbuildPath := filepath.Join(l.PackageDir, "PKGBUILD")

	if err := Fetch(l, Options{Stdout: os.Stdout, Stderr: os.Stderr}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(l.LogDest, "prepare-marker")); err != nil {
		t.Fatalf("prepare() did not run during fetch: %v", err)
	}
	if _, err := os.Stat(filepath.Join(l.LogDest, "pkgver-marker")); err != nil {
		t.Fatalf("pkgver() did not run during fetch: %v", err)
	}
	if got, err := os.ReadFile(pkgbuildPath); err != nil || string(got) != fixturePKGBUILD {
		t.Fatalf("fetch modified the reviewed PKGBUILD: err=%v", err)
	}
	staged, err := os.ReadFile(l.BuildFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(staged), "pkgver=1.1") {
		t.Fatalf("pkgver() did not update the staged build file:\n%s", staged)
	}
	if err := ValidateBuildFile(l, []byte(fixturePKGBUILD)); err != nil {
		t.Fatalf("validating staged PKGBUILD: %v", err)
	}
}

func TestIntegrationBuildUsesPreparedTree(t *testing.T) {
	if os.Getenv("PIQ_INTEGRATION") == "" {
		t.Skip("set PIQ_INTEGRATION=1")
	}
	l := integrationLayout(t)
	pkgbuildPath := filepath.Join(l.PackageDir, "PKGBUILD")

	if err := Fetch(l, Options{Stdout: os.Stdout, Stderr: os.Stderr}); err != nil {
		t.Fatal(err)
	}
	if err := Build(l, Options{Stdout: os.Stdout, Stderr: os.Stderr}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(pkgbuildPath); err != nil || string(got) != fixturePKGBUILD {
		t.Fatalf("build modified the reviewed PKGBUILD: err=%v", err)
	}
	arts, err := Artifacts(l)
	if err != nil || len(arts) != 1 {
		t.Fatalf("artifacts=%v err=%v", arts, err)
	}
	if !strings.Contains(filepath.Base(arts[0]), "piq-fixture-1.1-1") {
		t.Fatalf("build used the stale version: %s", arts[0])
	}
}

// initGitSource creates a small local git repository for a VCS source.
func initGitSource(t *testing.T, dir string) {
	t.Helper()
	runGit(t, "init", dir)
	runGit(t, "-C", dir, "config", "user.name", "piq test")
	runGit(t, "-C", dir, "config", "user.email", "piq@example.invalid")
	if err := os.WriteFile(filepath.Join(dir, "hello.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, "-C", dir, "add", "hello.txt")
	runGit(t, "-C", dir, "commit", "-m", "initial")
}

func runGit(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestIntegrationFetchBuildsVCSourceWithoutNetwork(t *testing.T) {
	if os.Getenv("PIQ_INTEGRATION") == "" {
		t.Skip("set PIQ_INTEGRATION=1")
	}
	cache := t.TempDir()
	l, err := NewLayout(cache, "piq-vcs-fixture")
	if err != nil {
		t.Fatal(err)
	}
	repo := filepath.Join(l.PackageDir, "upstream")
	initGitSource(t, repo)
	pkgbuild := fmt.Sprintf(`pkgname=piq-vcs-fixture
pkgver=1.0
pkgrel=1
pkgdesc="piq VCS integration fixture"
arch=('any')
url="https://example.invalid/piq-vcs-fixture"
license=('MIT')
source=("fixture::git+file://%s")
sha256sums=('SKIP')

pkgver() {
  echo 1.1
}

prepare() {
  echo ran > "$LOGDEST/prepare-marker"
}

package() {
  install -Dm644 /dev/null "$pkgdir/usr/share/piq-vcs-fixture/hello"
}
`, repo)
	if err := os.WriteFile(filepath.Join(l.PackageDir, "PKGBUILD"), []byte(pkgbuild), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Fetch(l, Options{Stdout: os.Stdout, Stderr: os.Stderr}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(l.LogDest, "prepare-marker")); err != nil {
		t.Fatalf("prepare() did not run during offline extraction: %v", err)
	}
	if err := ValidateBuildFile(l, []byte(pkgbuild)); err != nil {
		t.Fatal(err)
	}
	if err := Build(l, Options{Stdout: os.Stdout, Stderr: os.Stderr}); err != nil {
		t.Fatal(err)
	}
	arts, err := Artifacts(l)
	if err != nil || len(arts) != 1 {
		t.Fatalf("artifacts=%v err=%v", arts, err)
	}
	if !strings.Contains(filepath.Base(arts[0]), "piq-vcs-fixture-1.1-1") {
		t.Fatalf("unexpected artifact version: %s", arts[0])
	}
}
