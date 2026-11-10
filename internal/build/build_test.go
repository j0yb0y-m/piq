package build

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testLayout() Layout {
	return Layout{
		Pkgbase:    "hello",
		PackageDir: "/cache/hello",
		SrcDest:    "/cache/srcdest",
		BuildRoot:  "/cache/build",
		PkgDest:    "/cache/pkg",
		LogDest:    "/cache/logs",
	}
}

// hasPair reports whether args contains flag immediately followed by value.
func hasPair(args []string, flag, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag && args[i+1] == value {
			return true
		}
	}
	return false
}

func TestBwrapArgsChdirIsPackageDir(t *testing.T) {
	l := testLayout()
	args := bwrapArgs(l, "build")
	if !hasPair(args, "--chdir", l.PackageDir) {
		t.Fatalf("wrong chdir: %s", strings.Join(args, " "))
	}
	if hasPair(args, "--chdir", l.SrcDir()) {
		t.Fatalf("chdir points at srcdir: %s", strings.Join(args, " "))
	}
}

func TestBwrapArgsBindsAllWritableDirs(t *testing.T) {
	l := testLayout()
	args := bwrapArgs(l, "build")
	for _, dir := range []string{l.PackageDir, l.SrcDest, l.BuildRoot, l.PkgDest, l.LogDest} {
		if !hasPair(args, "--bind", dir) {
			t.Fatalf("missing --bind %s in %s", dir, strings.Join(args, " "))
		}
	}
}

func TestBwrapArgsReadOnlySystem(t *testing.T) {
	l := testLayout()
	args := bwrapArgs(l, "build")
	if !hasPair(args, "--ro-bind", "/usr") {
		t.Fatalf("missing --ro-bind /usr: %s", strings.Join(args, " "))
	}
	if !hasPair(args, "--ro-bind", "/etc") {
		t.Fatalf("missing --ro-bind /etc: %s", strings.Join(args, " "))
	}
	if !hasPair(args, "--tmpfs", "/var") {
		t.Fatalf("missing --tmpfs /var: %s", strings.Join(args, " "))
	}
}

func TestFetchSharesNetwork(t *testing.T) {
	args := bwrapArgs(testLayout(), "fetch")
	if !contains(args, "--share-net") {
		t.Fatalf("fetch args miss --share-net: %s", strings.Join(args, " "))
	}
}

func TestBuildDeniesNetworkByDefault(t *testing.T) {
	if contains(bwrapArgs(testLayout(), "build"), "--share-net") {
		t.Fatal("build args must not share the network by default")
	}
	if contains(sandboxArgs(testLayout(), "build", false), "--share-net") {
		t.Fatal("sandbox args must not share the network unless asked")
	}
}

func TestBuildAllowsNetworkWhenAsked(t *testing.T) {
	args := sandboxArgs(testLayout(), "build", true)
	if !contains(args, "--share-net") {
		t.Fatalf("expected --share-net when AllowNet is set: %s", strings.Join(args, " "))
	}
}

func contains(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// skipIfRoot keeps run-based tests honest: makepkg never runs as root.
func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("makepkg is never run as root")
	}
}

func TestMissingBwrapFails(t *testing.T) {
	skipIfRoot(t)
	old := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("missing") }
	defer func() { lookPath = old }()

	err := Build(Layout{PackageDir: t.TempDir()}, Options{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "bubblewrap (bwrap) not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// stubMakepkg writes an executable makepkg stub into dir that records its
// working directory and environment to marker.
func stubMakepkg(t *testing.T) (dir, marker string) {
	t.Helper()
	dir = t.TempDir()
	marker = filepath.Join(dir, "marker")
	script := "#!/bin/sh\n" +
		"pwd > \"" + marker + ".pwd\"\n" +
		"{\n" +
		"  printf 'HOME=%s\\n' \"$HOME\"\n" +
		"  printf 'PKGDEST=%s\\n' \"$PKGDEST\"\n" +
		"  printf 'SRCDEST=%s\\n' \"$SRCDEST\"\n" +
		"  printf 'BUILDDIR=%s\\n' \"$BUILDDIR\"\n" +
		"  printf 'LOGDEST=%s\\n' \"$LOGDEST\"\n" +
		"} > \"" + marker + ".env\"\n"
	path := filepath.Join(dir, "makepkg")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, marker
}

func TestExplicitUnsandboxedRunsWithoutBwrap(t *testing.T) {
	skipIfRoot(t)
	old := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("missing") }
	defer func() { lookPath = old }()

	dir, marker := stubMakepkg(t)
	t.Setenv("PATH", dir)

	pkgDir := t.TempDir()
	if err := Build(Layout{PackageDir: pkgDir}, Options{AllowUnsandboxed: true}); err != nil {
		t.Fatalf("expected stub to run: %v", err)
	}
	if _, err := os.Stat(marker + ".pwd"); err != nil {
		t.Fatalf("stub makepkg did not run: %v", err)
	}
	pwd, err := os.ReadFile(marker + ".pwd")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(pwd)) != pkgDir {
		t.Fatalf("stub ran in %q, want %q", strings.TrimSpace(string(pwd)), pkgDir)
	}
}

func TestAllowUnsandboxedEnv(t *testing.T) {
	skipIfRoot(t)
	old := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("missing") }
	defer func() { lookPath = old }()

	dir, marker := stubMakepkg(t)
	t.Setenv("PATH", dir)

	l, err := NewLayout(t.TempDir(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if err := Fetch(l, Options{AllowUnsandboxed: true}); err != nil {
		t.Fatalf("expected stub to run: %v", err)
	}
	raw, err := os.ReadFile(marker + ".env")
	if err != nil {
		t.Fatalf("stub makepkg did not run: %v", err)
	}
	env := string(raw)
	for _, want := range []string{
		"HOME=" + l.WorkDir(),
		"PKGDEST=" + l.PkgDest,
		"SRCDEST=" + l.SrcDest,
		"BUILDDIR=" + l.BuildRoot,
		"LOGDEST=" + l.LogDest,
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("missing env %q in stub environment:\n%s", want, env)
		}
	}
}

func TestLayoutCreatesDirs(t *testing.T) {
	cache := t.TempDir()
	l, err := NewLayout(cache, "hello")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"PackageDir": filepath.Join(cache, "hello"),
		"SrcDest":    filepath.Join(cache, "sources"),
		"BuildRoot":  filepath.Join(cache, "build"),
		"PkgDest":    filepath.Join(cache, "packages", "hello"),
		"LogDest":    filepath.Join(cache, "logs"),
	}
	got := map[string]string{
		"PackageDir": l.PackageDir,
		"SrcDest":    l.SrcDest,
		"BuildRoot":  l.BuildRoot,
		"PkgDest":    l.PkgDest,
		"LogDest":    l.LogDest,
	}
	for name, path := range want {
		if got[name] != path {
			t.Fatalf("%s = %q, want %q", name, got[name], path)
		}
		if fi, err := os.Stat(path); err != nil || !fi.IsDir() {
			t.Fatalf("%s %q not a directory: %v", name, path, err)
		}
	}
	if want := filepath.Join(l.BuildRoot, "hello"); l.WorkDir() != want {
		t.Fatalf("WorkDir = %q, want %q", l.WorkDir(), want)
	}
	if want := filepath.Join(l.BuildRoot, "hello", "src"); l.SrcDir() != want {
		t.Fatalf("SrcDir = %q, want %q", l.SrcDir(), want)
	}
}

func TestArtifactsFindsPackages(t *testing.T) {
	l, err := NewLayout(t.TempDir(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Artifacts(l); err == nil {
		t.Fatal("expected error for empty package dir")
	}
	for _, name := range []string{"foo.pkg.tar.zst", "bar.pkg.tar.zst"} {
		if err := os.WriteFile(filepath.Join(l.PkgDest, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	arts, err := Artifacts(l)
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 2 {
		t.Fatalf("got %d artifacts, want 2: %v", len(arts), arts)
	}
}

func TestArtifactsExcludesSignaturesAndSorts(t *testing.T) {
	l, err := NewLayout(t.TempDir(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"bar.pkg.tar.zst", "foo.pkg.tar.zst", "foo.pkg.tar.zst.sig"} {
		if err := os.WriteFile(filepath.Join(l.PkgDest, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(l.PkgDest, "dir.pkg.tar.zst"), 0o755); err != nil {
		t.Fatal(err)
	}
	arts, err := Artifacts(l)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		filepath.Join(l.PkgDest, "bar.pkg.tar.zst"),
		filepath.Join(l.PkgDest, "foo.pkg.tar.zst"),
	}
	if len(arts) != len(want) {
		t.Fatalf("got %d artifacts, want %d: %v", len(arts), len(want), arts)
	}
	for i := range want {
		if arts[i] != want[i] {
			t.Fatalf("artifact[%d] = %q, want %q", i, arts[i], want[i])
		}
	}
}

func TestLayoutsScopeArtifactsPerPackage(t *testing.T) {
	cache := t.TempDir()
	alpha, err := NewLayout(cache, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	beta, err := NewLayout(cache, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if alpha.PkgDest == beta.PkgDest {
		t.Fatalf("layouts share PkgDest %q", alpha.PkgDest)
	}
	if err := os.WriteFile(filepath.Join(alpha.PkgDest, "alpha-1-1-any.pkg.tar.zst"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Artifacts(beta); err == nil {
		t.Fatal("beta saw alpha's artifact")
	}
	arts, err := Artifacts(alpha)
	if err != nil || len(arts) != 1 {
		t.Fatalf("alpha artifacts = %v, err = %v", arts, err)
	}
}

func TestClearArtifactsRemovesStalePackages(t *testing.T) {
	l, err := NewLayout(t.TempDir(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	stale := []string{"foo.pkg.tar.zst", "foo.pkg.tar.zst.sig", "bar.pkg.tar.xz"}
	for _, name := range stale {
		if err := os.WriteFile(filepath.Join(l.PkgDest, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	keep := filepath.Join(l.PkgDest, "keep.txt")
	if err := os.WriteFile(keep, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := clearArtifacts(l); err != nil {
		t.Fatal(err)
	}
	for _, name := range stale {
		if _, err := os.Lstat(filepath.Join(l.PkgDest, name)); !os.IsNotExist(err) {
			t.Fatalf("%s still present: %v", name, err)
		}
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("unrelated file removed: %v", err)
	}
}

func TestRebuildDoesNotReturnStaleArtifact(t *testing.T) {
	skipIfRoot(t)
	l, err := NewLayout(t.TempDir(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.PkgDest, "hello-1-1-any.pkg.tar.zst"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	old := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("missing") }
	defer func() { lookPath = old }()

	dir, _ := stubMakepkg(t)
	t.Setenv("PATH", dir)

	if err := Build(l, Options{AllowUnsandboxed: true}); err != nil {
		t.Fatalf("stub build failed: %v", err)
	}
	if _, err := Artifacts(l); err == nil {
		t.Fatal("rebuild returned the stale artifact")
	}
}

func TestFetchDoesNotClearArtifacts(t *testing.T) {
	skipIfRoot(t)
	l, err := NewLayout(t.TempDir(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(l.PkgDest, "hello-1-1-any.pkg.tar.zst")
	if err := os.WriteFile(stale, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}

	old := lookPath
	lookPath = func(string) (string, error) { return "", errors.New("missing") }
	defer func() { lookPath = old }()

	dir, _ := stubMakepkg(t)
	t.Setenv("PATH", dir)

	if err := Fetch(l, Options{AllowUnsandboxed: true}); err != nil {
		t.Fatalf("stub fetch failed: %v", err)
	}
	arts, err := Artifacts(l)
	if err != nil || len(arts) != 1 || arts[0] != stale {
		t.Fatalf("fetch cleared artifacts: %v, err = %v", arts, err)
	}
}

func TestArtifactsRejectsSymlinks(t *testing.T) {
	l, err := NewLayout(t.TempDir(), "hello")
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(l.PkgDest, "real.pkg.tar.zst")
	if err := os.WriteFile(real, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(l.PkgDest, "linked.pkg.tar.zst")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	arts, err := Artifacts(l)
	if err != nil {
		t.Fatal(err)
	}
	if len(arts) != 1 || arts[0] != real {
		t.Fatalf("artifacts = %v, want only %q", arts, real)
	}
}

func TestArtifactsEmptyPkgDest(t *testing.T) {
	if _, err := Artifacts(Layout{}); err == nil {
		t.Fatal("expected error for empty PkgDest")
	}
}
