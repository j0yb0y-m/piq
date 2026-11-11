package review

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	rec := &Record{
		PackageBase:  "test-pkg",
		Committer:    "dev@example.com",
		Commit:       "deadbeef",
		PkgbuildHash: "abc123",
		PkgbuildRaw:  "pkgname=test-pkg\npkgver=1.0",
		Verdict:      "OK",
	}
	if err := store.Put(rec); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, err := store.Get("test-pkg")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected record, got nil")
	}
	if got.PackageBase != "test-pkg" {
		t.Errorf("expected package_base=test-pkg, got %q", got.PackageBase)
	}
	if got.Committer != "dev@example.com" {
		t.Errorf("expected committer=dev@example.com, got %q", got.Committer)
	}
	if got.Commit != "deadbeef" {
		t.Errorf("expected commit=deadbeef, got %q", got.Commit)
	}
	if got.PkgbuildRaw != "pkgname=test-pkg\npkgver=1.0" {
		t.Errorf("unexpected raw content: %q", got.PkgbuildRaw)
	}
}

func TestStoreGetMissing(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get("nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for missing record, got %+v", got)
	}
}

func TestHash(t *testing.T) {
	h := Hash([]byte("hello"))
	if h != "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824" {
		t.Errorf("unexpected hash: %q", h)
	}
}

func TestHashEmpty(t *testing.T) {
	h1 := Hash([]byte(""))
	h2 := Hash([]byte(""))
	if h1 != h2 {
		t.Error("empty inputs should hash identically")
	}
}

func TestStoreCreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "deep", "nested", "reviews")
	_, err := NewStore(dir)
	if err != nil {
		t.Fatalf("expected NewStore to create dirs: %v", err)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("expected directory to exist")
	}
}

func TestMatches(t *testing.T) {
	r := &Record{Commit: "abc", PkgbuildHash: "p", SrcinfoHash: "s", ScriptletHash: "i"}
	if !r.Matches("abc", "p", "s", "i") {
		t.Fatal("expected match")
	}
	if r.Matches("def", "p", "s", "i") {
		t.Fatal("commit change must not match")
	}
	if r.Matches("abc", "p", "s", "j") {
		t.Fatal("scriptlet change must not match")
	}
	if r.Matches("abc", "q", "s", "i") {
		t.Fatal("pkgbuild change must not match")
	}
	if r.Matches("abc", "p", "t", "i") {
		t.Fatal("srcinfo change must not match")
	}
	var nilRec *Record
	if nilRec.Matches("abc", "p", "s", "i") {
		t.Fatal("nil record must not match")
	}
}

func TestScriptletHashIsOrderIndependent(t *testing.T) {
	a := ScriptletHash(map[string]string{"b.install": "b", "a.install": "a"})
	b := ScriptletHash(map[string]string{"a.install": "a", "b.install": "b"})
	if a != b {
		t.Fatal("hash depends on map order")
	}
	want := Hash([]byte("a.install\x00a\x00b.install\x00b\x00"))
	if a != want {
		t.Errorf("scriptlet hash = %q, want golden %q", a, want)
	}
}

func TestScriptletHashEmpty(t *testing.T) {
	if got := ScriptletHash(nil); got != "" {
		t.Errorf("nil map: expected empty hash, got %q", got)
	}
	if got := ScriptletHash(map[string]string{}); got != "" {
		t.Errorf("empty map: expected empty hash, got %q", got)
	}
}

func TestScriptletHashChanges(t *testing.T) {
	base := ScriptletHash(map[string]string{"a.install": "a"})
	if got := ScriptletHash(map[string]string{"a.install": "b"}); got == base {
		t.Error("content change must change the hash")
	}
	if got := ScriptletHash(map[string]string{"b.install": "a"}); got == base {
		t.Error("name change must change the hash")
	}
}

func TestFingerprint(t *testing.T) {
	dir := t.TempDir()
	pkgbuild := []byte("pkgname=x")
	srcinfo := []byte("pkgbase = x")
	scriptlet := []byte("post_install(){ true; }")
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), pkgbuild, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), srcinfo, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.install"), scriptlet, 0o644); err != nil {
		t.Fatal(err)
	}
	p, s, i, err := Fingerprint(dir)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if p != Hash(pkgbuild) {
		t.Errorf("pkgbuild hash = %q, want %q", p, Hash(pkgbuild))
	}
	if s != Hash(srcinfo) {
		t.Errorf("srcinfo hash = %q, want %q", s, Hash(srcinfo))
	}
	wantScriptlets := ScriptletHash(map[string]string{"x.install": string(scriptlet)})
	if i != wantScriptlets {
		t.Errorf("scriptlet hash = %q, want %q", i, wantScriptlets)
	}
}

func TestFingerprintMissingSrcinfo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x"), 0o644); err != nil {
		t.Fatal(err)
	}
	p, s, i, err := Fingerprint(dir)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	if p == "" {
		t.Error("expected pkgbuild hash")
	}
	if s != "" {
		t.Errorf("expected empty srcinfo hash, got %q", s)
	}
	if i != "" {
		t.Errorf("expected empty scriptlet hash, got %q", i)
	}
}

func TestFingerprintMultipleScriptlets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.install"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.install"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, i, err := Fingerprint(dir)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	want := ScriptletHash(map[string]string{"a.install": "a", "b.install": "b"})
	if i != want {
		t.Errorf("scriptlet hash = %q, want %q", i, want)
	}
}

func TestFingerprintMissingPkgbuild(t *testing.T) {
	_, _, _, err := Fingerprint(t.TempDir())
	if err == nil {
		t.Fatal("expected error for missing PKGBUILD")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("expected fs.ErrNotExist, got %v", err)
	}
}

func TestFingerprintUnreadableSrcinfo(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".SRCINFO"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := Fingerprint(dir)
	if err == nil {
		t.Fatal("expected error when .SRCINFO is a directory")
	}
	if !strings.Contains(err.Error(), ".SRCINFO") {
		t.Errorf("expected error to mention .SRCINFO, got %v", err)
	}
}

func TestFingerprintScriptletIsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "x.install"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := Fingerprint(dir)
	if err == nil {
		t.Fatal("expected error when a *.install match is a directory")
	}
	if !strings.Contains(err.Error(), "x.install") {
		t.Errorf("expected error to mention x.install, got %v", err)
	}
}

func TestReadRegularFileRejectsFIFO(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("syscall.Mkfifo is Linux-only here")
	}
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("cannot create FIFO: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readRegularFile(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error for FIFO")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readRegularFile blocked on FIFO")
	}
}

func TestReadRegularFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(link); err == nil {
		t.Fatal("expected error for symlink")
	}
}

func TestFingerprintScriptletIsSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "real")
	if err := os.WriteFile(target, []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "x.install")); err != nil {
		t.Fatal(err)
	}
	_, _, _, err := Fingerprint(dir)
	if err == nil {
		t.Fatal("expected error when a *.install match is a symlink")
	}
	if !strings.Contains(err.Error(), "x.install") {
		t.Errorf("expected error to mention x.install, got %v", err)
	}
}

func TestFingerprintDirectoryWithGlobMetacharacters(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pkg[1]")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.install"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, i, err := Fingerprint(dir)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	want := ScriptletHash(map[string]string{"a.install": "a"})
	if i != want {
		t.Errorf("scriptlet hash = %q, want %q", i, want)
	}
}

func TestPutIsAtomic(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(&Record{PackageBase: "pkg", Commit: "one"}); err != nil {
		t.Fatalf("first put: %v", err)
	}
	if err := store.Put(&Record{PackageBase: "pkg", Commit: "two"}); err != nil {
		t.Fatalf("second put: %v", err)
	}
	got, err := store.Get("pkg")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil || got.Commit != "two" {
		t.Fatalf("expected second record, got %+v", got)
	}

	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.Contains(d.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	if runtime.GOOS == "linux" {
		info, err := os.Stat(filepath.Join(dir, "pkg.json"))
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("file mode = %04o, want 0600", perm)
		}
	}
}

func TestPutConcurrent(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- store.Put(&Record{PackageBase: "pkg", Verdict: fmt.Sprintf("v%d", i)})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent put: %v", err)
		}
	}
	got, err := store.Get("pkg")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected record after concurrent puts")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

func TestStoreRejectsEscapingPackageBase(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"../escape", "a/b", `a\b`, "..", "."} {
		if _, err := store.Get(name); err == nil {
			t.Errorf("Get(%q) accepted an unsafe name", name)
		}
		if err := store.Put(&Record{PackageBase: name}); err == nil {
			t.Errorf("Put(%q) accepted an unsafe name", name)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.json")); !os.IsNotExist(err) {
		t.Fatalf("store wrote outside its directory: %v", err)
	}
}

func TestFingerprintRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte("pkgname=x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "huge.install"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxReviewFileBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := Fingerprint(dir); err == nil {
		t.Fatal("oversized scriptlet was hashed")
	}
}
