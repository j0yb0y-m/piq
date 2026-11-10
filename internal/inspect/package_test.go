package inspect

import (
	"archive/tar"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestSuspiciousEntries(t *testing.T) {
	entries := []FileEntry{
		{Path: "/usr/bin/normal", Mode: 0o755, Size: 1000},
		{Path: "/usr/bin/setuid-bin", Mode: os.ModeSetuid | 0o755, Size: 2000},
		{Path: "/usr/lib/lib.so", Mode: 0o644, Size: 5000},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 1 {
		t.Fatalf("expected 1 suspicious entry, got %d", len(suspicious))
	}
	if suspicious[0] != "setuid/setgid bit set on /usr/bin/setuid-bin" {
		t.Errorf("unexpected message: %s", suspicious[0])
	}
}

func TestSuspiciousEntriesSetgid(t *testing.T) {
	entries := []FileEntry{
		{Path: "/usr/bin/setgid-bin", Mode: os.ModeSetgid | 0o755, Size: 2000},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 1 {
		t.Fatalf("expected 1 suspicious entry for setgid, got %d", len(suspicious))
	}
}

func TestSuspiciousEntriesClean(t *testing.T) {
	entries := []FileEntry{
		{Path: "/usr/bin/ls", Mode: 0o755, Size: 100000},
		{Path: "/usr/lib/libfoo.so", Mode: 0o644, Size: 50000},
		{Path: "/usr/share/doc/pkg/README", Mode: 0o644, Size: 500},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 0 {
		t.Errorf("expected 0 suspicious entries, got %d: %v", len(suspicious), suspicious)
	}
}

func TestSuspiciousEntriesEmpty(t *testing.T) {
	suspicious := SuspiciousEntries(nil)
	if len(suspicious) != 0 {
		t.Errorf("expected 0 suspicious entries for nil input, got %d", len(suspicious))
	}
}

func TestListingPopulatesMetadata(t *testing.T) {
	path := writeZstdTar(t, []tar.Header{
		{Name: "usr/bin/x", Mode: 0o4755, Typeflag: tar.TypeReg},
		{Name: "usr/lib/link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink},
	})
	entries, err := Listing(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Path != "usr/bin/x" || entries[0].Mode&os.ModeSetuid == 0 {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}
	if entries[1].Linkname != "/etc/passwd" || entries[1].Typeflag != tar.TypeSymlink {
		t.Fatalf("%+v", entries[1])
	}
}

func TestListingSetuidRoundTrip(t *testing.T) {
	path := writeZstdTar(t, []tar.Header{
		{Name: "usr/bin/su", Mode: 0o4755, Typeflag: tar.TypeReg},
	})
	entries, err := Listing(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].Mode != os.ModeSetuid|0o755 {
		t.Fatalf("expected setuid mode in listing, got %v", entries[0].Mode)
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(suspicious), suspicious)
	}
	if suspicious[0] != "setuid/setgid bit set on usr/bin/su" {
		t.Errorf("unexpected message: %s", suspicious[0])
	}
}

func TestSuspiciousEntriesWorldWritable(t *testing.T) {
	entries := []FileEntry{
		{Path: "/usr/share/pkg/world.txt", Mode: 0o666, Typeflag: tar.TypeReg},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(suspicious), suspicious)
	}
	if suspicious[0] != "world-writable file: /usr/share/pkg/world.txt" {
		t.Errorf("unexpected message: %s", suspicious[0])
	}
}

func TestSuspiciousEntriesWorldWritableInTmp(t *testing.T) {
	entries := []FileEntry{
		{Path: "/tmp/pkg/world.txt", Mode: 0o666, Typeflag: tar.TypeReg},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 0 {
		t.Errorf("expected no findings for world-writable file under /tmp, got %v", suspicious)
	}
}

func TestSuspiciousEntriesSymlinkModeNotWorldWritable(t *testing.T) {
	entries := []FileEntry{
		{Path: "/usr/lib/link", Mode: 0o777, Linkname: "libfoo.so.1", Typeflag: tar.TypeSymlink},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 0 {
		t.Errorf("expected no findings for symlink mode 0777, got %v", suspicious)
	}
}

func TestSuspiciousEntriesSystemConfig(t *testing.T) {
	entries := []FileEntry{
		{Path: "/etc/systemd/system/x.service", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/cron.d/x", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/sudoers.d/x", Mode: 0o440, Typeflag: tar.TypeReg},
		{Path: "/etc/ld.so.preload", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/pacman.d/hooks/x.hook", Mode: 0o644, Typeflag: tar.TypeReg},
	}
	suspicious := SuspiciousEntries(entries)
	want := []string{
		"system config path: /etc/systemd/system/x.service",
		"system config path: /etc/cron.d/x",
		"system config path: /etc/sudoers.d/x",
		"system config path: /etc/ld.so.preload",
		"system config path: /etc/pacman.d/hooks/x.hook",
	}
	if len(suspicious) != len(want) {
		t.Fatalf("expected %d findings, got %d: %v", len(want), len(suspicious), suspicious)
	}
	for i := range want {
		if suspicious[i] != want[i] {
			t.Errorf("finding %d: got %q, want %q", i, suspicious[i], want[i])
		}
	}
}

func TestSuspiciousEntriesEscapingSymlink(t *testing.T) {
	entries := []FileEntry{
		{Path: "/usr/bin/x", Linkname: "../../etc/shadow", Typeflag: tar.TypeSymlink},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(suspicious), suspicious)
	}
	if suspicious[0] != "escaping symlink: /usr/bin/x -> ../../etc/shadow" {
		t.Errorf("unexpected message: %s", suspicious[0])
	}
}

func TestSuspiciousEntriesAbsoluteEscapingSymlink(t *testing.T) {
	entries := []FileEntry{
		{Path: "/usr/bin/x", Linkname: "/root/.ssh/authorized_keys", Typeflag: tar.TypeSymlink},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(suspicious), suspicious)
	}
}

func TestSuspiciousEntriesRelativeSymlinkInsidePrefix(t *testing.T) {
	cases := []FileEntry{
		{Path: "/usr/bin/x", Linkname: "../lib/x", Typeflag: tar.TypeSymlink},
		{Path: "/usr/lib/libfoo.so", Linkname: "libfoo.so.1", Typeflag: tar.TypeSymlink},
	}
	for _, e := range cases {
		if suspicious := SuspiciousEntries([]FileEntry{e}); len(suspicious) != 0 {
			t.Errorf("%s -> %s: expected no findings, got %v", e.Path, e.Linkname, suspicious)
		}
	}
}

func TestSuspiciousEntriesDeviceNode(t *testing.T) {
	entries := []FileEntry{
		{Path: "/dev/evil", Mode: 0o600, Typeflag: tar.TypeChar},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(suspicious), suspicious)
	}
	if suspicious[0] != "device node: /dev/evil" {
		t.Errorf("unexpected message: %s", suspicious[0])
	}
}

func TestSuspiciousEntriesTraversal(t *testing.T) {
	entries := []FileEntry{
		{Path: "/usr/share/../../etc/passwd", Mode: 0o644, Typeflag: tar.TypeReg},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 1 {
		t.Fatalf("expected 1 finding, got %d: %v", len(suspicious), suspicious)
	}
	if suspicious[0] != "path traversal: /usr/share/../../etc/passwd" {
		t.Errorf("unexpected message: %s", suspicious[0])
	}
}

func TestSuspiciousEntriesDeduplicates(t *testing.T) {
	e := FileEntry{Path: "/etc/systemd/system/x.service", Mode: 0o666, Typeflag: tar.TypeReg}
	suspicious := SuspiciousEntries([]FileEntry{e, e})
	want := []string{
		"world-writable file: /etc/systemd/system/x.service",
		"system config path: /etc/systemd/system/x.service",
	}
	if len(suspicious) != len(want) {
		t.Fatalf("expected %d findings, got %d: %v", len(want), len(suspicious), suspicious)
	}
	seen := make(map[string]bool)
	for _, s := range suspicious {
		if seen[s] {
			t.Errorf("duplicate finding: %q", s)
		}
		seen[s] = true
	}
	for i := range want {
		if suspicious[i] != want[i] {
			t.Errorf("finding %d: got %q, want %q", i, suspicious[i], want[i])
		}
	}
}

func TestSuspiciousEntriesCleanSystemdUnit(t *testing.T) {
	entries := []FileEntry{
		{Path: "/usr/lib/systemd/system/foo.service", Mode: 0o644, Typeflag: tar.TypeReg},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 0 {
		t.Errorf("expected no findings for clean systemd unit, got %v", suspicious)
	}
}

// writeZstdTar builds a zstd-compressed tar archive in a temp directory and
// returns its path.
func writeZstdTar(t *testing.T, headers []tar.Header) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "pkg.tar.zst")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	zw, err := zstd.NewWriter(f)
	if err != nil {
		f.Close()
		t.Fatal(err)
	}
	tw := tar.NewWriter(zw)
	for _, h := range headers {
		hdr := h
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}
