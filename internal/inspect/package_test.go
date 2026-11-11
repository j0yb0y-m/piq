package inspect

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
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

func TestListingSetgidAndStickyModes(t *testing.T) {
	path := writeZstdTar(t, []tar.Header{
		{Name: "usr/bin/y", Mode: 0o2755, Typeflag: tar.TypeReg},
		{Name: "usr/share/sticky", Mode: 0o1777, Typeflag: tar.TypeDir},
	})
	entries, err := Listing(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Mode != os.ModeSetgid|0o755 {
		t.Errorf("expected setgid mode, got %v", entries[0].Mode)
	}
	if entries[1].Mode != os.ModeSticky|0o777 {
		t.Errorf("expected sticky mode, got %v", entries[1].Mode)
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
	if suspicious[0] != "escaping symlink: /usr/bin/x -> /root/.ssh/authorized_keys" {
		t.Errorf("unexpected message: %s", suspicious[0])
	}
}

func TestSuspiciousEntriesNormalizesPaths(t *testing.T) {
	t.Run("dot prefix still reports system config", func(t *testing.T) {
		e := FileEntry{Path: "./etc/systemd/system/x.service", Mode: 0o644, Typeflag: tar.TypeReg}
		suspicious := SuspiciousEntries([]FileEntry{e})
		want := "system config path: /etc/systemd/system/x.service"
		if len(suspicious) != 1 || suspicious[0] != want {
			t.Fatalf("got %v, want [%s]", suspicious, want)
		}
	})
	t.Run("duplicate slash does not hide an escaping symlink", func(t *testing.T) {
		e := FileEntry{Path: "//usr/bin/x", Linkname: "../../etc/shadow", Typeflag: tar.TypeSymlink}
		suspicious := SuspiciousEntries([]FileEntry{e})
		want := "escaping symlink: /usr/bin/x -> ../../etc/shadow"
		if len(suspicious) != 1 || suspicious[0] != want {
			t.Fatalf("got %v, want [%s]", suspicious, want)
		}
	})
	t.Run("dot prefix does not create a false positive", func(t *testing.T) {
		e := FileEntry{Path: "./usr/bin/x", Linkname: "../lib/x", Typeflag: tar.TypeSymlink}
		if suspicious := SuspiciousEntries([]FileEntry{e}); len(suspicious) != 0 {
			t.Fatalf("got %v, want no findings", suspicious)
		}
	})
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

func TestSuspiciousEntriesBlockDevice(t *testing.T) {
	entries := []FileEntry{
		{Path: "/dev/sdz", Mode: 0o600, Typeflag: tar.TypeBlock},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != 1 || suspicious[0] != "device node: /dev/sdz" {
		t.Fatalf("got %v, want [device node: /dev/sdz]", suspicious)
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

func TestSuspiciousEntriesHardlinkTraversal(t *testing.T) {
	entries := []FileEntry{
		{Path: "/usr/bin/x", Linkname: "../../etc/shadow", Typeflag: tar.TypeLink},
		{Path: "/usr/bin/y", Linkname: "/etc/passwd", Typeflag: tar.TypeLink},
		{Path: "/usr/bin/z", Linkname: "../lib/z", Typeflag: tar.TypeLink},
	}
	suspicious := SuspiciousEntries(entries)
	want := []string{
		"escaping hardlink: /usr/bin/x -> ../../etc/shadow",
		"escaping hardlink: /usr/bin/y -> /etc/passwd",
		"escaping hardlink: /usr/bin/z -> ../lib/z",
	}
	if len(suspicious) != len(want) {
		t.Fatalf("expected %d findings, got %v", len(want), suspicious)
	}
	for i := range want {
		if suspicious[i] != want[i] {
			t.Errorf("finding %d: got %q, want %q", i, suspicious[i], want[i])
		}
	}
}

func TestSuspiciousEntriesExpandedSystemConfig(t *testing.T) {
	entries := []FileEntry{
		{Path: "/etc/pam.d/sshd", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/ssh/sshd_config", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/sudoers", Mode: 0o440, Typeflag: tar.TypeReg},
		{Path: "/etc/ld.so.conf.d/x.conf", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/pacman.conf", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/modprobe.d/x.conf", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/udev/rules.d/99-x.rules", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/sysctl.d/99-x.conf", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/polkit-1/rules.d/49-x.rules", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/dbus-1/system.d/x.conf", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/profile", Mode: 0o644, Typeflag: tar.TypeReg},
		{Path: "/etc/mkinitcpio.d/linux.preset", Mode: 0o644, Typeflag: tar.TypeReg},
	}
	suspicious := SuspiciousEntries(entries)
	if len(suspicious) != len(entries) {
		t.Fatalf("expected %d findings, got %v", len(entries), suspicious)
	}
	for _, msg := range suspicious {
		if !strings.HasPrefix(msg, "system config path: ") {
			t.Errorf("unexpected finding: %q", msg)
		}
	}
}

func TestReadListingRejectsTooManyEntries(t *testing.T) {
	path := writeZstdTar(t, []tar.Header{
		{Name: "a", Typeflag: tar.TypeReg},
		{Name: "b", Typeflag: tar.TypeReg},
		{Name: "c", Typeflag: tar.TypeReg},
		{Name: "d", Typeflag: tar.TypeReg},
	})
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := zstd.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()

	if _, err := readListing(zr, 3); err == nil {
		t.Fatal("listing accepted more entries than its limit")
	}
}
