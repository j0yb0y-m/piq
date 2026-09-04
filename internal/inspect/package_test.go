package inspect

import (
	"os"
	"testing"
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
