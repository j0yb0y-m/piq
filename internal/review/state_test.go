package review

import (
	"os"
	"path/filepath"
	"testing"
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
