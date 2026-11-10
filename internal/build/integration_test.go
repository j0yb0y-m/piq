//go:build integration

package build

import (
	"os"
	"path/filepath"
	"testing"
)

const fixturePKGBUILD = `pkgname=piq-fixture
pkgver=1.0
pkgrel=1
pkgdesc="piq integration fixture"
arch=('any')
url="https://example.invalid/piq-fixture"
license=('MIT')

package() {
  install -Dm644 /dev/null "$pkgdir/usr/share/piq-fixture/hello"
}
`

func TestIntegrationBuild(t *testing.T) {
	if os.Getenv("PIQ_INTEGRATION") == "" {
		t.Skip("set PIQ_INTEGRATION=1")
	}
	cache := t.TempDir()
	l, err := NewLayout(cache, "piq-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(l.PackageDir, "PKGBUILD"), []byte(fixturePKGBUILD), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Fetch(l, Options{Stdout: os.Stdout, Stderr: os.Stderr}); err != nil {
		t.Fatal(err)
	}
	if err := Build(l, Options{Stdout: os.Stdout, Stderr: os.Stderr}); err != nil {
		t.Fatal(err)
	}
	arts, err := Artifacts(l)
	if err != nil || len(arts) != 1 {
		t.Fatalf("artifacts=%v err=%v", arts, err)
	}
}
