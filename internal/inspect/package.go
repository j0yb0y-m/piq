package inspect

import (
	"archive/tar"
	"io"
	"os"

	"github.com/klauspost/compress/zstd"
)

type FileEntry struct {
	Path string
	Mode os.FileMode
	Size int64
}

// Listing decompresses and walks a built .pkg.tar.zst without ever
// extracting it to disk, returning every entry's path, permission
// bits, and size.
func Listing(pkgPath string) ([]FileEntry, error) {
	f, err := os.Open(pkgPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	zr, err := zstd.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	tr := tar.NewReader(zr)
	var entries []FileEntry
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, FileEntry{
			Path: hdr.Name,
			Mode: os.FileMode(hdr.Mode),
			Size: hdr.Size,
		})
	}
	return entries, nil
}

// SuspiciousEntries flags anything in the finished package worth a
// human glance before pacman -U ever runs: setuid/setgid bits,
// systemd units and cron entries a first-glance at the PKGBUILD
// might not have made obvious, and files placed well outside a
// normal package's footprint.
func SuspiciousEntries(entries []FileEntry) []string {
	var out []string
	for _, e := range entries {
		if e.Mode&os.ModeSetuid != 0 || e.Mode&os.ModeSetgid != 0 {
			out = append(out, "setuid/setgid bit set on "+e.Path)
		}
	}
	return out
}
