package inspect

import (
	"archive/tar"
	"io"
	"os"
	"path"
	"strings"

	"github.com/klauspost/compress/zstd"
)

type FileEntry struct {
	Path     string
	Mode     os.FileMode
	Size     int64
	Linkname string
	Typeflag byte
}

// Listing decompresses and walks a built .pkg.tar.zst without ever
// extracting it to disk, returning every entry's path, permission
// bits, size, symlink target, and tar type.
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
			Path:     hdr.Name,
			Mode:     unixMode(hdr.Mode),
			Size:     hdr.Size,
			Linkname: hdr.Linkname,
			Typeflag: hdr.Typeflag,
		})
	}
	return entries, nil
}

// unixMode converts the raw Unix permission bits stored in a tar
// header, including setuid, setgid, and sticky, into an os.FileMode.
func unixMode(mode int64) os.FileMode {
	m := os.FileMode(mode & 0o777)
	if mode&0o4000 != 0 {
		m |= os.ModeSetuid
	}
	if mode&0o2000 != 0 {
		m |= os.ModeSetgid
	}
	if mode&0o1000 != 0 {
		m |= os.ModeSticky
	}
	return m
}

// SuspiciousEntries flags anything in the finished package worth a
// human glance before pacman -U ever runs: setuid/setgid bits,
// world-writable files, system configuration paths, symlinks that
// escape their package's footprint, device nodes, and path traversal.
func SuspiciousEntries(entries []FileEntry) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(msg string) {
		if seen[msg] {
			return
		}
		seen[msg] = true
		out = append(out, msg)
	}

	for _, e := range entries {
		p := normalizePath(e.Path)

		if e.Mode&os.ModeSetuid != 0 || e.Mode&os.ModeSetgid != 0 {
			add("setuid/setgid bit set on " + e.Path)
		}
		if isWorldWritable(e, p) {
			add("world-writable file: " + p)
		}
		if isSystemConfig(p) {
			add("system config path: " + p)
		}
		if isEscapingSymlink(e, p) {
			add("escaping symlink: " + p + " -> " + e.Linkname)
		}
		if e.Typeflag == tar.TypeChar || e.Typeflag == tar.TypeBlock {
			add("device node: " + p)
		}
		if hasTraversal(p) {
			add("path traversal: " + p)
		}
	}
	return out
}

func normalizePath(p string) string {
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		return "/" + p
	}
	return p
}

func isWorldWritable(e FileEntry, p string) bool {
	if e.Mode.Perm()&0o002 == 0 {
		return false
	}
	if p == "/tmp" || strings.HasPrefix(p, "/tmp/") {
		return false
	}
	switch e.Typeflag {
	case tar.TypeReg, tar.TypeRegA, tar.TypeDir:
		return true
	default:
		return false
	}
}

func isSystemConfig(p string) bool {
	if p == "/etc/ld.so.preload" {
		return true
	}
	for _, prefix := range []string{
		"/etc/systemd/system/",
		"/etc/cron.",
		"/etc/sudoers.d/",
		"/etc/pacman.d/hooks/",
	} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}

func isEscapingSymlink(e FileEntry, p string) bool {
	if e.Typeflag != tar.TypeSymlink || e.Linkname == "" {
		return false
	}
	if path.IsAbs(e.Linkname) {
		cleaned := path.Clean(e.Linkname)
		for _, root := range []string{"/usr", "/etc", "/opt", "/var"} {
			if cleaned == root || strings.HasPrefix(cleaned, root+"/") {
				return false
			}
		}
		return true
	}

	root := topLevelPrefix(p)
	if root == "/" {
		return false
	}
	resolved := path.Clean(path.Join(path.Dir(p), e.Linkname))
	return resolved != root && !strings.HasPrefix(resolved, root+"/")
}

func topLevelPrefix(p string) string {
	trimmed := strings.TrimPrefix(p, "/")
	if trimmed == "" {
		return "/"
	}
	first, _, _ := strings.Cut(trimmed, "/")
	return "/" + first
}

func hasTraversal(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
