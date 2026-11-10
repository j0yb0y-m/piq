package build

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Layout describes the on-disk cache layout used to fetch and build a
// single package. PackageDir holds the cloned PKGBUILD; the remaining
// directories are shared makepkg destinations under the cache.
type Layout struct {
	Pkgbase    string
	PackageDir string
	SrcDest    string
	BuildRoot  string
	PkgDest    string
	LogDest    string
}

// NewLayout builds the cache layout for pkgbase and creates every
// directory makepkg needs.
func NewLayout(cacheDir, pkgbase string) (Layout, error) {
	l := Layout{
		Pkgbase:    pkgbase,
		PackageDir: filepath.Join(cacheDir, pkgbase),
		SrcDest:    filepath.Join(cacheDir, "sources"),
		BuildRoot:  filepath.Join(cacheDir, "build"),
		PkgDest:    filepath.Join(cacheDir, "packages"),
		LogDest:    filepath.Join(cacheDir, "logs"),
	}
	for _, dir := range []string{l.PackageDir, l.SrcDest, l.BuildRoot, l.PkgDest, l.LogDest} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return Layout{}, fmt.Errorf("creating build directory %s: %w", dir, err)
		}
	}
	return l, nil
}

// WorkDir is the makepkg BUILDDIR for this package. makepkg appends the
// package base to BUILDDIR itself, hence the extra path element.
func (l Layout) WorkDir() string {
	return filepath.Join(l.BuildRoot, l.Pkgbase)
}

// SrcDir is where makepkg extracts and builds sources.
func (l Layout) SrcDir() string {
	return filepath.Join(l.WorkDir(), "src")
}

// Options controls a fetch or build run.
type Options struct {
	// AllowUnsandboxed permits running makepkg directly when bubblewrap
	// is missing. It must never be set silently.
	AllowUnsandboxed bool
	// AllowNet grants the build phase network access. Fetch always has
	// network access; builds deny it by default.
	AllowNet bool
	Stdout   io.Writer
	Stderr   io.Writer
}

// lookPath is a test seam for locating bubblewrap.
var lookPath = exec.LookPath

// bwrapArgs returns the sandbox arguments common to both phases. The
// system is read-only, only the layout directories are writable, and
// the process runs from the PKGBUILD directory. The makepkg command is
// appended by run.
func bwrapArgs(l Layout, phase string) []string {
	args := []string{
		"--unshare-all",
		"--new-session",
		"--die-with-parent",
		"--ro-bind", "/usr", "/usr",
		"--ro-bind", "/etc", "/etc",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/bin", "/sbin",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--tmpfs", "/var",
		"--bind", l.PackageDir, l.PackageDir,
		"--bind", l.SrcDest, l.SrcDest,
		"--bind", l.BuildRoot, l.BuildRoot,
		"--bind", l.PkgDest, l.PkgDest,
		"--bind", l.LogDest, l.LogDest,
		"--chdir", l.PackageDir,
		"--setenv", "HOME", l.WorkDir(),
		"--setenv", "PKGDEST", l.PkgDest,
		"--setenv", "SRCDEST", l.SrcDest,
		"--setenv", "BUILDDIR", l.BuildRoot,
		"--setenv", "LOGDEST", l.LogDest,
	}
	if phase == "fetch" {
		args = append(args, "--share-net")
	}
	return args
}

// sandboxArgs extends bwrapArgs with an optional network grant for the
// build phase.
func sandboxArgs(l Layout, phase string, allowNet bool) []string {
	args := bwrapArgs(l, phase)
	if phase == "build" && allowNet {
		args = append(args, "--share-net")
	}
	return args
}

// Fetch downloads and verifies sources with network access.
func Fetch(l Layout, opts Options) error {
	return run(l, opts, "fetch", "--nobuild", "--nodeps", "--noconfirm")
}

// Build runs prepare/build/package without network access by default.
func Build(l Layout, opts Options) error {
	return run(l, opts, "build", "--noextract", "--nodeps", "--noconfirm")
}

// run executes makepkg for phase inside bubblewrap, or directly when
// the caller explicitly allowed an unsandboxed run.
func run(l Layout, opts Options, phase string, flags ...string) error {
	if os.Geteuid() == 0 {
		return errors.New("refusing to run makepkg as root")
	}

	bwrap, err := lookPath("bwrap")
	if err != nil {
		if !opts.AllowUnsandboxed {
			return errors.New("bubblewrap (bwrap) not found; refusing to build unsandboxed (install bubblewrap or pass --no-sandbox)")
		}
		return runMakepkg(l, opts, flags...)
	}

	args := append(sandboxArgs(l, phase, opts.AllowNet), "makepkg")
	args = append(args, flags...)
	cmd := exec.Command(bwrap, args...)
	cmd.Dir = l.PackageDir
	setOutput(cmd, opts)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running makepkg: %w", err)
	}
	return nil
}

// runMakepkg is the explicit unsandboxed path, used only when the
// caller set AllowUnsandboxed and bubblewrap is unavailable.
func runMakepkg(l Layout, opts Options, flags ...string) error {
	cmd := exec.Command("makepkg", flags...)
	cmd.Dir = l.PackageDir
	cmd.Env = append(os.Environ(),
		"HOME="+l.WorkDir(),
		"PKGDEST="+l.PkgDest,
		"SRCDEST="+l.SrcDest,
		"BUILDDIR="+l.BuildRoot,
		"LOGDEST="+l.LogDest,
	)
	setOutput(cmd, opts)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("running makepkg: %w", err)
	}
	return nil
}

func setOutput(cmd *exec.Cmd, opts Options) {
	cmd.Stdout = opts.Stdout
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	cmd.Stderr = opts.Stderr
	if cmd.Stderr == nil {
		cmd.Stderr = os.Stderr
	}
}

// Artifacts returns the built package files in PkgDest, sorted by path.
// Signature files and non-regular files are ignored.
func Artifacts(l Layout) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(l.PkgDest, "*.pkg.tar.*"))
	if err != nil {
		return nil, fmt.Errorf("globbing package artifacts: %w", err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if strings.HasSuffix(m, ".sig") {
			continue
		}
		fi, err := os.Stat(m)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no package artifacts found in %s", l.PkgDest)
	}
	sort.Strings(out)
	return out, nil
}
