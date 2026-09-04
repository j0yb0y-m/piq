package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

type BuildDirs struct {
	SrcDir string // where sources get extracted and built
	PkgDir string // where package() installs its output tree
}

// requireBwrap returns an error if bubblewrap is not installed.
func requireBwrap() error {
	if _, err := exec.LookPath("bwrap"); err != nil {
		return fmt.Errorf("bubblewrap (bwrap) not found — refusing to build unsandboxed; install with: pacman -S bubblewrap")
	}
	return nil
}

// baseArgs returns the bwrap flags common to both phases: a
// read-only view of the system with only the build directories
// writable, and /var as a tmpfs to prevent package manager state
// leakage. The process is torn down the moment the parent exits.
func baseArgs(d BuildDirs) []string {
	return []string{
		"--unshare-all",
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
		"--bind", d.SrcDir, d.SrcDir,
		"--bind", d.PkgDir, d.PkgDir,
		"--chdir", d.SrcDir,
		"--setenv", "HOME", d.SrcDir,
	}
}

// FetchPhase runs `makepkg --nobuild` (download + checksum-verify
// sources only) WITH network access — this is the one phase that
// legitimately needs it.
func FetchPhase(d BuildDirs, pkgbuildDir string) error {
	if err := requireBwrap(); err != nil {
		return err
	}
	args := append(baseArgs(d),
		"--share-net",
		"--bind", pkgbuildDir, pkgbuildDir,
		"makepkg", "--nobuild", "--syncdeps", "--noconfirm",
	)
	cmd := exec.Command("bwrap", args...)
	cmd.Dir = pkgbuildDir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// BuildPhase runs the actual build — deliberately with NO network
// namespace shared at all. If prepare()/build()/package() try to
// reach out, DNS resolution and every socket call fail immediately.
func BuildPhase(d BuildDirs, pkgbuildDir string) error {
	if err := requireBwrap(); err != nil {
		return err
	}
	args := append(baseArgs(d),
		"--bind", pkgbuildDir, pkgbuildDir,
		"makepkg", "--noextract", "--nodeps",
	)
	cmd := exec.Command("bwrap", args...)
	cmd.Dir = pkgbuildDir
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// Canonicalize cleans a path and returns the absolute form. Used by
// callers to normalize cache paths before comparison.
func Canonicalize(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}
