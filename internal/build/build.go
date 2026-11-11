package build

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Layout describes the on-disk cache layout used to fetch and build a
// single package. PackageDir holds the cloned PKGBUILD; BuildFile is a
// writable copy of that PKGBUILD which makepkg may update during
// pkgver(). The remaining directories are shared makepkg destinations
// under the cache.
type Layout struct {
	Pkgbase    string
	PackageDir string
	BuildFile  string
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
		BuildFile:  filepath.Join(cacheDir, "buildfiles", pkgbase, "PKGBUILD"),
		SrcDest:    filepath.Join(cacheDir, "sources"),
		BuildRoot:  filepath.Join(cacheDir, "build"),
		PkgDest:    filepath.Join(cacheDir, "packages", pkgbase),
		LogDest:    filepath.Join(cacheDir, "logs"),
	}
	for _, dir := range []string{l.PackageDir, filepath.Dir(l.BuildFile), l.SrcDest, l.BuildRoot, l.PkgDest, l.LogDest} {
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
	// AllowNet grants the extraction/prepare phase and the build phase
	// network access. Source download always has network access; both
	// later phases deny it by default.
	AllowNet bool
	Stdout   io.Writer
	Stderr   io.Writer
}

// lookPath is a test seam for locating bubblewrap.
var lookPath = exec.LookPath

// bwrapArgs returns the sandbox arguments common to both phases. The
// system and the package directory are read-only, only makepkg's own
// destination directories are writable, and the process runs from the
// PKGBUILD directory. The makepkg command is appended by execPhase.
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
		"--ro-bind", l.PackageDir, l.PackageDir,
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
	if l.BuildFile != "" {
		// makepkg requires its build file to live in the working
		// directory. Bind the mutable copy over the repository's
		// PKGBUILD so pkgver() can update the version without giving
		// prepare() write access to the reviewed tree. The build phase
		// freezes the validated copy.
		target := filepath.Join(l.PackageDir, "PKGBUILD")
		if phase == "build" {
			args = append(args, "--ro-bind", l.BuildFile, target)
		} else {
			args = append(args, "--bind", l.BuildFile, target)
		}
	}
	if phase == "fetch" {
		args = append(args, "--share-net")
	}
	return args
}

// sandboxArgs extends bwrapArgs with an optional network grant for the
// prepare/extract and build phases.
func sandboxArgs(l Layout, phase string, allowNet bool) []string {
	args := bwrapArgs(l, phase)
	if allowNet && (phase == "extract" || phase == "build") {
		args = append(args, "--share-net")
	}
	return args
}

// Fetch copies the reviewed PKGBUILD into a mutable build file,
// downloads and verifies sources with network access, then extracts and
// prepares them without network access. prepare() and pkgver() run in
// the no-network phase; the package directory itself stays read-only and
// only the build file may change. Call ValidateBuildFile afterwards to
// confirm pkgver() only changed the version fields.
func Fetch(l Layout, opts Options) error {
	if err := prepareBuildFile(l); err != nil {
		return err
	}
	bwrap, err := preflight(opts)
	if err != nil {
		return err
	}
	if err := execPhase(l, opts, bwrap, "fetch", "--verifysource", "--nodeps", "--noconfirm"); err != nil {
		return err
	}
	// The extraction phase reuses the cache populated by the fetch
	// phase, then extracts and prepares the sources. --holdver keeps it
	// from updating VCS mirrors, and --skipinteg both skips the redundant
	// second checksum pass and hides the PKGBUILD's verify() hook
	// (makepkg's parser does not accept --noverify). Phase one already
	// verified the same cached sources, so the phase needs no network
	// while still running prepare() and pkgver().
	return execPhase(l, opts, bwrap, "extract", "--nobuild", "--holdver", "--skipinteg", "--nodeps", "--noconfirm")
}

// prepareBuildFile stages a writable copy of the reviewed PKGBUILD
// outside the repository so makepkg can update pkgver() without
// modifying the scanned tree.
func prepareBuildFile(l Layout) error {
	if l.BuildFile == "" {
		return nil
	}
	raw, err := readRegularFile(filepath.Join(l.PackageDir, "PKGBUILD"))
	if err != nil {
		return fmt.Errorf("reading PKGBUILD for build: %w", err)
	}
	if err := writeFileAtomic(l.BuildFile, raw); err != nil {
		return fmt.Errorf("staging PKGBUILD: %w", err)
	}
	return nil
}

// pkgverLineRE and pkgrelLineRE bound what pkgver() and prepare() may
// leave in the staged build file. makepkg's own check_pkgver rejects
// whitespace, slashes, colons, hyphens, and non-ASCII, but permits shell
// metacharacters such as ';'. A build file is sourced by makepkg, so only
// a strict version alphabet is safe.
var (
	pkgverLineRE = regexp.MustCompile(`^pkgver=[A-Za-z0-9._+~]+$`)
	pkgrelLineRE = regexp.MustCompile(`^pkgrel=[0-9]+$`)
)

// ValidateBuildFile checks that the staged PKGBUILD differs from the
// reviewed original only in pkgver/pkgrel assignments. Anything else
// means prepare() or pkgver() rewrote the build script after review.
func ValidateBuildFile(l Layout, original []byte) error {
	if l.BuildFile == "" {
		return nil
	}
	updated, err := os.ReadFile(l.BuildFile)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("staged PKGBUILD is missing after fetch")
	}
	if err != nil {
		return fmt.Errorf("reading staged PKGBUILD: %w", err)
	}
	if bytes.Equal(updated, original) {
		return nil
	}
	orig := bytes.Split(original, []byte("\n"))
	upd := bytes.Split(updated, []byte("\n"))
	if len(orig) != len(upd) {
		// makepkg rewrites the build file with a trailing newline even
		// when the original lacked one. Accept only that added newline.
		if !bytes.HasSuffix(original, []byte("\n")) && len(upd) == len(orig)+1 && len(upd[len(upd)-1]) == 0 {
			upd = upd[:len(upd)-1]
		}
		if len(orig) != len(upd) {
			return errors.New("staged PKGBUILD changed shape after fetch")
		}
	}
	for i := range orig {
		if bytes.Equal(orig[i], upd[i]) {
			continue
		}
		// Only an existing pkgver= or pkgrel= assignment may change,
		// and its replacement must be a plain version string. This
		// stops a hook from deleting or replacing shell code with a
		// line that merely looks like a version assignment.
		if bytes.HasPrefix(orig[i], []byte("pkgver=")) && pkgverLineRE.Match(upd[i]) {
			continue
		}
		if bytes.HasPrefix(orig[i], []byte("pkgrel=")) && pkgrelLineRE.Match(upd[i]) {
			continue
		}
		return fmt.Errorf("staged PKGBUILD line %d changed outside pkgver/pkgrel after fetch", i+1)
	}
	return nil
}

// maxBuildFileBytes bounds reads of a PKGBUILD from the AUR checkout.
const maxBuildFileBytes = 8 << 20

func readRegularFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxBuildFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBuildFileBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxBuildFileBytes)
	}
	return data, nil
}

func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".PKGBUILD-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// Build runs build() and package() against the tree prepared by Fetch,
// without network access by default. Stale artifacts for this package
// are removed once the run is known to be allowed, so a rebuild can
// never return the previous package.
func Build(l Layout, opts Options) error {
	bwrap, err := preflight(opts)
	if err != nil {
		return err
	}
	if err := clearArtifacts(l); err != nil {
		return err
	}
	return execPhase(l, opts, bwrap, "build", "--noextract", "--nodeps", "--noconfirm")
}

// preflight enforces the no-root rule and resolves bubblewrap. An empty
// bwrap path means the caller explicitly allowed an unsandboxed run.
func preflight(opts Options) (string, error) {
	if os.Geteuid() == 0 {
		return "", errors.New("refusing to run makepkg as root")
	}
	bwrap, err := lookPath("bwrap")
	if err != nil {
		if !opts.AllowUnsandboxed {
			return "", errors.New("bubblewrap (bwrap) not found; refusing to build unsandboxed (install bubblewrap or pass --no-sandbox)")
		}
		return "", nil
	}
	return bwrap, nil
}

// execPhase runs makepkg in the resolved sandbox, or directly when bwrap
// is empty.
func execPhase(l Layout, opts Options, bwrap, phase string, flags ...string) error {
	if bwrap == "" {
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
// caller set AllowUnsandboxed and bubblewrap is unavailable. The staged
// PKGBUILD is copied into the repository before the run and its updates
// are copied back afterwards, because makepkg only accepts a build file
// in its working directory.
func runMakepkg(l Layout, opts Options, flags ...string) error {
	if err := syncBuildFileToPackageDir(l); err != nil {
		return err
	}
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
	err := cmd.Run()
	syncErr := syncPackageDirToBuildFile(l)
	if err != nil {
		return fmt.Errorf("running makepkg: %w", err)
	}
	return syncErr
}

func syncBuildFileToPackageDir(l Layout) error {
	if l.BuildFile == "" {
		return nil
	}
	raw, err := os.ReadFile(l.BuildFile)
	if err != nil {
		return fmt.Errorf("reading staged PKGBUILD: %w", err)
	}
	if err := os.WriteFile(filepath.Join(l.PackageDir, "PKGBUILD"), raw, 0o644); err != nil {
		return fmt.Errorf("writing PKGBUILD for unsandboxed run: %w", err)
	}
	return nil
}

func syncPackageDirToBuildFile(l Layout) error {
	if l.BuildFile == "" {
		return nil
	}
	raw, err := readRegularFile(filepath.Join(l.PackageDir, "PKGBUILD"))
	if err != nil {
		return fmt.Errorf("reading PKGBUILD after unsandboxed run: %w", err)
	}
	if err := writeFileAtomic(l.BuildFile, raw); err != nil {
		return fmt.Errorf("saving PKGBUILD after unsandboxed run: %w", err)
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

// clearArtifacts removes package files left in PkgDest by an earlier
// build of the same package base, including signatures.
func clearArtifacts(l Layout) error {
	if l.PkgDest == "" {
		return nil
	}
	matches, err := filepath.Glob(filepath.Join(l.PkgDest, "*.pkg.tar.*"))
	if err != nil {
		return fmt.Errorf("globbing package artifacts: %w", err)
	}
	for _, m := range matches {
		if err := os.RemoveAll(m); err != nil {
			return fmt.Errorf("removing stale artifact %s: %w", m, err)
		}
	}
	return nil
}

// Artifacts returns the built package files in PkgDest, sorted by path.
// Signature files, symlinks and other non-regular files are ignored.
func Artifacts(l Layout) ([]string, error) {
	if l.PkgDest == "" {
		return nil, errors.New("no package artifacts found: package directory is empty")
	}
	matches, err := filepath.Glob(filepath.Join(l.PkgDest, "*.pkg.tar.*"))
	if err != nil {
		return nil, fmt.Errorf("globbing package artifacts: %w", err)
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if strings.HasSuffix(m, ".sig") {
			continue
		}
		fi, err := os.Lstat(m)
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
