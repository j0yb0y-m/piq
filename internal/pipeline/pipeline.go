// Package pipeline orchestrates the consent-gated path from an AUR
// package name to an installed package: clone, scan, fetch sources,
// sandboxed build, artifact inspection, and pacman installation.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/morganamilo/go-srcinfo"
	"mvdan.cc/sh/v3/syntax"

	"github.com/j0yb0y-m/piq/internal/alpm"
	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/build"
	"github.com/j0yb0y-m/piq/internal/config"
	"github.com/j0yb0y-m/piq/internal/history"
	"github.com/j0yb0y-m/piq/internal/inspect"
	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"github.com/j0yb0y-m/piq/internal/review"
	"github.com/j0yb0y-m/piq/internal/scanner"
	"github.com/j0yb0y-m/piq/internal/ui"
)

var (
	// ErrAborted means the user declined a confirmation prompt.
	ErrAborted = errors.New("aborted by user")
	// ErrBlocked means the risk policy refused the package.
	ErrBlocked = errors.New("blocked by risk policy")
)

// Options controls a pipeline run.
type Options struct {
	CacheDir  string
	Config    *config.Config
	Store     *review.Store
	Client    *aur.Client
	Confirm   func(string) bool
	Yes       bool
	Force     bool
	AllowNet  bool
	NoSandbox bool
	DryRun    bool
	JSON      bool
}

// Result is everything the pipeline learned about one package. Hash
// fields come from the fetched repo so callers can compare them with a
// stored review without rereading the tree.
type Result struct {
	Pkgbase       string
	PkgDir        string
	Commit        string
	PkgbuildHash  string
	PkgbuildRaw   string
	SrcinfoHash   string
	ScriptletHash string
	Layout        build.Layout
	Metadata      *srcinfo.Srcinfo
	Score         *scanner.Score
	Provenance    *history.Provenance
	Review        *review.Record
	Artifacts     []string
}

// Pipeline is a reusable scan/install orchestrator. Its unexported
// function fields are test seams; production always uses the defaults.
type Pipeline struct {
	opts Options

	fetchRepo    func(pkgbase, destDir string) error
	fetchSrc     func(build.Layout, build.Options) error
	buildSrc     func(build.Layout, build.Options) error
	artifactsFn  func(build.Layout) ([]string, error)
	inspectPkg   func(string) ([]string, error)
	pacmanRun    func([]string) error
	now          func() time.Time
	officialRepo func(string) (bool, error)
	missingDeps  func([]string) ([]string, error)
	elevation    func(string) ([]string, error)
}

// New returns a pipeline with production defaults for any option or
// seam the caller left unset.
func New(opts Options) *Pipeline {
	if opts.Config == nil {
		opts.Config = config.Default()
	}
	if opts.CacheDir == "" {
		opts.CacheDir = opts.Config.CacheDir
	}
	if opts.Client == nil {
		opts.Client = aur.NewClient()
	}
	if opts.Confirm == nil {
		opts.Confirm = func(string) bool { return false }
	}

	p := &Pipeline{
		opts:         opts,
		fetchRepo:    aur.FetchPackage,
		fetchSrc:     build.Fetch,
		buildSrc:     build.Build,
		artifactsFn:  build.Artifacts,
		now:          time.Now,
		officialRepo: alpm.InOfficial,
		missingDeps:  alpm.Missing,
		elevation:    alpm.Elevation,
	}
	p.inspectPkg = func(path string) ([]string, error) {
		entries, err := inspect.Listing(path)
		if err != nil {
			return nil, err
		}
		return inspect.SuspiciousEntries(entries), nil
	}
	p.pacmanRun = func(argv []string) error {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = p.out()
		cmd.Stderr = ui.Err()
		if err := cmd.Run(); err != nil {
			return err
		}
		return nil
	}
	return p
}

// out routes human progress to stdout normally and to stderr in JSON
// mode so stdout stays a single JSON document.
func (p *Pipeline) out() io.Writer {
	if p.opts.JSON {
		return ui.Err()
	}
	return ui.Out()
}

func (p *Pipeline) outf(format string, args ...any) {
	fmt.Fprintf(p.out(), format, args...)
}

// allowUnsandboxed authorizes an unsandboxed build only when the user
// explicitly asked for one. It deliberately avoids SandboxEnabled's
// bwrap auto-detection: a missing binary must fail loudly instead of
// silently degrading the build.
func (p *Pipeline) allowUnsandboxed() bool {
	return p.opts.NoSandbox || p.opts.Config.SandboxExplicitlyDisabled()
}

// Scan fetches and scores one package. When deep is true it also
// fetches upstream sources and scans their contents.
func (p *Pipeline) Scan(ctx context.Context, name string, deep bool) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.opts.CacheDir == "" {
		return nil, errors.New("pipeline: cache directory is empty")
	}

	pkgs, err := p.opts.Client.Info(name)
	if err != nil {
		return nil, fmt.Errorf("fetching AUR metadata: %w", err)
	}
	pkg, ok := pickPackage(pkgs, name)
	if !ok {
		return nil, fmt.Errorf("package %q not found on the AUR", name)
	}

	pkgbase := pkg.PackageBase
	if pkgbase == "" {
		pkgbase = pkg.Name
	}
	pkgDir := filepath.Join(p.opts.CacheDir, pkgbase)
	if err := p.fetchRepo(pkgbase, pkgDir); err != nil {
		return nil, fmt.Errorf("cloning package repo: %w", err)
	}

	metadata, missingSrcinfo, err := loadSrcinfo(pkgDir)
	if err != nil {
		return nil, err
	}

	pkgbuildPath := filepath.Join(pkgDir, "PKGBUILD")
	raw, err := readRegularFile(pkgbuildPath)
	if err != nil {
		return nil, fmt.Errorf("reading PKGBUILD: %w", err)
	}
	astFile, err := pkgbuild.Parse(strings.NewReader(string(raw)), "PKGBUILD")
	if err != nil {
		return nil, fmt.Errorf("parsing PKGBUILD: %w", err)
	}

	sctx := &scanner.Context{
		Raw:      string(raw),
		AST:      astFile,
		Metadata: metadata,
		AURInfo:  &pkg,
		File:     pkgbuildPath,
	}
	collectLocalFiles(sctx, pkgDir)

	var prov *history.Provenance
	if inspected, err := history.Inspect(pkgDir); err == nil {
		prov = inspected
		sctx.History = prov
	}

	var rec *review.Record
	if p.opts.Store != nil {
		if stored, err := p.opts.Store.Get(pkgbase); err == nil {
			rec = stored
		}
	}

	pkgbuildHash, srcinfoHash, scriptletHash, err := review.Fingerprint(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("fingerprinting package: %w", err)
	}

	extra := make([]scanner.Finding, 0, 1)
	if missingSrcinfo {
		extra = append(extra, scanner.Finding{
			Rule:     "missing-srcinfo",
			Severity: scanner.Warning,
			File:     ".SRCINFO",
			Message:  ".SRCINFO is missing; package metadata and dependencies may be incomplete",
		})
	}

	res := &Result{
		Pkgbase:       pkgbase,
		PkgDir:        pkgDir,
		PkgbuildHash:  pkgbuildHash,
		PkgbuildRaw:   string(raw),
		SrcinfoHash:   srcinfoHash,
		ScriptletHash: scriptletHash,
		Metadata:      metadata,
		Provenance:    prov,
		Review:        rec,
	}
	if prov != nil {
		res.Commit = prov.HeadHash
	}
	res.Score = p.score(sctx, extra)

	if deep {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		layout, err := build.NewLayout(p.opts.CacheDir, pkgbase)
		if err != nil {
			return nil, err
		}
		if err := p.fetchSrc(layout, build.Options{
			AllowUnsandboxed: p.allowUnsandboxed(),
			AllowNet:         true,
			Stdout:           p.out(),
			Stderr:           ui.Err(),
		}); err != nil {
			return nil, fmt.Errorf("fetching sources: %w", err)
		}
		fileScan, err := scanner.ScanTree(layout.SrcDir(), scanner.FileOptions{Deep: false})
		if err != nil {
			return nil, fmt.Errorf("scanning sources: %w", err)
		}
		extra = append(extra, fileScan.Findings...)
		res.Layout = layout
		res.Score = p.score(sctx, extra)
	}

	return res, nil
}

// score applies the configured ignore list, confirmation severity, and
// block threshold to the scanner context.
func (p *Pipeline) score(sctx *scanner.Context, extra []scanner.Finding) *scanner.Score {
	opts := scanner.Options{
		Ignore:    p.opts.Config.IgnoreSet(),
		Threshold: p.opts.Config.Threshold,
		Extra:     extra,
	}
	opts.MinSeverity, _ = scanner.ParseSeverity(p.opts.Config.Severity)
	return scanner.ScoreWith(sctx, opts)
}

// Install scans, resolves dependencies, builds, inspects, and installs
// a package and its AUR dependency closure.
func (p *Pipeline) Install(ctx context.Context, name string) (*Result, error) {
	root, err := p.Scan(ctx, name, true)
	if err != nil {
		return nil, err
	}

	if root.Score != nil && root.Score.Blocked && !p.opts.Force {
		PrintFindings(p.out(), root)
		return root, fmt.Errorf("%w: %s", ErrBlocked, root.Score.BlockReason)
	}

	if p.opts.DryRun {
		return root, p.dryRun(ctx, root, name)
	}

	closure, err := resolveAURClosureWith(ctx, p.opts.Client, name, 10, p.officialRepo)
	if err != nil {
		return root, err
	}

	deps := make([]*Result, 0, len(closure))
	for _, dep := range closure {
		if err := ctx.Err(); err != nil {
			return root, err
		}
		res, err := p.Scan(ctx, dep, true)
		if err != nil {
			return root, fmt.Errorf("scanning AUR dependency %s: %w", dep, err)
		}
		if res.Score != nil && res.Score.Blocked && !p.opts.Force {
			PrintFindings(p.out(), res)
			return res, fmt.Errorf("%w: AUR dependency %s: %s", ErrBlocked, dep, res.Score.BlockReason)
		}
		deps = append(deps, res)
	}

	repoDeps, err := p.repositoryDeps(root, deps, closure, name)
	if err != nil {
		return root, err
	}
	if len(repoDeps) > 0 {
		elev, err := p.elevation(p.opts.Config.Pacman.SudoCmd)
		if err != nil {
			return root, fmt.Errorf("resolving elevation command: %w", err)
		}
		p.outf("%s\n", ui.Notice(fmt.Sprintf("Installing %d repository dependency(ies)...", len(repoDeps))))
		args := append(append([]string{}, elev...), "-S", "--asdeps", "--needed", "--noconfirm")
		args = append(args, repoDeps...)
		if err := p.pacmanRun(args); err != nil {
			return root, fmt.Errorf("installing repository dependencies: %w", err)
		}
	}

	for _, dep := range deps {
		if err := p.installBuilt(dep); err != nil {
			return root, err
		}
	}
	if err := p.installBuilt(root); err != nil {
		return root, err
	}
	return root, nil
}

// dryRun reports the dependency and artifact plan without building,
// inspecting, or installing anything.
func (p *Pipeline) dryRun(ctx context.Context, root *Result, name string) error {
	closure, err := resolveAURClosureWith(ctx, p.opts.Client, name, 10, p.officialRepo)
	if err != nil {
		return err
	}

	aurSet := make(map[string]bool, len(closure)+1)
	for _, dep := range closure {
		aurSet[dep] = true
	}
	aurSet[name] = true

	var repoDeps []string
	seen := map[string]bool{}
	for _, dep := range depsOf(root.Metadata) {
		if aurSet[dep] || seen[dep] {
			continue
		}
		seen[dep] = true
		official, err := p.officialRepo(dep)
		if err != nil {
			return fmt.Errorf("checking official repo for %s: %w", dep, err)
		}
		if official {
			repoDeps = append(repoDeps, dep)
		}
	}

	p.outf("%s\n", ui.Notice("Dry run: "+root.Pkgbase))
	if len(closure) == 0 {
		p.outf("  AUR dependencies: none\n")
	} else {
		p.outf("  AUR dependencies: %s\n", strings.Join(closure, ", "))
	}
	if len(repoDeps) == 0 {
		p.outf("  Repository dependencies: none\n")
	} else {
		p.outf("  Repository dependencies: %s\n", strings.Join(repoDeps, ", "))
	}
	p.outf("  Would build, inspect, and install %s with pacman.\n", root.Pkgbase)
	return nil
}

// repositoryDeps returns the missing official-repository dependencies
// for the target and its AUR closure. AUR names are never passed to
// pacman -S.
func (p *Pipeline) repositoryDeps(root *Result, deps []*Result, closure []string, name string) ([]string, error) {
	aurNames := make(map[string]bool, len(closure)+2)
	for _, dep := range closure {
		aurNames[dep] = true
	}
	aurNames[name] = true
	aurNames[root.Pkgbase] = true

	seen := map[string]bool{}
	var candidates []string
	add := func(res *Result) {
		for _, dep := range depsOf(res.Metadata) {
			if aurNames[dep] || seen[dep] {
				continue
			}
			seen[dep] = true
			candidates = append(candidates, dep)
		}
	}
	add(root)
	for _, dep := range deps {
		add(dep)
	}

	var official []string
	for _, dep := range candidates {
		ok, err := p.officialRepo(dep)
		if err != nil {
			return nil, fmt.Errorf("checking official repo for %s: %w", dep, err)
		}
		if ok {
			official = append(official, dep)
		}
	}
	if len(official) == 0 {
		return nil, nil
	}
	missing, err := p.missingDeps(official)
	if err != nil {
		return nil, fmt.Errorf("checking installed dependencies: %w", err)
	}
	return missing, nil
}

// installBuilt builds, inspects, and installs a scanned result, saving
// its review record only after pacman succeeds.
func (p *Pipeline) installBuilt(res *Result) error {
	if res == nil || res.Score == nil {
		return errors.New("install: missing scan result")
	}

	PrintFindings(p.out(), res)

	if res.Score.Blocked {
		if !p.opts.Force {
			return fmt.Errorf("%w: %s", ErrBlocked, res.Score.BlockReason)
		}
		if !p.opts.Confirm("Acknowledge the blocking findings for " + res.Pkgbase + "?") {
			return ErrAborted
		}
		if !p.opts.Confirm("Force installation of " + res.Pkgbase + " despite the risk policy?") {
			return ErrAborted
		}
	} else if needsPrompt(res, p.opts) {
		if !p.opts.Confirm("Install " + res.Pkgbase + "?") {
			return ErrAborted
		}
	}

	p.outf("%s\n", ui.Notice("Building "+res.Pkgbase+" in a sandbox..."))
	if err := p.buildSrc(res.Layout, build.Options{
		AllowUnsandboxed: p.allowUnsandboxed(),
		AllowNet:         p.opts.AllowNet,
		Stdout:           p.out(),
		Stderr:           ui.Err(),
	}); err != nil {
		return fmt.Errorf("building %s: %w", res.Pkgbase, err)
	}

	artifacts, err := p.artifactsFn(res.Layout)
	if err != nil {
		return fmt.Errorf("finding built packages for %s: %w", res.Pkgbase, err)
	}
	if len(artifacts) == 0 {
		return fmt.Errorf("no packages were built for %s", res.Pkgbase)
	}
	res.Artifacts = artifacts

	for _, artifact := range artifacts {
		suspicious, err := p.inspectPkg(artifact)
		if err != nil {
			return fmt.Errorf("inspecting %s: %w", filepath.Base(artifact), err)
		}
		if len(suspicious) == 0 {
			continue
		}
		p.outf("\n%s\n", ui.Critical(fmt.Sprintf("Suspicious entries in %s:", filepath.Base(artifact))))
		for _, finding := range suspicious {
			p.outf("  - %s\n", finding)
		}
		if !p.opts.Yes {
			if !p.opts.Confirm("Install " + res.Pkgbase + " despite suspicious entries?") {
				return ErrAborted
			}
		}
	}

	elev, err := p.elevation(p.opts.Config.Pacman.SudoCmd)
	if err != nil {
		return fmt.Errorf("resolving elevation command: %w", err)
	}
	args := append(append([]string{}, elev...), "-U", "--noconfirm")
	args = append(args, artifacts...)
	p.outf("%s\n", ui.Notice("Installing "+res.Pkgbase+" with pacman..."))
	if err := p.pacmanRun(args); err != nil {
		return fmt.Errorf("installing %s: %w", res.Pkgbase, err)
	}

	if p.opts.Store != nil {
		committer := ""
		if res.Provenance != nil {
			committer = res.Provenance.Maintainer
		}
		rec := &review.Record{
			PackageBase:   res.Pkgbase,
			Commit:        res.Commit,
			Committer:     committer,
			PkgbuildHash:  res.PkgbuildHash,
			PkgbuildRaw:   res.PkgbuildRaw,
			SrcinfoHash:   res.SrcinfoHash,
			ScriptletHash: res.ScriptletHash,
			Verdict:       res.Score.Verdict.String(),
			ReviewedAt:    p.now().UTC(),
		}
		if err := p.opts.Store.Put(rec); err != nil {
			return fmt.Errorf("saving review for %s: %w", res.Pkgbase, err)
		}
	}

	p.outf("%s\n", ui.Success(res.Pkgbase+" installed successfully."))
	return nil
}

// needsPrompt reports whether installation needs an explicit decision.
// --yes only skips prompts for an unchanged package with no findings
// that require confirmation.
func needsPrompt(res *Result, opts Options) bool {
	if res == nil || res.Score == nil {
		return true
	}
	if res.Review == nil {
		return true
	}
	if res.Review.Commit != res.Commit ||
		res.Review.PkgbuildHash != res.PkgbuildHash ||
		res.Review.SrcinfoHash != res.SrcinfoHash ||
		res.Review.ScriptletHash != res.ScriptletHash {
		return true
	}
	if res.Score.NeedsConfirm {
		return true
	}
	return !opts.Yes
}

// loadSrcinfo parses .SRCINFO when present. A missing file is allowed
// and reported as a warning by the caller; anything else is fatal.
func loadSrcinfo(pkgDir string) (*srcinfo.Srcinfo, bool, error) {
	path := filepath.Join(pkgDir, ".SRCINFO")
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("checking .SRCINFO: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, false, fmt.Errorf("parsing .SRCINFO: %s is not a regular file", path)
	}
	meta, err := pkgbuild.LoadSrcinfo(path)
	if err != nil {
		return nil, false, fmt.Errorf("parsing .SRCINFO: %w", err)
	}
	return meta, false, nil
}

// readRegularFile refuses symlinks, FIFOs, devices, and directories so
// untrusted repository content cannot block or exhaust the scanner.
func readRegularFile(path string) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return os.ReadFile(path)
}

// collectLocalFiles populates ctx.Scriptlets and ctx.Sources from
// regular files actually present in the fetched repo. Symlinks are not
// followed: source rules then report referenced files as missing rather
// than reading outside the clone.
func collectLocalFiles(ctx *scanner.Context, pkgDir string) {
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if e.Name() == "PKGBUILD" || e.Name() == ".SRCINFO" {
			continue
		}
		path := filepath.Join(pkgDir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var fileAST *syntax.File
		parsed, perr := pkgbuild.Parse(strings.NewReader(string(data)), e.Name())
		if perr == nil {
			fileAST = parsed
		}
		ctx.Sources = append(ctx.Sources, scanner.LocalSource{
			Name:     e.Name(),
			Present:  true,
			Path:     path,
			Raw:      string(data),
			AST:      fileAST,
			IsScript: strings.HasSuffix(e.Name(), ".install"),
		})
		if strings.HasSuffix(e.Name(), ".install") {
			ctx.Scriptlets = append(ctx.Scriptlets, scanner.Scriptlet{
				Name: e.Name(),
				Raw:  string(data),
				AST:  fileAST,
			})
		}
	}
}

// pickPackage selects the exact package from an info response, falling
// back to the first result because AUR preserves server order.
func pickPackage(pkgs []aur.Package, name string) (aur.Package, bool) {
	for _, pkg := range pkgs {
		if pkg.Name == name {
			return pkg, true
		}
	}
	if len(pkgs) > 0 {
		return pkgs[0], true
	}
	return aur.Package{}, false
}
