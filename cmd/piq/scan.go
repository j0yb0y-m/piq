package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/config"
	"github.com/j0yb0y-m/piq/internal/history"
	"github.com/j0yb0y-m/piq/internal/pkgbuild"
	"github.com/j0yb0y-m/piq/internal/review"
	"github.com/j0yb0y-m/piq/internal/scanner"
	"github.com/j0yb0y-m/piq/internal/ui"
	"mvdan.cc/sh/v3/syntax"
)

// cfg is set once by the root command's PersistentPreRunE.
var cfg *config.Config

// scanResult bundles the scanner context plus its scoring verdict,
// provenance history, and any prior review record.
type scanResult struct {
	Pkgbase    string
	PkgDir     string
	Context    *scanner.Context
	Score      *scanner.Score
	Provenance *history.Provenance
	Review     *review.Record
}

// scanPackage clones the package repo (if needed), parses the PKGBUILD
// and .SRCINFO, assembles the scanner bundle (including companion
// scriptlets and referenced local files), inspects git provenance, and
// produces a scored verdict. It writes to the same cache dir used by
// install so nothing is downloaded twice.
func scanPackage(name string, store *review.Store) (*scanResult, error) {
	client := aur.NewClient()
	pkgs, err := client.Info(name)
	if err != nil {
		return nil, fmt.Errorf("fetching AUR metadata: %w", err)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("package %q not found on the AUR", name)
	}
	pkg := pkgs[0]

	pkgbase := pkg.PackageBase
	if pkgbase == "" {
		pkgbase = pkg.Name
	}

	cache, err := cacheDir()
	if err != nil {
		return nil, err
	}
	pkgDir := filepath.Join(cache, pkgbase)
	if err := aur.FetchPackage(pkgbase, pkgDir); err != nil {
		return nil, fmt.Errorf("cloning package repo: %w", err)
	}

	srcinfo, err := pkgbuild.LoadSrcinfo(filepath.Join(pkgDir, ".SRCINFO"))
	if err != nil {
		return nil, fmt.Errorf("parsing .SRCINFO: %w", err)
	}

	pkgbuildPath := filepath.Join(pkgDir, "PKGBUILD")
	raw, err := os.ReadFile(pkgbuildPath)
	if err != nil {
		return nil, fmt.Errorf("reading PKGBUILD: %w", err)
	}
	astFile, err := pkgbuild.Parse(strings.NewReader(string(raw)), "PKGBUILD")
	if err != nil {
		return nil, fmt.Errorf("parsing PKGBUILD: %w", err)
	}

	ctx := &scanner.Context{
		Raw:      string(raw),
		AST:      astFile,
		Metadata: srcinfo,
		AURInfo:  &pkg,
		File:     pkgbuildPath,
	}
	collectLocalFiles(ctx, pkgDir)

	var prov *history.Provenance
	if p, err := history.Inspect(pkgDir); err == nil {
		prov = p
		ctx.History = prov
	}

	var rec *review.Record
	if store != nil {
		rec, _ = store.Get(pkgbase)
	}

	res := &scanResult{
		Pkgbase:    pkgbase,
		PkgDir:     pkgDir,
		Context:    ctx,
		Provenance: prov,
		Review:     rec,
	}
	// Config is set globally before any command runs; apply ignored
	// rules now so later filtering is a no-op.
	res.Score = scoreWithConfig(ctx)
	return res, nil
}

// collectLocalFiles populates ctx.Scriptlets and ctx.Sources from the
// files actually present in the fetched repo so that AST rules run
// against companion scriptlets and install= references are validated
// against what truly arrived on disk.
func collectLocalFiles(ctx *scanner.Context, pkgDir string) {
	entries, err := os.ReadDir(pkgDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
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
		var sA *syntax.File
		fileAST, perr := pkgbuild.Parse(strings.NewReader(string(data)), e.Name())
		if perr == nil {
			sA = fileAST
		}
		ctx.Sources = append(ctx.Sources, scanner.LocalSource{
			Name:     e.Name(),
			Present:  true,
			Path:     path,
			Raw:      string(data),
			AST:      sA,
			IsScript: strings.HasSuffix(e.Name(), ".install"),
		})
		if strings.HasSuffix(e.Name(), ".install") {
			ctx.Scriptlets = append(ctx.Scriptlets, scanner.Scriptlet{
				Name: e.Name(),
				Raw:  string(data),
				AST:  sA,
			})
		}
	}
}

// scoreWithConfig runs the full rule set and produces a score, but
// drops findings from rules the user has ignored in config.
func scoreWithConfig(ctx *scanner.Context) *scanner.Score {
	score := scanner.NewScore(ctx)
	if cfg == nil || len(cfg.Rules.Ignore) == 0 {
		return score
	}
	filtered := score.Findings[:0]
	for _, f := range score.Findings {
		if cfg.IgnoresRule(f.Rule) {
			continue
		}
		filtered = append(filtered, f)
	}
	score.Findings = filtered
	// Recompute total after ignoring rules (gate hits stay as-is).
	total := 0
	for rule, pts := range score.PerRule {
		if cfg.IgnoresRule(rule) {
			continue
		}
		total += pts
	}
	score.Total = total
	return score
}

// printFindings renders findings grouped by severity with the verdict.
func printFindings(res *scanResult) {
	score := res.Score
	fmt.Printf("\n%s%s — verdict %s%s, risk score %d, %d findings\n",
		ui.Blue, res.Pkgbase, verdictColor(score.Verdict), score.Verdict.String(),
		score.Total, len(score.Findings))
	fmt.Printf("%s%s\n", ui.Overlay0, strings.Repeat("-", 60))
	for _, f := range score.Findings {
		color := ui.Text
		switch f.Severity {
		case scanner.Critical:
			color = ui.Red
		case scanner.Warning:
			color = ui.Peach
		}
		where := "PKGBUILD"
		if f.File != "" {
			where = f.File
		}
		fmt.Printf("  %s[%s]%s %s\n", color, f.Severity, ui.Text, f.Message)
		if f.Line > 0 {
			fmt.Printf("    %s→ %s:%d (%s)%s\n", ui.Overlay0, where, f.Line, f.Rule, ui.Text)
		} else {
			fmt.Printf("    %s→ %s (%s)%s\n", ui.Overlay0, where, f.Rule, ui.Text)
		}
	}
}

func verdictColor(v scanner.Verdict) string {
	switch v {
	case scanner.Malicious, scanner.Suspicious:
		return ui.Red
	case scanner.Sketchy:
		return ui.Peach
	case scanner.OK, scanner.Trusted:
		return ui.Green
	default:
		return ui.Text
	}
}
