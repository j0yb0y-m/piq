package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/inspect"
	"github.com/j0yb0y-m/piq/internal/report"
	"github.com/j0yb0y-m/piq/internal/review"
	"github.com/j0yb0y-m/piq/internal/sandbox"
	"github.com/j0yb0y-m/piq/internal/scanner"
	"github.com/j0yb0y-m/piq/internal/ui"
)

func main() {
	os.Exit(execute(os.Args[1:], os.Stdout, os.Stderr))
}

func searchCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "search <term>",
		Short: "Search the AUR",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if limit < 0 {
				return coded(exitUsage, fmt.Errorf("limit must not be negative: %d", limit))
			}
			results, err := aur.NewClient().Search(args[0])
			if err != nil {
				return err
			}
			if len(results) > limit {
				results = results[:limit]
			}
			if jsonOutput {
				return report.Write(ui.Out(), searchReport(results))
			}
			for _, r := range results {
				ui.Printf("%s %s (%d votes) — %s\n", r.Name, r.Version, r.NumVotes, r.Description)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "maximum number of results to show")
	return cmd
}

func cacheDir() (string, error) {
	if cfg != nil && cfg.CacheDir != "" {
		return cfg.CacheDir, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".cache", "piq"), nil
}

func confirm(prompt string) bool {
	ui.Printf("%s [y/N] ", ui.Warning(prompt))
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(strings.ToLower(line)) == "y"
}

func scanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "scan <package>",
		Short: "Security-scan a package without installing it",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			res, err := scanPackage(args[0], reviewStore)
			if err != nil {
				return err
			}
			if jsonOutput {
				if err := report.Write(ui.Out(), scanReport(res)); err != nil {
					return err
				}
			} else {
				printFindings(res)
			}
			if res.Score != nil && res.Score.Blocked {
				return coded(exitBlocked, fmt.Errorf("blocked: %s", res.Score.BlockReason))
			}
			return nil
		},
	}
}

func installCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install <package>",
		Short: "Scan, review, build, and install a package",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			res, err := scanPackage(name, reviewStore)
			if err != nil {
				return err
			}

			score := res.Score
			if jsonOutput {
				if err := report.Write(ui.Out(), scanReportFor(res, "install")); err != nil {
					return err
				}
				if score != nil && score.Verdict == scanner.Malicious {
					return coded(exitBlocked, fmt.Errorf("installation blocked: malicious verdict"))
				}
				return nil
			}

			if score.Verdict == scanner.Malicious {
				ui.Printf("%s\n", ui.Critical("BLOCKED: verdict is MALICIOUS — refusing to install."))
				printFindings(res)
				return fmt.Errorf("installation blocked: MALICIOUS verdict")
			}

			// If we have a prior review, show what changed since.
			if res.Review != nil {
				showDiff(res)
			}

			printFindings(res)

			criticalCount := 0
			for _, f := range score.Findings {
				if f.Severity == scanner.Critical {
					criticalCount++
				}
			}
			if criticalCount > 0 {
				ui.Printf("\n%s\n", ui.Critical(fmt.Sprintf("%d critical finding(s) detected.", criticalCount)))
			}
			if len(score.Findings) > 0 && !confirm("Proceed with installation anyway?") {
				ui.Println("Aborted.")
				return nil
			}

			pkgDir := res.PkgDir

			srcDir := filepath.Join(filepath.Dir(pkgDir), "src", res.Pkgbase)
			pkgOutDir := filepath.Join(filepath.Dir(pkgDir), "pkg", res.Pkgbase)
			os.MkdirAll(srcDir, 0o755)
			os.MkdirAll(pkgOutDir, 0o755)

			dirs := sandbox.BuildDirs{
				SrcDir: srcDir,
				PkgDir: pkgOutDir,
			}

			ui.Printf("%s\n", ui.Notice("Phase 1/3: Fetching sources..."))
			if err := sandbox.FetchPhase(dirs, pkgDir); err != nil {
				return fmt.Errorf("fetch phase: %w", err)
			}

			ui.Printf("%s\n", ui.Notice("Phase 2/3: Building in sandbox (no network)..."))
			if err := sandbox.BuildPhase(dirs, pkgDir); err != nil {
				return fmt.Errorf("build phase: %w", err)
			}

			ui.Printf("%s\n", ui.Notice("Phase 3/3: Inspecting built package..."))
			entries, err := filepath.Glob(filepath.Join(pkgOutDir, "*.pkg.tar.zst"))
			if err != nil || len(entries) == 0 {
				return fmt.Errorf("no .pkg.tar.zst found in %s", pkgOutDir)
			}

			// Inspect all built packages (split packages support).
			for _, pkgPath := range entries {
				fileEntries, err := inspect.Listing(pkgPath)
				if err != nil {
					return fmt.Errorf("inspecting %s: %w", pkgPath, err)
				}
				suspicious := inspect.SuspiciousEntries(fileEntries)
				if len(suspicious) > 0 {
					ui.Printf("\n%s\n", ui.Critical(fmt.Sprintf("Suspicious entries in %s:", filepath.Base(pkgPath))))
					for _, s := range suspicious {
						ui.Printf("  - %s\n", s)
					}
					if !confirm("Install anyway?") {
						ui.Println("Aborted.")
						return nil
					}
				}
			}

			sudoCmd := "sudo"
			if cfg != nil && cfg.Pacman.SudoCmd != "" {
				sudoCmd = cfg.Pacman.SudoCmd
			}

			// Install all built packages in one pacman invocation.
			pacmanArgs := append([]string{"pacman", "-U", "--noconfirm"}, entries...)
			pacman := exec.Command(sudoCmd, pacmanArgs...)
			pacman.Stdout = os.Stdout
			pacman.Stderr = os.Stderr
			if err := pacman.Run(); err != nil {
				return fmt.Errorf("pacman install: %w", err)
			}

			// Record review state for future update-diff.
			saveReview(res)

			ui.Printf("%s\n", ui.Success(fmt.Sprintf("%s installed successfully.", name)))
			return nil
		},
	}
}

// showDiff compares the current PKGBUILD with the last-reviewed
// snapshot and shows what changed, flagging any newly-introduced
// dangerous patterns.
func showDiff(res *scanResult) {
	if res.Review == nil || res.Review.PkgbuildRaw == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(res.PkgDir, "PKGBUILD"))
	if err != nil {
		return
	}
	newSrc := string(raw)
	oldSrc := res.Review.PkgbuildRaw

	// Same hash = nothing changed.
	if res.Review.PkgbuildHash == review.Hash(raw) {
		return
	}

	ui.Printf("\n%s\n", ui.Warning("Package has been updated since last review."))
	ui.Printf("  %s%s\n", ui.Muted("Last reviewed: "), res.Review.ReviewedAt.Format("2006-01-02"))
	ui.Printf("  %s%s\n", ui.Muted("Previous committer: "), res.Review.Committer)

	unified, newFindings := scanner.PKGBUILDDiff(oldSrc, newSrc)
	if unified != "" {
		ui.Printf("\n%s\n", ui.Notice("Diff since last review:"))
		ui.Println(unified)
	}
	// Show any dangerous lines that were ADDED since the last review.
	if len(newFindings) > 0 {
		ui.Printf("\n%s\n", ui.Critical("Newly-introduced issues since last review:"))
		for _, f := range newFindings {
			ui.Printf("  %s %s (%s)\n", ui.Critical(fmt.Sprintf("[%s]", f.Severity)), f.Message, f.Rule)
		}
	}
}

// saveReview persists the current scan state for future update-diff.
func saveReview(res *scanResult) {
	if reviewStore == nil || res.Context == nil || res.Context.AURInfo == nil {
		return
	}
	raw, err := os.ReadFile(filepath.Join(res.PkgDir, "PKGBUILD"))
	if err != nil {
		return
	}
	committer := ""
	if res.Provenance != nil {
		committer = res.Provenance.Maintainer
	}
	rec := &review.Record{
		PackageBase:  res.Pkgbase,
		Committer:    committer,
		PkgbuildHash: review.Hash(raw),
		PkgbuildRaw:  string(raw),
		Verdict:      res.Score.Verdict.String(),
		ReviewedAt:   time.Now(),
	}
	_ = reviewStore.Put(rec)
}
