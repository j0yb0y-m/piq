package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/alpm"
	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/pipeline"
	"github.com/j0yb0y-m/piq/internal/report"
	"github.com/j0yb0y-m/piq/internal/ui"
)

// systemCmd audits all installed AUR packages for known-bad patterns.
func systemCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "system",
		Short: "Audit installed AUR packages",
		RunE: func(cmd *cobra.Command, args []string) error {
			cache, err := cacheDir()
			if err != nil {
				return err
			}

			// List installed packages from AUR by checking each one's
			// origin database. Pacman shows this as `aur/<name>` or
			// `<name> (aur)`.
			out, err := pacmanListAUR()
			if err != nil {
				return fmt.Errorf("listing AUR packages: %w", err)
			}
			if len(out) == 0 {
				if jsonOutput {
					return report.Write(ui.Out(), []report.Scan{})
				}
				ui.Printf("%s\n", ui.Success("No AUR packages found to audit."))
				return nil
			}

			if !jsonOutput {
				ui.Printf("%s\n\n", ui.Notice(fmt.Sprintf("Auditing %d AUR package(s)...", len(out))))
			}

			scans := []report.Scan{}
			var totalFindings int
			for _, pkgname := range out {
				installed, err := alpm.Installed(pkgname)
				if err != nil || !installed {
					continue
				}

				pkgbase := pkgname
				client := aur.NewClient()
				pkgs, _ := client.Info(pkgname)
				if len(pkgs) > 0 && pkgs[0].PackageBase != "" {
					pkgbase = pkgs[0].PackageBase
				}

				pkgDir := filepath.Join(cache, pkgbase)
				// If not cached, clone it silently for scanning.
				if _, err := os.Stat(pkgDir); os.IsNotExist(err) {
					if err := aur.FetchPackage(pkgbase, pkgDir); err != nil {
						skipPackage(pkgname, err)
						continue
					}
				}

				res, err := pipeline.New(pipeline.Options{
					CacheDir: cache,
					Config:   cfg,
					Store:    reviewStore,
					Confirm:  confirm,
					JSON:     jsonOutput,
				}).Scan(cmd.Context(), pkgname, false)
				if err != nil {
					skipPackage(pkgname, err)
					continue
				}
				if jsonOutput {
					scans = append(scans, scanReport(res))
					continue
				}
				if len(res.Score.Findings) > 0 {
					verdict := verdictStyle(res.Score.Verdict)
					ui.Printf("%s — %s (score %d)\n",
						verdict(pkgname), res.Score.Verdict.String(), res.Score.Total)
					for _, f := range res.Score.Findings {
						ui.Printf("  %s %s\n", ui.Muted(fmt.Sprintf("[%s]", f.Severity)), f.Message)
					}
					ui.Println()
					totalFindings += len(res.Score.Findings)
				} else {
					ui.Printf("%s — OK\n", ui.Success(pkgname))
				}
			}

			if jsonOutput {
				return report.Write(ui.Out(), scans)
			}

			if totalFindings == 0 {
				ui.Printf("%s\n", ui.Success("All AUR packages look clean."))
			} else {
				ui.Printf("%s\n", ui.Warning(fmt.Sprintf("%d finding(s) across %d packages.", totalFindings, len(out))))
			}
			return nil
		},
	}
}

// skipPackage reports a package that could not be scanned. In JSON mode
// it writes to stderr so stdout stays valid JSON.
func skipPackage(pkgname string, err error) {
	if jsonOutput {
		ui.Errorf("piq: skipping %s: %v\n", pkgname, err)
		return
	}
	ui.Printf("%s %s: %s\n", ui.Warning("[skip]"), pkgname, err)
}

// pacmanListAUR returns package names whose origin is the AUR.
func pacmanListAUR() ([]string, error) {
	// pacman -Qmq lists foreign (AUR) packages.
	out, err := pacmanOutput("-Qmq")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var pkgs []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l != "" {
			pkgs = append(pkgs, l)
		}
	}
	return pkgs, nil
}

func pacmanOutput(args ...string) (string, error) {
	cmd := exec.Command("pacman", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("pacman %s: %w\n%s", strings.Join(args, " "), err, out)
	}
	return string(out), nil
}
