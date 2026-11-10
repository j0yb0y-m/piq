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
				fmt.Printf("%sNo AUR packages found to audit.%s\n", ui.Green, ui.Text)
				return nil
			}

			fmt.Printf("%sAuditing %d AUR package(s)...%s\n\n", ui.Blue, len(out), ui.Text)

			var totalFindings int
			for _, pkgname := range out {
				if !alpm.IsInstalled(pkgname) {
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
						fmt.Printf("%s[skip]%s %s: %s\n", ui.Peach, ui.Text, pkgname, err)
						continue
					}
				}

				res, err := scanPackage(pkgname, reviewStore)
				if err != nil {
					fmt.Printf("%s[skip]%s %s: %s\n", ui.Peach, ui.Text, pkgname, err)
					continue
				}
				if len(res.Score.Findings) > 0 {
					color := verdictColor(res.Score.Verdict)
					fmt.Printf("%s%s%s — %s (score %d)\n",
						color, pkgname, ui.Text, res.Score.Verdict.String(), res.Score.Total)
					for _, f := range res.Score.Findings {
						fmt.Printf("  %s[%s]%s %s\n", ui.Overlay0, f.Severity, ui.Text, f.Message)
					}
					fmt.Println()
					totalFindings += len(res.Score.Findings)
				} else {
					fmt.Printf("%s%s%s — OK\n", ui.Green, pkgname, ui.Text)
				}
			}

			if totalFindings == 0 {
				fmt.Printf("%sAll AUR packages look clean.%s\n", ui.Green, ui.Text)
			} else {
				fmt.Printf("%s%d finding(s) across %d packages.%s\n",
					ui.Peach, totalFindings, len(out), ui.Text)
			}
			return nil
		},
	}
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
