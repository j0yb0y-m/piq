package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/alpm"
	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/pipeline"
	"github.com/j0yb0y-m/piq/internal/report"
	"github.com/j0yb0y-m/piq/internal/review"
	"github.com/j0yb0y-m/piq/internal/ui"
)

func auditCmd() *cobra.Command {
	var deep, integrity bool
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Audit installed foreign (AUR) packages",
		Args:  exactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			names, err := alpm.Foreign()
			if err != nil {
				return fmt.Errorf("listing foreign packages: %w", err)
			}

			out := report.Audit{
				SchemaVersion: report.SchemaVersion,
				Command:       "audit",
				Packages:      []report.AuditEntry{},
			}
			if len(names) == 0 {
				if jsonOutput {
					return report.Write(ui.Out(), out)
				}
				ui.Printf("%s\n", ui.Success("No foreign packages found to audit."))
				return nil
			}

			client := aur.NewClient()
			pkgs, err := client.Info(names...)
			if err != nil {
				return fmt.Errorf("fetching AUR metadata: %w", err)
			}
			byName := make(map[string]aur.Package, len(pkgs))
			for _, pkg := range pkgs {
				byName[pkg.Name] = pkg
			}

			versions, err := alpm.InstalledVersions()
			if err != nil {
				return fmt.Errorf("reading installed versions: %w", err)
			}

			var scanner *pipeline.Pipeline
			if deep {
				cache, err := cacheDir()
				if err != nil {
					return err
				}
				scanner = pipeline.New(pipeline.Options{
					CacheDir: cache,
					Config:   cfg,
					Store:    reviewStore,
					Confirm:  confirm,
					JSON:     jsonOutput,
				})
			}

			if !jsonOutput {
				ui.Printf("%s\n\n", ui.Notice(fmt.Sprintf("Auditing %d foreign package(s)...", len(names))))
			}

			var outdated, unreviewed, blocked, integrityFindings int
			for _, name := range names {
				entry := report.AuditEntry{
					Package:   name,
					Installed: versions[name],
				}

				pkgbase := name
				if pkg, ok := byName[name]; ok {
					pkgbase = pkg.PackageBase
					if pkgbase == "" {
						pkgbase = pkg.Name
					}
					entry.AURVersion = pkg.Version
					entry.Outdated = versionIsOlder(entry.Installed, pkg.Version)
				}

				rec := storedReview(pkgbase)
				entry.ReviewStatus = reviewStatus(rec)

				if deep {
					res, err := scanner.Scan(cmd.Context(), name, false)
					switch {
					case err != nil:
						entry.Error = err.Error()
					default:
						entry.Verdict = res.Score.Verdict.String()
						entry.Score = res.Score.Total
						entry.Blocked = res.Score.Blocked
						entry.Findings = findingsReport(res.Score.Findings)
						if rec != nil && !rec.Matches(res.Commit, res.PkgbuildHash, res.SrcinfoHash, res.ScriptletHash) {
							entry.ReviewStatus = "changed"
						}
					}
				}

				if integrity {
					findings, err := alpm.CheckIntegrity(name)
					if err != nil {
						if entry.Error == "" {
							entry.Error = err.Error()
						} else {
							entry.Error += "; " + err.Error()
						}
					} else {
						entry.Integrity = findings
					}
				}

				if entry.Outdated {
					outdated++
				}
				if entry.ReviewStatus == "unreviewed" {
					unreviewed++
				}
				if entry.Blocked {
					blocked++
				}
				integrityFindings += len(entry.Integrity)
				out.Packages = append(out.Packages, entry)

				if jsonOutput {
					continue
				}
				printAuditEntry(entry, deep, rec)
			}

			if jsonOutput {
				return report.Write(ui.Out(), out)
			}
			ui.Printf("%s\n", auditSummary(len(names), outdated, unreviewed, blocked, integrityFindings))
			return nil
		},
	}
	cmd.Flags().BoolVar(&deep, "deep", false, "scan each package's PKGBUILD for risk findings")
	cmd.Flags().BoolVar(&integrity, "integrity", false, "verify installed file integrity with pacman -Qkk")
	return cmd
}

// printAuditEntry renders one audit row plus optional finding details.
func printAuditEntry(entry report.AuditEntry, deep bool, rec *review.Record) {
	if deep && entry.Verdict != "" {
		ui.Printf("%s\n", auditLine(entry.Package, entry.Installed, entry.AURVersion, rec))
		ui.Printf("  verdict: %s, risk score %d\n", entry.Verdict, entry.Score)
		for _, f := range entry.Findings {
			ui.Printf("  [%s] %s\n", f.Severity, f.Message)
			if f.Line > 0 {
				ui.Printf("    → %s:%d (%s)\n", f.File, f.Line, f.Rule)
			} else if f.File != "" || f.Rule != "" {
				ui.Printf("    → %s (%s)\n", f.File, f.Rule)
			}
		}
		if entry.ReviewStatus == "changed" {
			ui.Printf("  review: %s\n", ui.Warning("changed since last review"))
		}
	} else {
		ui.Printf("%s\n", auditLine(entry.Package, entry.Installed, entry.AURVersion, rec))
	}
	for _, finding := range entry.Integrity {
		ui.Printf("  %s %s\n", ui.Warning("integrity:"), finding)
	}
	if entry.Error != "" {
		ui.Printf("  %s %s\n", ui.Warning("[error]"), entry.Error)
	}
}

// auditSummary renders the closing count line.
func auditSummary(total, outdated, unreviewed, blocked, integrity int) string {
	parts := []string{
		fmt.Sprintf("%d outdated", outdated),
		fmt.Sprintf("%d unreviewed", unreviewed),
	}
	if blocked > 0 {
		parts = append(parts, fmt.Sprintf("%d blocked", blocked))
	}
	if integrity > 0 {
		parts = append(parts, fmt.Sprintf("%d integrity finding(s)", integrity))
	}
	return fmt.Sprintf("%d package(s): %s.", total, strings.Join(parts, ", "))
}

// auditLine formats one package's installed/AUR version and review status.
// Version differences are labeled outdated; the command computes the
// authoritative ordering with vercmp for the JSON report.
func auditLine(pkg, installed, aurVersion string, rec *review.Record) string {
	var b strings.Builder
	b.WriteString(pkg)
	switch {
	case aurVersion == "":
		fmt.Fprintf(&b, " %s [not in AUR]", installed)
	case installed == "":
		fmt.Fprintf(&b, " %s", aurVersion)
	case installed == aurVersion:
		fmt.Fprintf(&b, " %s [current]", installed)
	default:
		fmt.Fprintf(&b, " %s → %s [outdated]", installed, aurVersion)
	}
	if rec == nil {
		b.WriteString(" [unreviewed]")
	} else {
		b.WriteString(" [reviewed]")
	}
	return b.String()
}

// versionIsOlder reports whether installed is older than available. If
// vercmp is unavailable, differing versions are treated as outdated.
func versionIsOlder(installed, available string) bool {
	if installed == "" || available == "" {
		return false
	}
	cmp, err := alpm.CompareVersions(installed, available)
	if err != nil {
		return installed != available
	}
	return cmp < 0
}

// storedReview returns the saved review for a package base, or nil when
// none exists or the record cannot be read.
func storedReview(pkgbase string) *review.Record {
	if reviewStore == nil || pkgbase == "" {
		return nil
	}
	rec, err := reviewStore.Get(pkgbase)
	if err != nil {
		return nil
	}
	return rec
}

// reviewStatus describes a stored review in one word.
func reviewStatus(rec *review.Record) string {
	if rec == nil {
		return "unreviewed"
	}
	return "reviewed"
}

// submittedTime converts AUR's Unix-seconds field, returning nil for zero.
func submittedTime(seconds int64) *time.Time {
	if seconds <= 0 {
		return nil
	}
	t := time.Unix(seconds, 0).UTC()
	return &t
}
