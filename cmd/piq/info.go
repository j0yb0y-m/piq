package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/report"
	"github.com/j0yb0y-m/piq/internal/review"
	"github.com/j0yb0y-m/piq/internal/ui"
)

func infoCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "info <package>",
		Short: "Show AUR package metadata and review status",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			pkgs, err := aur.NewClient().Info(name)
			if err != nil {
				return fmt.Errorf("fetching AUR metadata: %w", err)
			}
			pkg, ok := exactPackage(pkgs, name)
			if !ok {
				return fmt.Errorf("package %q not found on the AUR", name)
			}

			pkgbase := pkg.PackageBase
			if pkgbase == "" {
				pkgbase = pkg.Name
			}
			rec := storedReview(pkgbase)

			if jsonOutput {
				return report.Write(ui.Out(), infoReport(pkg, rec))
			}
			ui.Printf("%s", formatInfo(pkg, rec))
			return nil
		},
	}
}

// exactPackage selects the package whose name matches exactly. Unlike the
// pipeline's fallback, info never guesses: the user asked for one name.
func exactPackage(pkgs []aur.Package, name string) (aur.Package, bool) {
	for _, pkg := range pkgs {
		if pkg.Name == name {
			return pkg, true
		}
	}
	return aur.Package{}, false
}

// formatInfo renders a package's metadata and review status for humans.
func formatInfo(pkg aur.Package, rec *review.Record) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s\n", ui.Accent(pkg.Name), pkg.Version)
	fmt.Fprintf(&b, "  votes:       %d\n", pkg.NumVotes)
	fmt.Fprintf(&b, "  popularity:  %.2f\n", pkg.Popularity)
	maintainer := pkg.Maintainer
	if maintainer == "" {
		maintainer = "orphan"
	}
	fmt.Fprintf(&b, "  maintainer:  %s\n", maintainer)
	if submitted := submittedTime(pkg.FirstSubmitted); submitted != nil {
		fmt.Fprintf(&b, "  submitted:   %s\n", submitted.Format("2006-01-02"))
	} else {
		b.WriteString("  submitted:   unknown\n")
	}
	if pkg.URL != "" {
		fmt.Fprintf(&b, "  url:         %s\n", pkg.URL)
	}
	fmt.Fprintf(&b, "  review:      %s\n", reviewStatus(rec))
	if rec != nil && !rec.ReviewedAt.IsZero() {
		fmt.Fprintf(&b, "  reviewed:    %s\n", rec.ReviewedAt.UTC().Format(time.RFC3339))
	}
	return b.String()
}

// infoReport builds the JSON payload for info.
func infoReport(pkg aur.Package, rec *review.Record) report.Info {
	out := report.Info{
		SchemaVersion: report.SchemaVersion,
		Command:       "info",
		Name:          pkg.Name,
		Version:       pkg.Version,
		Votes:         pkg.NumVotes,
		Popularity:    pkg.Popularity,
		Maintainer:    pkg.Maintainer,
		Submitted:     submittedTime(pkg.FirstSubmitted),
		URL:           pkg.URL,
		ReviewStatus:  reviewStatus(rec),
	}
	if rec != nil && !rec.ReviewedAt.IsZero() {
		reviewed := rec.ReviewedAt.UTC()
		out.ReviewedAt = &reviewed
	}
	return out
}
