package main

import (
	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/report"
	"github.com/j0yb0y-m/piq/internal/ui"
)

// Build metadata, set by goreleaser through -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the piq version",
		Args:  exactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if jsonOutput {
				return report.Write(ui.Out(), report.Version{
					SchemaVersion: report.SchemaVersion,
					Command:       "version",
					Version:       version,
					Commit:        commit,
					Date:          date,
				})
			}
			ui.Printf("piq %s (%s, %s)\n", version, commit, date)
			return nil
		},
	}
}
