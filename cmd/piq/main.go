package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/aur"
	"github.com/j0yb0y-m/piq/internal/pipeline"
	"github.com/j0yb0y-m/piq/internal/report"
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
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "piq"), nil
}

func confirm(prompt string) bool {
	if jsonOutput {
		ui.Errorf("%s [y/N] ", ui.Warning(prompt))
	} else {
		ui.Printf("%s [y/N] ", ui.Warning(prompt))
	}
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(strings.ToLower(line)) == "y"
}

func pipelineOptions() (pipeline.Options, error) {
	cache, err := cacheDir()
	if err != nil {
		return pipeline.Options{}, err
	}
	return pipeline.Options{
		CacheDir: cache,
		Config:   cfg,
		Store:    reviewStore,
		Confirm:  confirm,
		JSON:     jsonOutput,
	}, nil
}

func scanCmd() *cobra.Command {
	var deep bool
	cmd := &cobra.Command{
		Use:   "scan <package>",
		Short: "Security-scan a package without installing it",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := pipelineOptions()
			if err != nil {
				return err
			}
			res, err := pipeline.New(opts).Scan(cmd.Context(), args[0], deep)
			if err != nil {
				return err
			}
			if jsonOutput {
				if err := report.Write(ui.Out(), scanReport(res)); err != nil {
					return err
				}
			} else {
				pipeline.PrintFindings(ui.Out(), res)
			}
			if res.Score != nil && res.Score.Blocked {
				return coded(exitBlocked, fmt.Errorf("blocked: %s", res.Score.BlockReason))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&deep, "deep", false, "fetch and scan upstream sources (skipped when the static scan blocks)")
	return cmd
}

func installCmd() *cobra.Command {
	var yes, dryRun, allowNet, noSandbox, force bool
	cmd := &cobra.Command{
		Use:   "install <package>",
		Short: "Scan, review, build, and install a package",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := pipelineOptions()
			if err != nil {
				return err
			}
			opts.Yes = yes
			opts.DryRun = dryRun
			opts.AllowNet = allowNet
			opts.NoSandbox = noSandbox
			opts.Force = force

			res, err := pipeline.New(opts).Install(cmd.Context(), args[0])
			switch {
			case errors.Is(err, pipeline.ErrAborted):
				if !jsonOutput {
					ui.Println("Aborted.")
				}
				return nil
			case errors.Is(err, pipeline.ErrBlocked):
				if jsonOutput && res != nil {
					if werr := report.Write(ui.Out(), scanReportFor(res, "install")); werr != nil {
						return werr
					}
				}
				return coded(exitBlocked, err)
			case err != nil:
				return err
			}
			if jsonOutput {
				return report.Write(ui.Out(), scanReportFor(res, "install"))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "do not prompt for unchanged, clean packages")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "show the plan without building or installing")
	cmd.Flags().BoolVar(&allowNet, "allow-net", false, "allow source preparation and the build to use the network")
	cmd.Flags().BoolVar(&noSandbox, "no-sandbox", false, "permit an unsandboxed build if bubblewrap is unavailable")
	cmd.Flags().BoolVar(&force, "force", false, "install despite blocking findings after extra confirmation")
	return cmd
}
