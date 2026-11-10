package main

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/config"
	"github.com/j0yb0y-m/piq/internal/review"
	"github.com/j0yb0y-m/piq/internal/ui"
)

// Package-level state populated by newRootCmd's PersistentPreRunE before
// any command runs.
var (
	cfg         *config.Config
	reviewStore *review.Store
	jsonOutput  bool
)

// newRootCmd builds the piq command tree.
func newRootCmd() *cobra.Command {
	var configPath string

	root := &cobra.Command{
		Use:           "piq",
		Short:         "piq — a security-first AUR helper",
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			cfg, err = config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			cache, err := cacheDir()
			if err != nil {
				return fmt.Errorf("resolving cache dir: %w", err)
			}
			reviewStore, err = review.NewStore(filepath.Join(cache, "reviews"))
			if err != nil {
				return fmt.Errorf("init review store: %w", err)
			}
			jsonOutput = readJSONFlag(cmd)
			if jsonOutput {
				ui.SetColor(false)
			}
			return nil
		},
	}

	root.PersistentFlags().StringVar(&configPath, "config", "", "path to piq.toml (default: ~/.config/piq/piq.toml)")
	root.PersistentFlags().Bool("json", false, "output in JSON format")

	root.AddCommand(searchCmd(), scanCmd(), installCmd(), systemCmd(), hooksCmd())
	return root
}

// readJSONFlag reads --json from the root persistent flag set. Handlers
// must not consult their own flag set: inherited persistent flags are
// registered on the root, not on the child command.
func readJSONFlag(cmd *cobra.Command) bool {
	enabled, err := cmd.Root().PersistentFlags().GetBool("json")
	return err == nil && enabled
}

// exactArgs requires exactly n positional arguments and classifies the
// failure as a usage error so run exits with exitUsage.
func exactArgs(n int) cobra.PositionalArgs {
	validate := cobra.ExactArgs(n)
	return func(cmd *cobra.Command, args []string) error {
		return coded(exitUsage, validate(cmd, args))
	}
}
