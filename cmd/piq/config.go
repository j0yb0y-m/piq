package main

import (
	"fmt"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/config"
	"github.com/j0yb0y-m/piq/internal/report"
	"github.com/j0yb0y-m/piq/internal/ui"
)

func configCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "config",
		Short: "Show the effective configuration",
		Args:  exactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := config.Path()
			if explicit, err := cmd.Root().PersistentFlags().GetString("config"); err == nil && explicit != "" {
				path = explicit
			}
			if path == "" {
				path = "(unknown)"
			}

			cache, err := cacheDir()
			if err != nil {
				return err
			}

			if jsonOutput {
				return report.Write(ui.Out(), configReport(path, cache))
			}

			ui.Printf("config: %s\n", path)
			ui.Printf("cache:  %s\n\n", cache)
			data, err := toml.Marshal(cfg)
			if err != nil {
				return fmt.Errorf("encoding config: %w", err)
			}
			ui.Printf("%s", data)
			return nil
		},
	}
}

// configReport builds the JSON payload for config. It reports effective
// values: the resolved config and cache paths, not the raw file contents.
func configReport(path, cache string) report.Config {
	ignore := append([]string{}, cfg.Rules.Ignore...)
	var sandbox *bool
	if cfg.Sandbox.Enabled != nil {
		enabled := *cfg.Sandbox.Enabled
		sandbox = &enabled
	}
	return report.Config{
		SchemaVersion:  report.SchemaVersion,
		Command:        "config",
		ConfigPath:     path,
		CachePath:      cache,
		Severity:       cfg.Severity,
		Threshold:      cfg.Threshold,
		Ignore:         ignore,
		SandboxEnabled: sandbox,
		SudoCmd:        cfg.Pacman.SudoCmd,
	}
}
