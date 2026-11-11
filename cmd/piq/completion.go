package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/ui"
)

func completionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion <bash|zsh|fish>",
		Short: "Generate a shell completion script",
		Args:  exactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletionV2(ui.Out(), true)
			case "zsh":
				return cmd.Root().GenZshCompletion(ui.Out())
			case "fish":
				return cmd.Root().GenFishCompletion(ui.Out(), true)
			default:
				return coded(exitUsage, fmt.Errorf("unsupported shell %q (want bash, zsh, or fish)", args[0]))
			}
		},
	}
}
