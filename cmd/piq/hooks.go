package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/ui"
)

func hooksCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "hooks",
		Short: "Install yay/paru hook files that route AUR installs through piq",
		RunE: func(cmd *cobra.Command, args []string) error {
			installed := 0

			if cfg != nil && cfg.Hooks.Yay != "" {
				if err := writeHook(cfg.Hooks.Yay, yayHookContent()); err != nil {
					fmt.Printf("%syay hook:%s %s\n", ui.Peach, ui.Text, err)
				} else {
					fmt.Printf("%syay hook installed -> %s%s\n", ui.Green, cfg.Hooks.Yay, ui.Text)
					installed++
				}
			}

			if cfg != nil && cfg.Hooks.Paru != "" {
				if err := writeHook(cfg.Hooks.Paru, paruHookContent()); err != nil {
					fmt.Printf("%sparu hook:%s %s\n", ui.Peach, ui.Text, err)
				} else {
					fmt.Printf("%sparu hook installed -> %s%s\n", ui.Green, cfg.Hooks.Paru, ui.Text)
					installed++
				}
			}

			if installed == 0 {
				fmt.Printf("%sNo hook targets configured.%s Set hooks.yay/hooks.paru in piq.toml.\n", ui.Peach, ui.Text)
				fmt.Println()
				fmt.Println("Example piq.toml:")
				fmt.Println()
				fmt.Println("  [hooks]")
				if runtime.GOOS == "linux" {
					fmt.Println(`  yay  = "/usr/share/libalpm/hooks/90-piq-yay.hook"`)
					fmt.Println(`  paru = "/usr/share/libalpm/hooks/90-piq-paru.hook"`)
				}
			}
			return nil
		},
	}
}

func writeHook(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

// yayHookContent generates a proper alpm hook that intercepts
// yay install transactions and runs piq scan before they proceed.
func yayHookContent() string {
	return `[Trigger]
Type = Transaction
Operation = Install
Operation = Upgrade
Target = *

[Action]
Description = piq security scan before yay install...
When = PreTransaction
Exec = /usr/bin/piq scan --json %PKGNAME%
AbortTransaction = Yes
Failure = Report
`
}

// paruHookContent generates a proper alpm hook for paru.
func paruHookContent() string {
	return `[Trigger]
Type = Transaction
Operation = Install
Operation = Upgrade
Target = *

[Action]
Description = piq security scan before paru install...
When = PreTransaction
Exec = /usr/bin/piq scan --json %PKGNAME%
AbortTransaction = Yes
Failure = Report
`
}
