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
					ui.Printf("%s %s\n", ui.Warning("yay hook:"), err)
				} else {
					ui.Printf("%s\n", ui.Success(fmt.Sprintf("yay hook installed -> %s", cfg.Hooks.Yay)))
					installed++
				}
			}

			if cfg != nil && cfg.Hooks.Paru != "" {
				if err := writeHook(cfg.Hooks.Paru, paruHookContent()); err != nil {
					ui.Printf("%s %s\n", ui.Warning("paru hook:"), err)
				} else {
					ui.Printf("%s\n", ui.Success(fmt.Sprintf("paru hook installed -> %s", cfg.Hooks.Paru)))
					installed++
				}
			}

			if installed == 0 {
				ui.Printf("%s Set hooks.yay/hooks.paru in piq.toml.\n", ui.Warning("No hook targets configured."))
				ui.Println()
				ui.Println("Example piq.toml:")
				ui.Println()
				ui.Println("  [hooks]")
				if runtime.GOOS == "linux" {
					ui.Println(`  yay  = "/usr/share/libalpm/hooks/90-piq-yay.hook"`)
					ui.Println(`  paru = "/usr/share/libalpm/hooks/90-piq-paru.hook"`)
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
