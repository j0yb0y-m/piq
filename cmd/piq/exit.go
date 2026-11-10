package main

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/j0yb0y-m/piq/internal/ui"
)

// Process exit codes.
const (
	exitOK      = 0
	exitError   = 1
	exitUsage   = 2
	exitBlocked = 3
)

// codedError carries an explicit exit code through the error chain.
type codedError struct {
	code int
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }

func (e *codedError) Unwrap() error { return e.err }

// coded attaches code to err. A nil err stays nil so it can be returned
// directly from validators.
func coded(code int, err error) error {
	if err == nil {
		return nil
	}
	return &codedError{code: code, err: err}
}

// codeOf reports the exit code associated with err. Usage errors that
// cobra generates itself ("unknown command ...") are classified as
// usage; anything else defaults to a runtime error.
func codeOf(err error) int {
	if err == nil {
		return exitOK
	}
	var ee *codedError
	if errors.As(err, &ee) {
		return ee.code
	}
	if strings.HasPrefix(err.Error(), "unknown command") {
		return exitUsage
	}
	return exitError
}

// execute is the process entry point: it configures the ui writers,
// builds the command tree, and returns the process exit code.
func execute(args []string, stdout, stderr io.Writer) int {
	ui.Init(stdout, stderr)
	return run(newRootCmd(), args, stdout, stderr)
}

// run executes root with args and returns the process exit code. Errors
// are printed exactly once, without usage text, so runtime failures do
// not dump the help screen.
func run(root *cobra.Command, args []string, stdout, stderr io.Writer) int {
	// Direct callers (tests, embedders) do not necessarily go through
	// execute, so keep the ui writers in sync here as well.
	ui.Init(stdout, stderr)

	if !root.SilenceErrors {
		root.SilenceErrors = true
	}
	if !root.SilenceUsage {
		root.SilenceUsage = true
	}

	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return coded(exitUsage, err)
	})
	leafRootForUnknownCommands(root)

	if err := root.Execute(); err != nil {
		ui.Errorf("piq: %v\n", err)
		return codeOf(err)
	}
	return exitOK
}

// leafRootForUnknownCommands makes a non-runnable root without
// subcommands behave like cobra's command trees: positional arguments
// are unknown commands (usage error) rather than a silent help screen
// with exit code zero. Roots with subcommands already get this from
// cobra; runnable roots handle their own arguments.
func leafRootForUnknownCommands(root *cobra.Command) {
	if root.Runnable() || root.HasSubCommands() {
		return
	}
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("unknown command %q for %q", args[0], cmd.CommandPath())
		}
		return cmd.Help()
	}
}
