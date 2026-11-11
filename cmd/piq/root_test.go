package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRunPrintsErrorOnce(t *testing.T) {
	root := &cobra.Command{Use: "piq", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(&cobra.Command{Use: "boom", RunE: func(*cobra.Command, []string) error {
		return errors.New("boom")
	}})
	var out, errb bytes.Buffer
	if code := run(root, []string{"boom"}, &out, &errb); code != exitError {
		t.Fatalf("code = %d, want %d", code, exitError)
	}
	if n := strings.Count(errb.String(), "boom"); n != 1 {
		t.Fatalf("error printed %d times, want 1: %q", n, errb.String())
	}
}

func TestRunUsageExitCode(t *testing.T) {
	root := &cobra.Command{Use: "piq", SilenceErrors: true, SilenceUsage: true}
	root.Flags().Bool("real", false, "")
	var out, errb bytes.Buffer
	if code := run(root, []string{"--nope"}, &out, &errb); code != exitUsage {
		t.Fatalf("code = %d, want %d", code, exitUsage)
	}
}

func TestRunBlockedExitCode(t *testing.T) {
	root := &cobra.Command{Use: "piq", SilenceErrors: true, SilenceUsage: true}
	root.AddCommand(&cobra.Command{Use: "blocked", RunE: func(*cobra.Command, []string) error {
		return coded(exitBlocked, errors.New("blocked"))
	}})
	var out, errb bytes.Buffer
	if code := run(root, []string{"blocked"}, &out, &errb); code != exitBlocked {
		t.Fatalf("code = %d, want %d", code, exitBlocked)
	}
}

func TestRunUnknownCommandIsUsageError(t *testing.T) {
	root := &cobra.Command{Use: "piq", SilenceErrors: true, SilenceUsage: true}
	var out, errb bytes.Buffer
	if code := run(root, []string{"nope"}, &out, &errb); code != exitUsage {
		t.Fatalf("code = %d, want %d", code, exitUsage)
	}
}

// TestReadJSONFlagFromRootPersistentFlag guards resolution R3: handlers
// must read --json from the root persistent flag, not from their own
// command's flag set.
func TestReadJSONFlagFromRootPersistentFlag(t *testing.T) {
	root := &cobra.Command{Use: "piq"}
	var got bool
	child := &cobra.Command{Use: "child", RunE: func(cmd *cobra.Command, args []string) error {
		got = readJSONFlag(cmd)
		return nil
	}}
	root.AddCommand(child)
	root.PersistentFlags().Bool("json", false, "")

	var out, errb bytes.Buffer
	if code := run(root, []string{"child", "--json"}, &out, &errb); code != exitOK {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitOK, errb.String())
	}
	if !got {
		t.Fatal("child saw json=false, want true")
	}
}

// TestCommandsExposePipelineFlags guards the user-facing surface of the
// scan and install pipeline: every flag must stay wired to a flag variable.
func TestCommandsExposePipelineFlags(t *testing.T) {
	root := newRootCmd()
	tests := []struct {
		command string
		flags   []string
	}{
		{"scan", []string{"deep"}},
		{"install", []string{"yes", "dry-run", "allow-net", "no-sandbox", "force"}},
	}
	for _, tc := range tests {
		cmd, _, err := root.Find([]string{tc.command})
		if err != nil {
			t.Fatalf("find %s: %v", tc.command, err)
		}
		for _, name := range tc.flags {
			if cmd.Flags().Lookup(name) == nil {
				t.Errorf("%s missing flag --%s", tc.command, name)
			}
		}
	}
}

// TestNewRootCmdSetsJSONOutput verifies the root's PersistentPreRunE
// publishes the parsed --json value in the package global handlers read.
func TestNewRootCmdSetsJSONOutput(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	root := newRootCmd()
	var got bool
	root.AddCommand(&cobra.Command{Use: "probe", RunE: func(cmd *cobra.Command, args []string) error {
		got = jsonOutput
		return nil
	}})

	var out, errb bytes.Buffer
	if code := run(root, []string{"--json", "probe"}, &out, &errb); code != exitOK {
		t.Fatalf("code = %d, want %d (stderr %q)", code, exitOK, errb.String())
	}
	if !got {
		t.Fatal("probe saw jsonOutput=false, want true")
	}
}
