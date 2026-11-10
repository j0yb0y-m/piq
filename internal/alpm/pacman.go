package alpm

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// ExitError describes a command that ran but exited non-zero. It retains the
// captured stderr so callers can surface pacman's diagnostics.
type ExitError struct {
	Code   int
	Stderr string
}

func (e *ExitError) Error() string {
	if s := strings.TrimSpace(e.Stderr); s != "" {
		return fmt.Sprintf("exit status %d: %s", e.Code, s)
	}
	return fmt.Sprintf("exit status %d", e.Code)
}

// ExitCode returns the process exit code.
func (e *ExitError) ExitCode() int { return e.Code }

// run executes name with args and returns captured stdout, the exit code, and
// an error. A non-zero exit yields an *ExitError carrying the code and stderr;
// a start failure (for example a missing binary) yields a wrapped error that
// is not an *ExitError.
func run(name string, args ...string) (string, int, error) {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err == nil {
		return stdout.String(), 0, nil
	}

	var execErr *exec.ExitError
	if errors.As(err, &execErr) {
		code := execErr.ExitCode()
		exitErr := &ExitError{Code: code, Stderr: stderr.String()}
		return stdout.String(), code, exitErr
	}

	return stdout.String(), -1, fmt.Errorf("run %s: %w", name, err)
}

// Missing returns the subset of names that pacman -T reports as not provided
// by an installed package. An empty names slice returns nil without invoking
// pacman.
func Missing(names []string) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}

	args := append([]string{"-T"}, names...)
	out, _, err := run("pacman", args...)
	if err == nil {
		// pacman -T exits 0 when every name is satisfied.
		return nil, nil
	}

	var exitErr *ExitError
	if errors.As(err, &exitErr) && exitErr.Code == 127 {
		// 127 with no output also means nothing is missing.
		return nonEmptyLines(out), nil
	}
	return nil, err
}

// InOfficial reports whether name is available from a configured sync
// repository. A non-zero exit means "not found"; only a failure to start
// pacman is returned as an error.
func InOfficial(name string) (bool, error) {
	_, _, err := run("pacman", "-Si", name)
	if err == nil {
		return true, nil
	}

	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, err
}

// Installed reports whether name is present in the local package database.
// A non-zero exit means "not installed"; only a failure to start pacman is
// returned as an error.
func Installed(name string) (bool, error) {
	_, _, err := run("pacman", "-Q", name)
	if err == nil {
		return true, nil
	}

	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return false, nil
	}
	return false, err
}

// Foreign returns installed packages that are not in any sync repository,
// which is where AUR packages live.
func Foreign() ([]string, error) {
	out, _, err := run("pacman", "-Qmq")
	if err != nil {
		return nil, err
	}
	return nonEmptyLines(out), nil
}

var missingFilesPattern = regexp.MustCompile(`(\d+)\s+missing\s+files?`)

// CheckIntegrity runs pacman -Qkk and returns the integrity findings for pkg.
// A non-zero exit is expected when files are missing, so findings are parsed
// from both stdout and stderr instead of being treated as a failure.
func CheckIntegrity(pkg string) ([]string, error) {
	out, _, err := run("pacman", "-Qkk", pkg)
	if err != nil {
		var exitErr *ExitError
		if !errors.As(err, &exitErr) {
			return nil, err
		}
		out += "\n" + exitErr.Stderr
	}

	findings := make([]string, 0)
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "warning:") {
			findings = append(findings, line)
			continue
		}
		if match := missingFilesPattern.FindStringSubmatch(line); match != nil {
			n, convErr := strconv.Atoi(match[1])
			if convErr == nil && n > 0 {
				findings = append(findings, line)
			}
		}
	}
	return findings, nil
}

// CompareVersions compares two version strings using vercmp. It returns a
// negative number when a is older than b, zero when they are equal, and a
// positive number when a is newer.
func CompareVersions(a, b string) (int, error) {
	out, _, err := run("vercmp", a, b)
	if err != nil {
		return 0, err
	}

	trimmed := strings.TrimSpace(out)
	n, convErr := strconv.Atoi(trimmed)
	if convErr != nil {
		return 0, fmt.Errorf("parse vercmp output %q: %w", trimmed, convErr)
	}
	return n, nil
}

// Elevation parses the configured privilege-elevation command (for example
// "sudo -A") into an argv prefix. It does not execute anything.
func Elevation(sudoCmd string) ([]string, error) {
	fields := strings.Fields(sudoCmd)
	if len(fields) == 0 {
		return nil, errors.New("elevation command is empty")
	}
	return fields, nil
}

func nonEmptyLines(s string) []string {
	lines := make([]string, 0)
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
