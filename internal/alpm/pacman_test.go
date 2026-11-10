package alpm

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stub installs a shell script named name in a fresh temp dir and prepends
// that dir to PATH. The script must be executable; tests never touch a real
// pacman or vercmp.
func stub(t *testing.T, name, script string) string {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write stub %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return path
}

// noBinary clears PATH so exec.Command fails with a start error.
func noBinary(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
}

func TestMissing(t *testing.T) {
	t.Run("lists missing packages and tolerates exit 127", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\necho missing-one\necho missing-two\nexit 127\n")

		got, err := Missing([]string{"a", "b"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != "missing-one" || got[1] != "missing-two" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("exit 0 means nothing missing", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\nexit 0\n")

		got, err := Missing([]string{"a"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("exit 127 with no output means nothing missing", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\nexit 127\n")

		got, err := Missing([]string{"a"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("other non-zero exit is an error even with output", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\necho something\nexit 2\n")

		got, err := Missing([]string{"a"})
		if err == nil {
			t.Fatalf("expected error, got %v", got)
		}
	})

	t.Run("blank lines are trimmed", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\nprintf '\\nmissing\\n\\n'\nexit 127\n")

		got, err := Missing([]string{"a"})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != "missing" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("empty names does not run pacman", func(t *testing.T) {
		noBinary(t)

		got, err := Missing(nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("forwards every name", func(t *testing.T) {
		log := filepath.Join(t.TempDir(), "args")
		t.Setenv("PIQ_STUB_LOG", log)
		stub(t, "pacman", "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PIQ_STUB_LOG\"\nexit 127\n")

		if _, err := Missing([]string{"a", "b"}); err != nil {
			t.Fatal(err)
		}
		assertArgs(t, log, "-T", "a", "b")
	})

	t.Run("binary absent is an error", func(t *testing.T) {
		noBinary(t)

		if _, err := Missing([]string{"a"}); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestForeign(t *testing.T) {
	t.Run("lists foreign packages", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\necho paru\necho yay\n")

		got, err := Foreign()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0] != "paru" || got[1] != "yay" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("empty output yields empty slice", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\nexit 0\n")

		got, err := Foreign()
		if err != nil {
			t.Fatal(err)
		}
		if got == nil || len(got) != 0 {
			t.Fatalf("got %#v, want empty non-nil slice", got)
		}
	})

	t.Run("blank lines are ignored", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\nprintf '\\nparu\\n\\n'\n")

		got, err := Foreign()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0] != "paru" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("non-zero exit is an error", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\nexit 1\n")

		if _, err := Foreign(); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("binary absent is an error", func(t *testing.T) {
		noBinary(t)

		if _, err := Foreign(); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestInOfficial(t *testing.T) {
	t.Run("exit 0 means official", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\nexit 0\n")

		got, err := InOfficial("jq")
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			t.Fatal("want true")
		}
	})

	t.Run("exit 1 means not found", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\nexit 1\n")

		got, err := InOfficial("paru")
		if err != nil {
			t.Fatal(err)
		}
		if got {
			t.Fatal("want false")
		}
	})

	t.Run("binary absent is an error", func(t *testing.T) {
		noBinary(t)

		if _, err := InOfficial("jq"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestInstalled(t *testing.T) {
	t.Run("exit 0 means installed", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\nexit 0\n")

		got, err := Installed("jq")
		if err != nil {
			t.Fatal(err)
		}
		if !got {
			t.Fatal("want true")
		}
	})

	t.Run("exit 1 means not installed", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\nexit 1\n")

		got, err := Installed("paru")
		if err != nil {
			t.Fatal(err)
		}
		if got {
			t.Fatal("want false")
		}
	})

	t.Run("binary absent is an error", func(t *testing.T) {
		noBinary(t)

		if _, err := Installed("jq"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestCheckIntegrity(t *testing.T) {
	t.Run("filters noise", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\necho 'paru: 0 missing files'\necho 'paru: warning: /usr/bin/x (No such file)'\n")

		got, err := CheckIntegrity("paru")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !strings.Contains(got[0], "warning:") {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("non-zero exit still returns findings", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\necho 'paru: warning: /usr/bin/x (No such file)'\necho 'paru: 2 missing files'\nexit 1\n")

		got, err := CheckIntegrity("paru")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("got %v", got)
		}
		if !strings.Contains(got[0], "warning:") || !strings.Contains(got[1], "2 missing files") {
			t.Fatalf("findings out of order or malformed: %v", got)
		}
	})

	t.Run("zero missing summary is dropped", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\necho 'paru: 0 missing files'\nexit 0\n")

		got, err := CheckIntegrity("paru")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("singular one missing file is kept", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\necho 'paru: 1 missing file'\nexit 1\n")

		got, err := CheckIntegrity("paru")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !strings.Contains(got[0], "1 missing file") {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("stderr findings are parsed", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\necho 'paru: warning: /usr/bin/x (No such file)' >&2\nexit 1\n")

		got, err := CheckIntegrity("paru")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || !strings.Contains(got[0], "warning:") {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("binary absent is an error", func(t *testing.T) {
		noBinary(t)

		if _, err := CheckIntegrity("paru"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestCompareVersions(t *testing.T) {
	t.Run("negative result", func(t *testing.T) {
		stub(t, "vercmp", "#!/bin/sh\necho -1\n")

		n, err := CompareVersions("1.0", "2.0")
		if err != nil {
			t.Fatal(err)
		}
		if n != -1 {
			t.Fatalf("n=%d", n)
		}
	})

	t.Run("surrounding newlines parse", func(t *testing.T) {
		stub(t, "vercmp", "#!/bin/sh\nprintf '\\n1\\n'\n")

		n, err := CompareVersions("2.0", "1.0")
		if err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("n=%d", n)
		}
	})

	t.Run("non-integer output is an error", func(t *testing.T) {
		stub(t, "vercmp", "#!/bin/sh\necho not-a-number\n")

		if _, err := CompareVersions("1.0", "2.0"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("empty output is an error", func(t *testing.T) {
		stub(t, "vercmp", "#!/bin/sh\nexit 0\n")

		if _, err := CompareVersions("1.0", "2.0"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("non-zero exit is an error", func(t *testing.T) {
		stub(t, "vercmp", "#!/bin/sh\nexit 2\n")

		if _, err := CompareVersions("1.0", "2.0"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("forwards arguments", func(t *testing.T) {
		log := filepath.Join(t.TempDir(), "args")
		t.Setenv("PIQ_STUB_LOG", log)
		stub(t, "vercmp", "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PIQ_STUB_LOG\"\necho 0\n")

		if _, err := CompareVersions("1.0", "2.0"); err != nil {
			t.Fatal(err)
		}
		assertArgs(t, log, "1.0", "2.0")
	})
}

func TestElevation(t *testing.T) {
	t.Run("sudo with flags", func(t *testing.T) {
		got, err := Elevation("sudo -A")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, ",") != "sudo,-A" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("single command", func(t *testing.T) {
		got, err := Elevation("doas")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, ",") != "doas" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("leading and trailing whitespace", func(t *testing.T) {
		got, err := Elevation("  sudo   -A  ")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, ",") != "sudo,-A" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("empty is an error", func(t *testing.T) {
		if _, err := Elevation(""); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("whitespace only is an error", func(t *testing.T) {
		if _, err := Elevation("   \t "); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestExitError(t *testing.T) {
	t.Run("exposes exit code and stderr via errors.As", func(t *testing.T) {
		stub(t, "pacman", "#!/bin/sh\necho 'something broke' >&2\nexit 3\n")

		_, code, err := run("pacman", "-Q", "jq")
		if err == nil {
			t.Fatal("expected error")
		}
		if code != 3 {
			t.Fatalf("code=%d", code)
		}

		var exitErr *ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("errors.As failed for %T: %v", err, err)
		}
		if exitErr.ExitCode() != 3 {
			t.Fatalf("ExitCode()=%d", exitErr.ExitCode())
		}
		if !strings.Contains(exitErr.Stderr, "something broke") {
			t.Fatalf("stderr=%q", exitErr.Stderr)
		}
		if !strings.Contains(exitErr.Error(), "something broke") {
			t.Fatalf("error message should retain stderr: %q", exitErr.Error())
		}
	})

	t.Run("start failure is not an ExitError", func(t *testing.T) {
		noBinary(t)

		_, _, err := run("pacman", "-Q", "jq")
		if err == nil {
			t.Fatal("expected error")
		}
		var exitErr *ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("start failure wrapped as ExitError: %v", err)
		}
	})
}

func assertArgs(t *testing.T, log string, want ...string) {
	t.Helper()

	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatalf("read stub log: %v", err)
	}
	got := strings.Fields(string(data))
	if len(got) != len(want) {
		t.Fatalf("args=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("args=%v, want %v", got, want)
		}
	}
}
