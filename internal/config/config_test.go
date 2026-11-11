package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestDefault(t *testing.T) {
	cfg := Default()
	if cfg.Severity != "warning" {
		t.Errorf("expected severity=warning, got %q", cfg.Severity)
	}
	if cfg.Threshold != 80 {
		t.Errorf("expected threshold=80, got %d", cfg.Threshold)
	}
	if cfg.Pacman.SudoCmd != "sudo" {
		t.Errorf("expected sudo_cmd=sudo, got %q", cfg.Pacman.SudoCmd)
	}
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load("/nonexistent/path/piq.toml")
	if err != nil {
		t.Fatalf("unexpected error loading missing file: %v", err)
	}
	if cfg.Severity != "warning" {
		t.Errorf("expected defaults, got severity=%q", cfg.Severity)
	}
}

func TestLoadTOML(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "piq.toml")
	content := `
severity = "critical"
threshold = 50
cache_dir = "/tmp/piq-test"

[rules]
ignore = ["typosquat", "reputation"]

[pacman]
sudo_cmd = "doas"
`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Severity != "critical" {
		t.Errorf("expected severity=critical, got %q", cfg.Severity)
	}
	if cfg.Threshold != 50 {
		t.Errorf("expected threshold=50, got %d", cfg.Threshold)
	}
	if cfg.CacheDir != "/tmp/piq-test" {
		t.Errorf("expected cache_dir=/tmp/piq-test, got %q", cfg.CacheDir)
	}
	if len(cfg.Rules.Ignore) != 2 {
		t.Fatalf("expected 2 ignored rules, got %d", len(cfg.Rules.Ignore))
	}
	if cfg.Pacman.SudoCmd != "doas" {
		t.Errorf("expected sudo_cmd=doas, got %q", cfg.Pacman.SudoCmd)
	}
}

func TestIgnoresRule(t *testing.T) {
	cfg := &Config{Rules: Rules{Ignore: []string{"typosquat", "reputation"}}}
	if !cfg.IgnoresRule("typosquat") {
		t.Error("expected typosquat to be ignored")
	}
	if !cfg.IgnoresRule("reputation") {
		t.Error("expected reputation to be ignored")
	}
	if cfg.IgnoresRule("pipe-to-shell") {
		t.Error("pipe-to-shell should not be ignored")
	}
}

func TestIgnoresAll(t *testing.T) {
	cfg := &Config{Rules: Rules{Ignore: []string{"*"}}}
	if !cfg.IgnoresRule("anything") {
		t.Error("wildcard should ignore everything")
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("PIQ_SEVERITY", "info")
	t.Setenv("PIQ_THRESHOLD", "25")
	t.Setenv("PIQ_CACHE_DIR", "/env/test")
	t.Setenv("PIQ_SUDO_CMD", "sudo -A")
	t.Setenv("PIQ_RULES_IGNORE", "typosquat, reputation")

	cfg := Default()
	applyEnv(cfg)

	if cfg.Severity != "info" {
		t.Errorf("expected severity=info, got %q", cfg.Severity)
	}
	if cfg.Threshold != 25 {
		t.Errorf("expected threshold=25, got %d", cfg.Threshold)
	}
	if cfg.CacheDir != "/env/test" {
		t.Errorf("expected cache_dir=/env/test, got %q", cfg.CacheDir)
	}
	if cfg.Pacman.SudoCmd != "sudo -A" {
		t.Errorf("expected sudo_cmd=sudo -A, got %q", cfg.Pacman.SudoCmd)
	}
	if len(cfg.Rules.Ignore) != 2 {
		t.Errorf("expected 2 ignored rules from env, got %d", len(cfg.Rules.Ignore))
	}
}

func TestValidateRejectsUnknownSeverity(t *testing.T) {
	c := Default()
	c.Severity = "paranoid"
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateRejectsNegativeThreshold(t *testing.T) {
	c := Default()
	c.Threshold = -1
	if err := c.Validate(); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateNormalizesSeverity(t *testing.T) {
	c := Default()
	c.Severity = "  WARNING "
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Severity != "warning" {
		t.Errorf("severity = %q", c.Severity)
	}
}

func TestIgnoreSet(t *testing.T) {
	c := Default()
	c.Rules.Ignore = []string{"reputation", "typosquat"}
	if !c.IgnoreSet()["reputation"] || !c.IgnoreSet()["typosquat"] {
		t.Fatal("missing rule")
	}
}

func TestLoadRejectsInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "piq.toml")
	os.WriteFile(path, []byte(`severity = "nope"`), 0o644)
	if _, err := Load(path); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestSandboxExplicitlyDisabled(t *testing.T) {
	cfg := &Config{}
	if cfg.SandboxExplicitlyDisabled() {
		t.Error("nil sandbox setting must not count as explicitly disabled")
	}

	enabled := true
	cfg = &Config{Sandbox: Sandbox{Enabled: &enabled}}
	if cfg.SandboxExplicitlyDisabled() {
		t.Error("explicitly enabled sandbox reported as disabled")
	}

	disabled := false
	cfg = &Config{Sandbox: Sandbox{Enabled: &disabled}}
	if !cfg.SandboxExplicitlyDisabled() {
		t.Error("explicitly disabled sandbox not reported")
	}

	var nilConfig *Config
	if nilConfig.SandboxExplicitlyDisabled() {
		t.Error("nil config must not count as explicitly disabled")
	}
}

func TestSandboxEnabled(t *testing.T) {
	// With explicit true
	b := true
	cfg := &Config{Sandbox: Sandbox{Enabled: &b}}
	if !cfg.SandboxEnabled() {
		t.Error("expected sandbox enabled")
	}

	// With explicit false
	b = false
	cfg = &Config{Sandbox: Sandbox{Enabled: &b}}
	if cfg.SandboxEnabled() {
		t.Error("expected sandbox disabled")
	}

	// With nil — auto-detect based on bwrap presence
	if _, err := exec.LookPath("bwrap"); err == nil {
		t.Skip("bwrap is installed; cannot assert auto-detect is false")
	}
	cfg = &Config{Sandbox: Sandbox{Enabled: nil}}
	if cfg.SandboxEnabled() {
		t.Error("expected sandbox disabled without bwrap")
	}
}
