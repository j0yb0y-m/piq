// Package config loads piq's user configuration from a TOML file at
// ~/.config/piq/piq.toml, with environment-variable overrides for the
// most security-relevant knobs. A missing file is not an error — piq
// ships sane defaults and runs fine with zero configuration.
package config

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// errInvalidConfig marks configuration that failed validation.
var errInvalidConfig = errors.New("invalid config")

// Config is the top-level user configuration tree.
type Config struct {
	Severity  string  `toml:"severity"`  // minimum severity to block on: info|warning|critical
	Threshold int     `toml:"threshold"` // minimum cumulative risk score to block on (0-1000)
	CacheDir  string  `toml:"cache_dir"`
	Rules     Rules   `toml:"rules"`
	Sandbox   Sandbox `toml:"sandbox"`
	Pacman    Pacman  `toml:"pacman"`
}

// Rules lets users silence specific checks by rule ID.
type Rules struct {
	Ignore []string `toml:"ignore"`
}

// Sandbox controls whether builds are wrapped in bubblewrap.
type Sandbox struct {
	Enabled *bool `toml:"enabled"` // nil = auto-detect (default on if bwrap present)
}

// Pacman controls how package installation is elevated.
type Pacman struct {
	SudoCmd string `toml:"sudo_cmd"` // e.g. "sudo", "doas", "sudo -A"
}

// Default returns the built-in configuration.
func Default() *Config {
	return &Config{
		Severity:  "warning",
		Threshold: 80,
		CacheDir:  defaultCacheDir(),
		Rules:     Rules{},
		Sandbox:   Sandbox{Enabled: nil},
		Pacman:    Pacman{SudoCmd: "sudo"},
	}
}

func defaultCacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "piq")
}

// Path returns the absolute path of the primary config file.
func Path() string {
	d, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(d, "piq", "piq.toml")
}

// Load reads the config file at the given explicit path, or the
// default location if path is empty. env overrides are then applied.
func Load(path string) (*Config, error) {
	cfg := Default()
	if path == "" {
		path = Path()
	}
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
		} else {
			if err := toml.Unmarshal(data, cfg); err != nil {
				return nil, err
			}
		}
	}
	applyEnv(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyEnv layers PIQ_* environment variables on top of the file.
func applyEnv(c *Config) {
	str := func(key string, set func(string)) {
		if v, ok := os.LookupEnv(key); ok {
			set(v)
		}
	}
	intEnv := func(key string, set func(int)) {
		if v, ok := os.LookupEnv(key); ok {
			if n, err := strconv.Atoi(v); err == nil {
				set(n)
			}
		}
	}

	str("PIQ_SEVERITY", func(v string) { c.Severity = v })
	intEnv("PIQ_THRESHOLD", func(v int) { c.Threshold = v })
	str("PIQ_CACHE_DIR", func(v string) { c.CacheDir = v })
	str("PIQ_SUDO_CMD", func(v string) { c.Pacman.SudoCmd = v })
	str("PIQ_RULES_IGNORE", func(v string) {
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id != "" {
				c.Rules.Ignore = append(c.Rules.Ignore, id)
			}
		}
	})
}

// Validate normalizes and checks configuration values. It is called by
// Load after environment overrides have been applied.
func (c *Config) Validate() error {
	severity := strings.ToLower(strings.TrimSpace(c.Severity))
	switch severity {
	case "info", "warning", "critical":
		c.Severity = severity
	default:
		return fmt.Errorf("%w: severity %q (want info, warning, or critical)", errInvalidConfig, c.Severity)
	}

	if c.Threshold < 0 || c.Threshold > 1000 {
		return fmt.Errorf("%w: threshold %d out of range 0-1000", errInvalidConfig, c.Threshold)
	}

	if c.CacheDir != "" && !filepath.IsAbs(c.CacheDir) {
		return fmt.Errorf("%w: cache_dir %q must be absolute", errInvalidConfig, c.CacheDir)
	}

	if len(strings.Fields(c.Pacman.SudoCmd)) == 0 {
		return fmt.Errorf("%w: pacman.sudo_cmd must not be empty", errInvalidConfig)
	}

	return nil
}

// IgnoreSet returns the configured rule IDs as a set.
func (c *Config) IgnoreSet() map[string]bool {
	set := make(map[string]bool, len(c.Rules.Ignore))
	for _, id := range c.Rules.Ignore {
		set[id] = true
	}
	return set
}

// IgnoresRule reports whether the given rule ID is user-suppressed.
func (c *Config) IgnoresRule(id string) bool {
	set := c.IgnoreSet()
	return set[id] || set["*"]
}

// SandboxEnabled resolves the effective sandbox setting.
func (c *Config) SandboxEnabled() bool {
	if c.Sandbox.Enabled != nil {
		return *c.Sandbox.Enabled
	}
	_, err := exec.LookPath("bwrap")
	return err == nil
}

// SandboxExplicitlyDisabled reports whether the user turned sandboxing
// off in config. Unlike SandboxEnabled it never auto-detects bwrap: a
// missing binary with the default setting must not silently authorize
// an unsandboxed build.
func (c *Config) SandboxExplicitlyDisabled() bool {
	return c != nil && c.Sandbox.Enabled != nil && !*c.Sandbox.Enabled
}
