// Package config loads piq's user configuration from a TOML file at
// ~/.config/piq/piq.toml, with environment-variable overrides for the
// most security-relevant knobs. A missing file is not an error — piq
// ships sane defaults and runs fine with zero configuration.
package config

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Config is the top-level user configuration tree.
type Config struct {
	Severity  string     `toml:"severity"`  // minimum severity to block on: info|warning|critical
	Threshold int        `toml:"threshold"` // minimum cumulative risk score to block on (0-100+)
	CacheDir  string     `toml:"cache_dir"`
	Network   Network    `toml:"network"`
	Rules     Rules      `toml:"rules"`
	Hooks     Hooks      `toml:"hooks"`
	Sandbox   Sandbox    `toml:"sandbox"`
	Pacman    Pacman     `toml:"pacman"`
}

// Network controls network behavior during a scan/build.
type Network struct {
	NoScan bool `toml:"no_scan"` // skip the reputation / AUR metadata scan
}

// Rules lets users silence specific checks by rule ID.
type Rules struct {
	Ignore []string `toml:"ignore"`
}

// Hooks install paths for other AUR helpers (yay/paru).
type Hooks struct {
	Yay string `toml:"yay"`
	Paru string `toml:"paru"`
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
		Network:   Network{NoScan: false},
		Rules:     Rules{},
		Hooks:     Hooks{},
		Sandbox:   Sandbox{Enabled: nil},
		Pacman:    Pacman{SudoCmd: "sudo"},
	}
}

func defaultCacheDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache", "piq")
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
	return cfg, nil
}

// applyEnv layers PIQ_* environment variables on top of the file.
func applyEnv(c *Config) {
	str := func(key string, set func(string)) {
		if v, ok := os.LookupEnv(key); ok {
			set(v)
		}
	}
	boolEnv := func(key string, set func(bool)) {
		if v, ok := os.LookupEnv(key); ok {
			if b, err := strconv.ParseBool(v); err == nil {
				set(b)
			}
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
	boolEnv("PIQ_NETWORK_NO_SCAN", func(v bool) { c.Network.NoScan = v })
	str("PIQ_SUDO_CMD", func(v string) { c.Pacman.SudoCmd = v })
	str("PIQ_RULES_IGNORE", func(v string) {
		for _, id := range strings.Split(v, ",") {
			if id = strings.TrimSpace(id); id != "" {
				c.Rules.Ignore = append(c.Rules.Ignore, id)
			}
		}
	})
}

// IgnoresRule reports whether the given rule ID is user-suppressed.
func (c *Config) IgnoresRule(id string) bool {
	for _, x := range c.Rules.Ignore {
		if x == id || x == "*" {
			return true
		}
	}
	return false
}

// SandboxEnabled resolves the effective sandbox setting.
func (c *Config) SandboxEnabled() bool {
	if c.Sandbox.Enabled != nil {
		return *c.Sandbox.Enabled
	}
	return bwrapAvailable()
}

func bwrapAvailable() bool {
	_, err := os.Stat("/usr/bin/bwrap")
	if err == nil {
		return true
	}
	_, err = os.Stat("/bin/bwrap")
	return err == nil
}
