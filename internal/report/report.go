// Package report defines piq's stable, versioned JSON output contract.
// Every machine-readable command emits one of these types through Write
// so downstream tools can rely on the same keys and schema version.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// SchemaVersion is the version of the JSON contract emitted by piq.
// Bump it whenever a field is renamed, removed, or changes meaning.
const SchemaVersion = 1

// Finding is a single issue discovered while scanning a package.
type Finding struct {
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Message  string `json:"message"`
}

// Provenance summarizes the git history behind a package repository.
type Provenance struct {
	CommitCount     int       `json:"commit_count"`
	Maintainer      string    `json:"maintainer"`
	HeadCommitter   string    `json:"head_committer"`
	HeadCommittedAt time.Time `json:"head_committed_at"`
}

// Scan is the report emitted by commands that scan one package.
type Scan struct {
	SchemaVersion int         `json:"schema_version"`
	Command       string      `json:"command"`
	Package       string      `json:"package"`
	Verdict       string      `json:"verdict"`
	BlockReason   string      `json:"block_reason"`
	Score         int         `json:"score"`
	Blocked       bool        `json:"blocked"`
	Findings      []Finding   `json:"findings"`
	Provenance    *Provenance `json:"provenance,omitempty"`
	GeneratedAt   time.Time   `json:"generated_at"`
}

// PackageSummary is one AUR search result.
type PackageSummary struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Votes       int    `json:"votes"`
}

// Search is the report emitted by search.
type Search struct {
	SchemaVersion int              `json:"schema_version"`
	Command       string           `json:"command"`
	Results       []PackageSummary `json:"results"`
}

// AuditEntry is one installed foreign package in the audit report.
type AuditEntry struct {
	Package      string    `json:"package"`
	Installed    string    `json:"installed_version"`
	AURVersion   string    `json:"aur_version"`
	Outdated     bool      `json:"outdated"`
	ReviewStatus string    `json:"review_status"`
	Verdict      string    `json:"verdict,omitempty"`
	Score        int       `json:"score,omitempty"`
	Blocked      bool      `json:"blocked,omitempty"`
	Findings     []Finding `json:"findings,omitempty"`
	Integrity    []string  `json:"integrity,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// Audit is the report emitted by audit.
type Audit struct {
	SchemaVersion int          `json:"schema_version"`
	Command       string       `json:"command"`
	Packages      []AuditEntry `json:"packages"`
}

// Info is the report emitted by info.
type Info struct {
	SchemaVersion int        `json:"schema_version"`
	Command       string     `json:"command"`
	Name          string     `json:"name"`
	Version       string     `json:"version"`
	Votes         int        `json:"votes"`
	Popularity    float64    `json:"popularity"`
	Maintainer    string     `json:"maintainer"`
	Submitted     *time.Time `json:"submitted,omitempty"`
	URL           string     `json:"url"`
	ReviewStatus  string     `json:"review_status"`
	ReviewedAt    *time.Time `json:"reviewed_at,omitempty"`
}

// Config is the report emitted by config.
type Config struct {
	SchemaVersion  int      `json:"schema_version"`
	Command        string   `json:"command"`
	ConfigPath     string   `json:"config_path"`
	CachePath      string   `json:"cache_path"`
	Severity       string   `json:"severity"`
	Threshold      int      `json:"threshold"`
	Ignore         []string `json:"ignore"`
	SandboxEnabled *bool    `json:"sandbox_enabled"`
	SudoCmd        string   `json:"sudo_cmd"`
}

// Version is the report emitted by version.
type Version struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Date          string `json:"date"`
}

// Write encodes v as indented JSON without HTML escaping. The output is
// pure JSON: no ANSI escapes and no human-readable text.
func Write(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encoding json: %w", err)
	}
	return nil
}
