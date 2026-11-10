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
