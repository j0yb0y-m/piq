// Package review persists per-package review state so piq can show
// exactly what changed since the last time the user approved a
// package, and detect when an endorsed package has drifted. State is
// kept as small JSON files in the piq cache dir.
package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Record captures the state of a package the user last reviewed.
type Record struct {
	PackageBase   string    `json:"pkgbase"`
	Committer     string    `json:"committer"`
	PkgbuildHash  string    `json:"pkgbuild_hash"`
	PkgbuildRaw   string    `json:"pkgbuild_raw,omitempty"` // snapshot for diff
	SrcinfoHash   string    `json:"srcinfo_hash"`
	ScriptletHash string    `json:"scriptlet_hash"`
	Verdict       string    `json:"verdict"`
	ReviewedAt    time.Time `json:"reviewed_at"`
}

// Store persists review records.
type Store struct {
	dir string
}

// NewStore returns a Store rooted at dir, creating it if needed.
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) path(pkgbase string) string {
	return filepath.Join(s.dir, pkgbase+".json")
}

// Get returns the stored record for pkgbase, or nil if none.
func (s *Store) Get(pkgbase string) (*Record, error) {
	data, err := os.ReadFile(s.path(pkgbase))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, err
	}
	return &rec, nil
}

// Put saves a record.
func (s *Store) Put(rec *Record) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path(rec.PackageBase), data, 0o600)
}

// Hash returns the sha256 hex digest of a byte slice.
func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
