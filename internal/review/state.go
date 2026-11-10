// Package review persists per-package review state so piq can show
// exactly what changed since the last time the user approved a
// package, and detect when an endorsed package has drifted. State is
// kept as small JSON files in the piq cache dir.
package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Record captures the state of a package the user last reviewed.
type Record struct {
	PackageBase   string    `json:"pkgbase"`
	Commit        string    `json:"commit"`
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

// Put saves a record atomically: the data is written and synced to a
// temp file in the store dir, then renamed over the final path.
func (s *Store) Put(rec *Record) error {
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, "."+rec.PackageBase+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}
	if _, err := f.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := f.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, s.path(rec.PackageBase)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// Matches reports whether the record was reviewed at commit and covers
// exactly the given PKGBUILD, .SRCINFO, and scriptlet hashes.
func (r *Record) Matches(commit, pkgbuildHash, srcinfoHash, scriptletHash string) bool {
	if r == nil {
		return false
	}
	return r.Commit == commit &&
		r.PkgbuildHash == pkgbuildHash &&
		r.SrcinfoHash == srcinfoHash &&
		r.ScriptletHash == scriptletHash
}

// ScriptletHash returns a stable digest of install scriptlets keyed by
// file name, or "" when there are none. Names are sorted so map order
// never affects the result.
func ScriptletHash(scriptlets map[string]string) string {
	if len(scriptlets) == 0 {
		return ""
	}
	names := make([]string, 0, len(scriptlets))
	for name := range scriptlets {
		names = append(names, name)
	}
	sort.Strings(names)
	var buf []byte
	for _, name := range names {
		buf = append(buf, name...)
		buf = append(buf, 0)
		buf = append(buf, scriptlets[name]...)
		buf = append(buf, 0)
	}
	return Hash(buf)
}

// Fingerprint hashes the PKGBUILD, .SRCINFO, and any *.install
// scriptlets in dir. A missing .SRCINFO or absent scriptlets yield empty
// hashes; only a missing or unreadable PKGBUILD is an error.
func Fingerprint(dir string) (pkgbuildHash, srcinfoHash, scriptletHash string, err error) {
	pkgbuild, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		return "", "", "", fmt.Errorf("read PKGBUILD: %w", err)
	}
	pkgbuildHash = Hash(pkgbuild)

	srcinfo, err := os.ReadFile(filepath.Join(dir, ".SRCINFO"))
	if err != nil && !os.IsNotExist(err) {
		return "", "", "", fmt.Errorf("read .SRCINFO: %w", err)
	}
	if err == nil {
		srcinfoHash = Hash(srcinfo)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "*.install"))
	if err != nil {
		return "", "", "", fmt.Errorf("glob scriptlets: %w", err)
	}
	scriptlets := make(map[string]string, len(matches))
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", "", "", fmt.Errorf("read scriptlet %s: %w", filepath.Base(path), err)
		}
		scriptlets[filepath.Base(path)] = string(data)
	}
	return pkgbuildHash, srcinfoHash, ScriptletHash(scriptlets), nil
}

// Hash returns the sha256 hex digest of a byte slice.
func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
