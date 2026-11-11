// Package review persists per-package review state so piq can show
// exactly what changed since the last time the user approved a
// package, and detect when an endorsed package has drifted. State is
// kept as small JSON files in the piq cache dir.
package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// validRecordName rejects package bases that would escape the store or
// produce a dot-only path component.
func validRecordName(pkgbase string) bool {
	return pkgbase != "" && pkgbase != "." && pkgbase != ".." && !strings.ContainsAny(pkgbase, `/\`)
}

// Get returns the stored record for pkgbase, or nil if none.
func (s *Store) Get(pkgbase string) (*Record, error) {
	if !validRecordName(pkgbase) {
		return nil, fmt.Errorf("invalid package base %q", pkgbase)
	}
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
	if rec == nil {
		return errors.New("nil review record")
	}
	if !validRecordName(rec.PackageBase) {
		return fmt.Errorf("invalid package base %q", rec.PackageBase)
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, "."+filepath.Base(rec.PackageBase)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	cleanup := func() {
		_ = f.Close()
		_ = os.Remove(tmp)
	}
	if err := f.Chmod(0o600); err != nil {
		cleanup()
		return err
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
// hashes; a missing or unreadable PKGBUILD is an error. Every input must
// be a regular file; symlinks, FIFOs, and directories are rejected
// rather than read.
func Fingerprint(dir string) (pkgbuildHash, srcinfoHash, scriptletHash string, err error) {
	pkgbuild, err := readRegularFile(filepath.Join(dir, "PKGBUILD"))
	if err != nil {
		return "", "", "", fmt.Errorf("read PKGBUILD: %w", err)
	}
	pkgbuildHash = Hash(pkgbuild)

	srcinfo, err := readRegularFile(filepath.Join(dir, ".SRCINFO"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", "", "", fmt.Errorf("read .SRCINFO: %w", err)
	}
	if err == nil {
		srcinfoHash = Hash(srcinfo)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", "", "", fmt.Errorf("read dir: %w", err)
	}
	scriptlets := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".install") {
			continue
		}
		data, err := readRegularFile(filepath.Join(dir, name))
		if err != nil {
			return "", "", "", fmt.Errorf("read scriptlet %s: %w", name, err)
		}
		scriptlets[name] = string(data)
	}
	return pkgbuildHash, srcinfoHash, ScriptletHash(scriptlets), nil
}

// maxReviewFileBytes bounds every file Fingerprint reads. A package with
// a larger PKGBUILD, .SRCINFO, or scriptlet is rejected instead of
// exhausting memory while hashing it.
const maxReviewFileBytes = 8 << 20

// readRegularFile reads path only if it is a regular file. It rejects
// symlinks, FIFOs, devices, and directories before opening them, and
// refuses files larger than maxReviewFileBytes so a hostile checkout
// cannot block or exhaust memory.
func readRegularFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxReviewFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxReviewFileBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", path, maxReviewFileBytes)
	}
	return data, nil
}

// Hash returns the sha256 hex digest of a byte slice.
func Hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
