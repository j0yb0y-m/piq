package scanner

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FileOptions configures a source-tree scan. Zero values select defaults.
type FileOptions struct {
	MaxFiles   int      // maximum number of text files to scan; 0 means 2000
	MaxBytes   int64    // maximum size of a single file; 0 means 1 MiB
	Deep       bool     // scan directories that are normally skipped
	IgnoreDirs []string // directory base names to skip; nil means the default list
}

// FileScan reports what a source-tree scan inspected and what it found.
type FileScan struct {
	Findings     []Finding
	FilesScanned int
	FilesSkipped int
	Truncated    bool
}

const (
	defaultFileScanMaxFiles = 2000
	defaultFileScanMaxBytes = 1 << 20
	binarySniffBytes        = 8 << 10
	maxExcerptRunes         = 120
)

// defaultFileScanIgnoreDirs lists directory names that rarely ship runtime
// payloads: VCS metadata, dependency checkouts, build output, tests, and docs.
var defaultFileScanIgnoreDirs = []string{
	".git", "node_modules", "vendor", "target", "dist",
	"build", "test", "tests", "doc", "docs", "examples",
}

var (
	fileScanPipeToShellRE  = regexp.MustCompile(`(?i)(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b`)
	fileScanObfuscationRE  = regexp.MustCompile(`(?i)(base64\s+(-d|--decode)|xxd\s+-r|openssl\s+enc\s+-d)[^\n|]*\|\s*(ba|z|da|k)?sh\b`)
	fileScanReverseShellRE = regexp.MustCompile(`(?i)/dev/(tcp|udp)/`)
	fileScanDestructiveRE  = regexp.MustCompile(`(?i)\brm\s+-[a-z]*r[a-z]*f?\s+(/|~|\$HOME)(\s|$)`)
	fileScanCredentialRE   = regexp.MustCompile(`(?i)(~|\$HOME)/\.ssh/|\.aws/credentials|wallet\.dat`)
	fileScanEgressRE       = regexp.MustCompile(`(?i)\b(curl|wget|nc|scp|rsync)\b`)
	fileScanPersistPathRE  = regexp.MustCompile(`(?i)(/etc/systemd/system|/etc/cron\.|/var/spool/cron)`)
	fileScanPersistWriteRE = regexp.MustCompile(`(?:>|\btee\b|\bcp\b|\binstall\b)`)
	fileScanSetuidRE       = regexp.MustCompile(`(?i)chmod\s+[ug]?\+s|chmod\s+4[0-7]{3}`)
)

// ScanTree walks root and scans regular text files for runtime payloads that
// a PKGBUILD parser cannot see: piped-to-shell downloads, obfuscated
// decoders, reverse shells, destructive commands, credential egress,
// persistence writes, and setuid changes. It reports findings only; it never
// gates on them.
func ScanTree(root string, opts FileOptions) (FileScan, error) {
	if opts.MaxFiles <= 0 {
		opts.MaxFiles = defaultFileScanMaxFiles
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultFileScanMaxBytes
	}
	ignore := opts.IgnoreDirs
	if ignore == nil {
		ignore = defaultFileScanIgnoreDirs
	}
	skip := make(map[string]bool, len(ignore))
	for _, name := range ignore {
		skip[name] = true
	}

	var res FileScan
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			if path != root && !opts.Deep && skip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil // never follow symlinks out of the tree
		}
		if !d.Type().IsRegular() {
			res.FilesSkipped++ // sockets, FIFOs, devices: nothing safe to read
			return nil
		}
		if res.FilesScanned >= opts.MaxFiles {
			res.Truncated = true
			return fs.SkipAll
		}

		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			res.FilesSkipped++
			return nil
		}
		rel = filepath.ToSlash(rel)

		findings, ok := scanTreeFile(path, rel, opts.MaxBytes)
		if !ok {
			res.FilesSkipped++
			return nil
		}
		res.FilesScanned++
		res.Findings = append(res.Findings, findings...)
		return nil
	})
	if err != nil {
		return res, fmt.Errorf("walking %s: %w", root, err)
	}
	return res, nil
}

// scanTreeFile reads and scans one file. It reports ok=false when the file is
// unreadable, too large, or binary, so the caller can count it as skipped.
func scanTreeFile(path, rel string, maxBytes int64) ([]Finding, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, false
	}
	if int64(len(data)) > maxBytes {
		return nil, false
	}
	sniff := data
	if len(sniff) > binarySniffBytes {
		sniff = sniff[:binarySniffBytes]
	}
	if bytes.IndexByte(sniff, 0) >= 0 {
		return nil, false
	}

	return scanTreeContent(rel, data), true
}

// scanTreeContent inspects one decoded text file line by line.
func scanTreeContent(rel string, data []byte) []Finding {
	hasEgress := fileScanEgressRE.Match(data)

	var findings []Finding
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if line == "" {
			continue
		}
		lineNo := i + 1
		excerpt := clipExcerpt(line)

		if m := fileScanPipeToShellRE.FindString(line); m != "" {
			findings = append(findings, Finding{
				Rule:     "source-pipe-to-shell",
				Severity: Critical,
				Line:     lineNo,
				File:     rel,
				Message:  fmt.Sprintf("downloads code and pipes it straight into a shell (%q); whatever the remote host returns runs immediately", clipExcerpt(m)),
			})
		}
		if m := fileScanObfuscationRE.FindString(line); m != "" {
			findings = append(findings, Finding{
				Rule:     "source-obfuscation",
				Severity: Critical,
				Line:     lineNo,
				File:     rel,
				Message:  fmt.Sprintf("decodes an obfuscated payload and pipes it into a shell (%q); hidden commands run immediately", clipExcerpt(m)),
			})
		}
		if m := fileScanReverseShellRE.FindString(line); m != "" {
			findings = append(findings, Finding{
				Rule:     "source-reverse-shell",
				Severity: Warning,
				Line:     lineNo,
				File:     rel,
				Message:  fmt.Sprintf("opens a raw network socket via %q; a common reverse-shell technique", m),
			})
		}
		if m := fileScanDestructiveRE.FindString(line); m != "" {
			findings = append(findings, Finding{
				Rule:     "source-destructive",
				Severity: Critical,
				Line:     lineNo,
				File:     rel,
				Message:  fmt.Sprintf("recursively force-deletes a broad path (%q); can wipe the build root or the user's home directory", clipExcerpt(m)),
			})
		}
		if fileScanCredentialRE.MatchString(line) {
			if hasEgress {
				findings = append(findings, Finding{
					Rule:     "source-credential-egress",
					Severity: Critical,
					Line:     lineNo,
					File:     rel,
					Message:  fmt.Sprintf("touches credentials (%q) in a file that also makes network calls; looks like credential exfiltration", excerpt),
				})
			}
		}
		if fileScanPersistPathRE.MatchString(line) && fileScanPersistWriteRE.MatchString(line) {
			findings = append(findings, Finding{
				Rule:     "source-persistence",
				Severity: Warning,
				Line:     lineNo,
				File:     rel,
				Message:  fmt.Sprintf("writes to a system persistence location (%q); the change survives removal and runs on boot or on a schedule", excerpt),
			})
		}
		if m := fileScanSetuidRE.FindString(line); m != "" {
			findings = append(findings, Finding{
				Rule:     "source-setuid",
				Severity: Warning,
				Line:     lineNo,
				File:     rel,
				Message:  fmt.Sprintf("sets the setuid bit (%q); anyone who runs the resulting binary gains its owner's privileges", clipExcerpt(m)),
			})
		}
	}
	return findings
}

func clipExcerpt(s string) string {
	s = strings.TrimSpace(s)
	runes := []rune(s)
	if len(runes) <= maxExcerptRunes {
		return s
	}
	return string(runes[:maxExcerptRunes]) + "..."
}
