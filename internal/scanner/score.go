package scanner

import (
	"fmt"
	"sort"
)

// Verdict is the aggregate risk assessment for a whole package.
type Verdict int

const (
	Trusted    Verdict = iota // no findings, checksums present, nothing of note
	OK                        // only INFO-level noise; ready to install
	Sketchy                   // one or more Warning-level concerns
	Suspicious                // serious concerns / high cumulative score
	Malicious                 // an unambiguous indicator of malice
)

func (v Verdict) String() string {
	switch v {
	case Trusted:
		return "TRUSTED"
	case OK:
		return "OK"
	case Sketchy:
		return "SKETCHY"
	case Suspicious:
		return "SUSPICIOUS"
	case Malicious:
		return "MALICIOUS"
	default:
		return "UNKNOWN"
	}
}

// thresholds control how cumulative points map to a verdict. Tune with
// the calibration corpus in M7.
const (
	sketchyThreshold    = 40
	suspiciousThreshold = 80
)

// Score is the aggregated, per-rule breakdown of a scan.
type Score struct {
	Verdict      Verdict
	Total        int
	PerRule      map[string]int
	GateHits     []string
	Findings     []Finding
	Blocked      bool
	BlockReason  string
	NeedsConfirm bool
}

// Options carries config policy into scoring: rules to suppress, the
// minimum severity that needs human confirmation, an optional score
// threshold that blocks installation, and findings from outside the
// rule registry (e.g. source scans).
type Options struct {
	Ignore      map[string]bool
	MinSeverity Severity
	Threshold   int
	Extra       []Finding
}

// ignores reports whether the rule is suppressed, including the "*"
// wildcard used by config.
func (o Options) ignores(rule string) bool {
	return o.Ignore[rule] || o.Ignore["*"]
}

// NewScore scores a context with default options.
func NewScore(ctx *Context) *Score {
	return ScoreWith(ctx, Options{})
}

// ScoreWith runs every registered rule (except ignored ones), buckets
// findings by rule, sums their Points plus any extra findings, and
// applies gating + thresholds to produce a verdict and block state.
func ScoreWith(ctx *Context, opts Options) *Score {
	s := &Score{PerRule: map[string]int{}}
	for _, r := range registry {
		if opts.ignores(r.Name()) {
			continue
		}
		findings := r.Check(ctx)
		if len(findings) == 0 {
			continue
		}
		s.Findings = append(s.Findings, findings...)

		points, gate := 0, false
		if sr, ok := r.(ScoredRule); ok {
			points = sr.Points()
			gate = sr.Gate()
		}
		s.PerRule[r.Name()] += points
		if gate && len(findings) > 0 {
			s.GateHits = append(s.GateHits, r.Name())
		}
	}

	for _, f := range opts.Extra {
		s.Findings = append(s.Findings, f)
		s.PerRule[f.Rule] += extraPoints(f.Severity)
	}

	for _, p := range s.PerRule {
		s.Total += p
	}
	s.Verdict = s.derive()
	s.NeedsConfirm = s.needsConfirm(opts.MinSeverity)
	s.Blocked, s.BlockReason = s.blockState(opts.Threshold)
	return s
}

// extraPoints maps an externally supplied finding to risk points.
func extraPoints(sev Severity) int {
	switch sev {
	case Critical:
		return 60
	case Warning:
		return 25
	default:
		return 5
	}
}

// needsConfirm reports whether any finding reaches the confirmation
// severity. The zero value Info means every finding qualifies.
func (s *Score) needsConfirm(min Severity) bool {
	for _, f := range s.Findings {
		if f.Severity >= min {
			return true
		}
	}
	return false
}

// blockState decides whether install is blocked and why. Any gate hit
// blocks; otherwise a positive threshold blocks once Total reaches it.
func (s *Score) blockState(threshold int) (bool, string) {
	if len(s.GateHits) > 0 {
		return true, "gate: " + s.GateHits[0]
	}
	if threshold > 0 && s.Total >= threshold {
		return true, fmt.Sprintf("score %d >= threshold %d", s.Total, threshold)
	}
	return false, ""
}

func (s *Score) derive() Verdict {
	if len(s.GateHits) > 0 {
		return Malicious
	}
	switch {
	case s.Total >= suspiciousThreshold:
		return Suspicious
	case s.Total >= sketchyThreshold:
		return Sketchy
	case s.Total > 0:
		return OK
	default:
		return Trusted
	}
}

// Report renders a human-readable summary line for the verdict.
func (s *Score) Report() string {
	return fmt.Sprintf("VERDICT: %s (risk score %d), %d finding(s)", s.Verdict, s.Total, len(s.Findings))
}

// SortedRules returns rule IDs sorted by descending points for stable
// display.
func (s *Score) SortedRules() []string {
	keys := make([]string, 0, len(s.PerRule))
	for k := range s.PerRule {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return s.PerRule[keys[i]] > s.PerRule[keys[j]] })
	return keys
}
