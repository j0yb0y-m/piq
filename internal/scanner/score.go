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
	Verdict  Verdict
	Total    int
	PerRule  map[string]int
	GateHits []string
	Findings []Finding
}

// NewScore runs every registered rule, buckets findings by rule,
// sums their Points, and applies gating + thresholds to produce a
// verdict.
func NewScore(ctx *Context) *Score {
	s := &Score{PerRule: map[string]int{}}
	for _, r := range registry {
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

	for _, p := range s.PerRule {
		s.Total += p
	}
	s.Verdict = s.derive()
	return s
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
