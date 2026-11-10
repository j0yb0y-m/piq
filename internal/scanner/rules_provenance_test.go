package scanner

import (
	"testing"
	"time"

	"github.com/j0yb0y-m/piq/internal/history"
)

func TestMaintainerChangeOnlyOnRecentHandover(t *testing.T) {
	now := time.Now()
	recent := &history.Provenance{
		HeadCommitter: "new@x", PreviousCommitter: "old@x",
		HeadCommittedAt: now.Add(-24 * time.Hour), HeadCommitterFirstAt: now.Add(-24 * time.Hour),
	}
	if f := findingsFor(maintainerChangeRule{}.Check(&Context{History: recent}), "maintainer-change"); len(f) == 0 {
		t.Fatal("expected finding")
	}
	stable := &history.Provenance{HeadCommitter: "same@x", PreviousCommitter: "same@x", HeadCommittedAt: now, HeadCommitterFirstAt: now.Add(-24 * time.Hour)}
	if f := findingsFor(maintainerChangeRule{}.Check(&Context{History: stable}), "maintainer-change"); len(f) != 0 {
		t.Fatal("stable repo flagged")
	}
	old := &history.Provenance{HeadCommitter: "new@x", PreviousCommitter: "old@x", HeadCommittedAt: now, HeadCommitterFirstAt: now.Add(-2 * 365 * 24 * time.Hour)}
	if f := findingsFor(maintainerChangeRule{}.Check(&Context{History: old}), "maintainer-change"); len(f) != 0 {
		t.Fatal("old handover flagged")
	}
}

// TestMaintainerChangeDatesHandoverFromFirstCommitterCommit is the R16
// regression: a recent HEAD alone must not look like a recent handover.
func TestMaintainerChangeDatesHandoverFromFirstCommitterCommit(t *testing.T) {
	now := time.Now()
	p := &history.Provenance{
		HeadCommitter: "new@x", PreviousCommitter: "old@x",
		HeadCommittedAt:      now.Add(-24 * time.Hour),
		HeadCommitterFirstAt: now.Add(-2 * 365 * 24 * time.Hour),
	}
	if f := findingsFor(maintainerChangeRule{}.Check(&Context{History: p}), "maintainer-change"); len(f) != 0 {
		t.Fatalf("old handover with recent HEAD flagged: %v", f)
	}
}

func TestMaintainerChangeNeedsFirstCommitterCommit(t *testing.T) {
	now := time.Now()
	p := &history.Provenance{
		HeadCommitter: "new@x", PreviousCommitter: "old@x",
		HeadCommittedAt: now.Add(-24 * time.Hour),
	}
	if f := findingsFor(maintainerChangeRule{}.Check(&Context{History: p}), "maintainer-change"); len(f) != 0 {
		t.Fatalf("missing HeadCommitterFirstAt flagged: %v", f)
	}
}

func TestMaintainerChangeNeedsBothCommitters(t *testing.T) {
	now := time.Now()
	for name, p := range map[string]*history.Provenance{
		"zero timestamp": {HeadCommitter: "new@x", PreviousCommitter: "old@x"},
		"no previous":    {HeadCommitter: "new@x", HeadCommittedAt: now.Add(-24 * time.Hour), HeadCommitterFirstAt: now.Add(-24 * time.Hour)},
		"no head":        {PreviousCommitter: "old@x", HeadCommittedAt: now.Add(-24 * time.Hour), HeadCommitterFirstAt: now.Add(-24 * time.Hour)},
	} {
		if f := findingsFor(maintainerChangeRule{}.Check(&Context{History: p}), "maintainer-change"); len(f) != 0 {
			t.Errorf("%s flagged: %v", name, f)
		}
	}
}

func TestMaintainerDriftOnlyRecentMinority(t *testing.T) {
	now := time.Now()
	drift := &history.Provenance{
		HeadCommitter: "new@x", CommitCount: 200, HeadCommittedAt: now.Add(-24 * time.Hour),
		Committers: map[string]int{"new@x": 5, "old@x": 195},
	}
	if f := findingsFor(maintainerDriftRule{}.Check(&Context{History: drift}), "maintainer-drift"); len(f) == 0 {
		t.Fatal("expected drift finding")
	}

	stable := &history.Provenance{
		HeadCommitter: "same@x", CommitCount: 200, HeadCommittedAt: now.Add(-24 * time.Hour),
		Committers: map[string]int{"same@x": 100, "old@x": 100},
	}
	if f := findingsFor(maintainerDriftRule{}.Check(&Context{History: stable}), "maintainer-drift"); len(f) != 0 {
		t.Fatalf("stable repo flagged: %v", f)
	}

	old := &history.Provenance{
		HeadCommitter: "new@x", CommitCount: 200, HeadCommittedAt: now.Add(-2 * 365 * 24 * time.Hour),
		Committers: map[string]int{"new@x": 5, "old@x": 195},
	}
	if f := findingsFor(maintainerDriftRule{}.Check(&Context{History: old}), "maintainer-drift"); len(f) != 0 {
		t.Fatalf("old history flagged: %v", f)
	}

	for name, p := range map[string]*history.Provenance{
		"zero timestamp": {HeadCommitter: "new@x", CommitCount: 200, Committers: map[string]int{"new@x": 5}},
		"no commits":     {HeadCommitter: "new@x", HeadCommittedAt: now},
		"no head":        {CommitCount: 200, HeadCommittedAt: now, Committers: map[string]int{"new@x": 5}},
	} {
		if f := findingsFor(maintainerDriftRule{}.Check(&Context{History: p}), "maintainer-drift"); len(f) != 0 {
			t.Errorf("%s flagged: %v", name, f)
		}
	}
}
