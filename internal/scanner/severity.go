package scanner

import (
	"fmt"
	"strings"
)

// ParseSeverity converts a config-level severity name into a Severity.
// It trims surrounding space and ignores case.
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, nil
	case "warning":
		return Warning, nil
	case "critical":
		return Critical, nil
	default:
		return Info, fmt.Errorf("unknown severity %q (want info, warning, or critical)", s)
	}
}
