package cli

import "strings"

// parseRate parses a byte-rate flag value into bytes/sec. Empty or
// "unlimited" (case-insensitive) returns 0; otherwise the value is
// parsed via parseSize (k/m/g/t suffixes).
func parseRate(s string) (int64, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || strings.EqualFold(trimmed, "unlimited") {
		return 0, nil
	}
	return parseSize(trimmed)
}
