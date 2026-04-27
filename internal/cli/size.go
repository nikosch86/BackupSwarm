package cli

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// parseSize parses an integer with an optional binary suffix
// (k/m/g/t, case-insensitive, optional "b"/"iB" tail). Empty input
// returns 0; decimals and negative values are rejected.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	cut := len(s)
	for i, r := range s {
		if r >= '0' && r <= '9' {
			continue
		}
		cut = i
		break
	}
	digits := s[:cut]
	suffix := strings.ToLower(strings.TrimSpace(s[cut:]))

	if digits == "" {
		return 0, fmt.Errorf("size %q: missing leading digits", s)
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("size %q: %w", s, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("size %q: must be non-negative", s)
	}

	// Strip optional "b"/"ib" tail so "1KB", "1KiB", "1Kib" all reduce
	// to the unit letter alone.
	suffix = strings.TrimSuffix(suffix, "b")
	suffix = strings.TrimSuffix(suffix, "i")

	mul := int64(1)
	switch suffix {
	case "":
		mul = 1
	case "k":
		mul = 1 << 10
	case "m":
		mul = 1 << 20
	case "g":
		mul = 1 << 30
	case "t":
		mul = 1 << 40
	default:
		return 0, fmt.Errorf("size %q: unknown unit suffix %q", s, s[cut:])
	}

	if mul > 1 && n > math.MaxInt64/mul {
		return 0, fmt.Errorf("size %q: overflows int64", s)
	}
	return n * mul, nil
}
