package cli

import "testing"

func TestParseSize_AcceptsHumanUnits(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"", 0},
		{"0", 0},
		{"1024", 1024},
		{"1k", 1 << 10},
		{"1K", 1 << 10},
		{"10K", 10 << 10},
		{"1m", 1 << 20},
		{"5M", 5 << 20},
		{"1g", 1 << 30},
		{"1G", 1 << 30},
		{"1t", 1 << 40},
		{"1T", 1 << 40},
		{"1KB", 1 << 10},
		{"1kb", 1 << 10},
		{"1KiB", 1 << 10},
		{"1MiB", 1 << 20},
		{"1Mib", 1 << 20},
		{"  2g  ", 2 << 30},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseSize(tc.in)
			if err != nil {
				t.Fatalf("parseSize(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("parseSize(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseSize_Rejects(t *testing.T) {
	cases := []string{
		"abc",
		"1z",
		"k",
		"-1",
		"-1g",
		"1.5g",
		"1ZB",
		// 9223372036854775808 = math.MaxInt64 + 1 — too big for int64.
		"9223372036854775808",
		// 8388609 * 2^40 > MaxInt64.
		"8388609t",
	}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, err := parseSize(in); err == nil {
				t.Errorf("parseSize(%q) accepted invalid input", in)
			}
		})
	}
}
