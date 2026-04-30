package cli

import "testing"

func TestParseMaxStorage(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantBytes   int64
		wantNoStore bool
	}{
		{"empty is unlimited", "", 0, false},
		{"unlimited literal", "unlimited", 0, false},
		{"unlimited mixed case", "UnLiMiTeD", 0, false},
		{"unlimited padded", "  unlimited  ", 0, false},
		{"zero means no storage", "0", 0, true},
		{"zero with bytes suffix", "0b", 0, true},
		{"zero with k suffix", "0k", 0, true},
		{"positive bytes", "1024", 1024, false},
		{"positive with suffix", "10g", 10 << 30, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotBytes, gotNoStore, err := parseMaxStorage(tc.in)
			if err != nil {
				t.Fatalf("parseMaxStorage(%q): %v", tc.in, err)
			}
			if gotBytes != tc.wantBytes {
				t.Errorf("bytes = %d, want %d", gotBytes, tc.wantBytes)
			}
			if gotNoStore != tc.wantNoStore {
				t.Errorf("noStorage = %v, want %v", gotNoStore, tc.wantNoStore)
			}
		})
	}
}

func TestParseMaxStorage_Rejects(t *testing.T) {
	cases := []string{"garbage", "-1", "1.5g", "k"}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			if _, _, err := parseMaxStorage(in); err == nil {
				t.Errorf("parseMaxStorage(%q) accepted invalid input", in)
			}
		})
	}
}
