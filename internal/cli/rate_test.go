package cli

import "testing"

func TestParseRate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{in: "", want: 0},
		{in: "unlimited", want: 0},
		{in: "UNLIMITED", want: 0},
		{in: "0", want: 0},
		{in: "100", want: 100},
		{in: "1k", want: 1 << 10},
		{in: "5M", want: 5 << 20},
		{in: "2g", want: 2 << 30},
		{in: " 5m ", want: 5 << 20},
		{in: "5mb", want: 5 << 20},
		{in: "5mib", want: 5 << 20},
		{in: "-1", wantErr: true},
		{in: "1.5m", wantErr: true},
		{in: "abc", wantErr: true},
		{in: "5x", wantErr: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			got, err := parseRate(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseRate(%q) = %d, want err", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRate(%q) err: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("parseRate(%q) = %d, want %d", tc.in, got, tc.want)
			}
		})
	}
}
