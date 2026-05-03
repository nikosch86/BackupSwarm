package daemon

import "testing"

// TestBuildLimiters_ZeroDisablesPerSide asserts a zero rate produces a nil
// limiter (pass-through), positive produces a configured limiter.
func TestBuildLimiters_ZeroDisablesPerSide(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name             string
		up, down         int64
		wantUp, wantDown bool
	}{
		{name: "both_zero_unlimited", up: 0, down: 0, wantUp: false, wantDown: false},
		{name: "up_only", up: 1024, down: 0, wantUp: true, wantDown: false},
		{name: "down_only", up: 0, down: 2048, wantUp: false, wantDown: true},
		{name: "both_set", up: 1024, down: 2048, wantUp: true, wantDown: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lim := buildLimiters(tc.up, tc.down)
			if (lim.Up != nil) != tc.wantUp {
				t.Errorf("Up nil-ness: got %v, want non-nil=%v", lim.Up != nil, tc.wantUp)
			}
			if (lim.Down != nil) != tc.wantDown {
				t.Errorf("Down nil-ness: got %v, want non-nil=%v", lim.Down != nil, tc.wantDown)
			}
		})
	}
}

// TestNewLimiter_BurstFloor asserts a small byte rate still gets a usable
// burst (≥ limiterBurstFloor) so single-chunk writes don't stall.
func TestNewLimiter_BurstFloor(t *testing.T) {
	t.Parallel()
	lim := newLimiter(1024)
	if lim == nil {
		t.Fatal("newLimiter(1024) = nil; want configured limiter")
	}
	if lim.Burst() < limiterBurstFloor {
		t.Fatalf("burst %d < floor %d", lim.Burst(), limiterBurstFloor)
	}
}

// TestNewLimiter_ZeroAndNegative asserts non-positive rates produce nil.
func TestNewLimiter_ZeroAndNegative(t *testing.T) {
	t.Parallel()
	if l := newLimiter(0); l != nil {
		t.Errorf("newLimiter(0) = %v, want nil", l)
	}
	if l := newLimiter(-1); l != nil {
		t.Errorf("newLimiter(-1) = %v, want nil", l)
	}
}
