package placement_test

import (
	"errors"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"backupswarm/internal/placement"
)

// identityWeight is the canonical weight function for tests over int pools.
func identityWeight(i int) int64 { return int64(i) }

func TestWeightedRandom_PicksRequestedCount(t *testing.T) {
	pool := []int{10, 20, 30, 40, 50}
	rng := rand.New(rand.NewPCG(1, 2))
	out, err := placement.WeightedRandom(pool, identityWeight, 3, rng)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 3 {
		t.Errorf("expected 3 picks, got %d", len(out))
	}
}

func TestWeightedRandom_AllPicksUnique(t *testing.T) {
	pool := []int{10, 20, 30, 40, 50}
	rng := rand.New(rand.NewPCG(1, 2))
	out, err := placement.WeightedRandom(pool, identityWeight, len(pool), rng)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := make(map[int]bool, len(out))
	for _, v := range out {
		if seen[v] {
			t.Errorf("duplicate pick: %d", v)
		}
		seen[v] = true
	}
}

func TestWeightedRandom_TooLargeR(t *testing.T) {
	pool := []int{10, 20}
	rng := rand.New(rand.NewPCG(1, 2))
	_, err := placement.WeightedRandom(pool, identityWeight, 5, rng)
	if !errors.Is(err, placement.ErrInsufficientPeers) {
		t.Errorf("expected ErrInsufficientPeers, got %v", err)
	}
}

func TestWeightedRandom_AllZeroWeights(t *testing.T) {
	pool := []int{1, 2, 3}
	rng := rand.New(rand.NewPCG(1, 2))
	_, err := placement.WeightedRandom(pool, func(int) int64 { return 0 }, 1, rng)
	if !errors.Is(err, placement.ErrNoCapacity) {
		t.Errorf("expected ErrNoCapacity, got %v", err)
	}
}

func TestWeightedRandom_PartialZeroWeightsExhaust(t *testing.T) {
	// Pool [w=10, w=0, w=0]; r=2 → after first pick the remaining sum is 0.
	pool := []int{0, 1, 2}
	weights := map[int]int64{0: 10, 1: 0, 2: 0}
	rng := rand.New(rand.NewPCG(1, 2))
	_, err := placement.WeightedRandom(pool, func(i int) int64 { return weights[i] }, 2, rng)
	if !errors.Is(err, placement.ErrNoCapacity) {
		t.Errorf("expected ErrNoCapacity once nonzero weight is exhausted, got %v", err)
	}
}

func TestWeightedRandom_DistributionMatchesWeights(t *testing.T) {
	// Two candidates, weights 3:1. Pick R=1 across many trials and assert
	// the high-weight candidate wins ~75% of trials.
	type item struct {
		id int
		w  int64
	}
	pool := []item{{0, 3}, {1, 1}}
	weight := func(it item) int64 { return it.w }
	rng := rand.New(rand.NewPCG(42, 99))

	const trials = 20000
	counts := make([]int, len(pool))
	for i := 0; i < trials; i++ {
		out, err := placement.WeightedRandom(pool, weight, 1, rng)
		if err != nil {
			t.Fatalf("trial %d: %v", i, err)
		}
		counts[out[0].id]++
	}

	expectedHi := trials * 3 / 4
	expectedLo := trials * 1 / 4
	tol := trials / 50 // 2%
	if counts[0] < expectedHi-tol || counts[0] > expectedHi+tol {
		t.Errorf("heavy weight: expected %d ± %d, got %d", expectedHi, tol, counts[0])
	}
	if counts[1] < expectedLo-tol || counts[1] > expectedLo+tol {
		t.Errorf("light weight: expected %d ± %d, got %d", expectedLo, tol, counts[1])
	}
}

func TestWeightedRandom_DeterministicWithSameSeed(t *testing.T) {
	pool := []int{10, 20, 30, 40, 50}
	rng1 := rand.New(rand.NewPCG(7, 11))
	out1, err := placement.WeightedRandom(pool, identityWeight, 3, rng1)
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	rng2 := rand.New(rand.NewPCG(7, 11))
	out2, err := placement.WeightedRandom(pool, identityWeight, 3, rng2)
	if err != nil {
		t.Fatalf("second run: %v", err)
	}
	if !slices.Equal(out1, out2) {
		t.Errorf("expected identical output with same seed: %v vs %v", out1, out2)
	}
}

func TestWeightedRandom_NegativeWeightRejected(t *testing.T) {
	pool := []int{10, 20}
	rng := rand.New(rand.NewPCG(1, 2))
	_, err := placement.WeightedRandom(pool, func(i int) int64 { return int64(-i) }, 1, rng)
	if err == nil {
		t.Fatalf("expected error on negative weight")
	}
	if errors.Is(err, placement.ErrInsufficientPeers) || errors.Is(err, placement.ErrNoCapacity) {
		t.Errorf("expected dedicated negative-weight error, got %v", err)
	}
}

func TestWeightedRandom_ZeroR(t *testing.T) {
	pool := []int{10, 20}
	rng := rand.New(rand.NewPCG(1, 2))
	out, err := placement.WeightedRandom(pool, identityWeight, 0, rng)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty result, got %v", out)
	}
}

func TestWeightedRandom_NegativeR(t *testing.T) {
	pool := []int{10, 20}
	rng := rand.New(rand.NewPCG(1, 2))
	_, err := placement.WeightedRandom(pool, identityWeight, -1, rng)
	if err == nil {
		t.Fatalf("expected error on negative r")
	}
}

func TestWeightedRandom_SingleCandidate(t *testing.T) {
	pool := []int{42}
	rng := rand.New(rand.NewPCG(1, 2))
	out, err := placement.WeightedRandom(pool, identityWeight, 1, rng)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 1 || out[0] != 42 {
		t.Errorf("expected [42], got %v", out)
	}
}

func TestWeightedRandom_DoesNotMutateInput(t *testing.T) {
	pool := []int{10, 20, 30, 40, 50}
	original := slices.Clone(pool)
	rng := rand.New(rand.NewPCG(1, 2))
	if _, err := placement.WeightedRandom(pool, identityWeight, 3, rng); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(pool, original) {
		t.Errorf("input pool was mutated: was %v, now %v", original, pool)
	}
}

func TestWeightedRandom_NilRng(t *testing.T) {
	pool := []int{10, 20}
	_, err := placement.WeightedRandom(pool, identityWeight, 1, nil)
	if err == nil {
		t.Fatalf("expected error on nil rng")
	}
}

// TestWeightedRandom_WeightSumOverflowsInt64 asserts the loop rejects
// inputs whose weights add past int64 max.
func TestWeightedRandom_WeightSumOverflowsInt64(t *testing.T) {
	const huge = int64(1) << 62
	pool := []int{0, 1, 2, 3}
	weight := func(int) int64 { return huge }
	rng := rand.New(rand.NewPCG(1, 2))
	_, err := placement.WeightedRandom(pool, weight, 1, rng)
	if err == nil {
		t.Fatal("expected error on int64 weight-sum overflow")
	}
	if !strings.Contains(err.Error(), "overflows int64") {
		t.Errorf("err = %v, want 'overflows int64' message", err)
	}
}
