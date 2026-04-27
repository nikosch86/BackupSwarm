// Package placement chooses storage peers for a chunk by weighted-random
// draw without replacement. Weight is interpreted as available capacity in
// bytes; a peer with weight 0 is never selected. The pool is whatever the
// caller deems eligible — reachability and role gating happen upstream.
package placement

import (
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
)

// ErrInsufficientPeers is returned when the caller asks for more unique
// picks than the pool can supply.
var ErrInsufficientPeers = errors.New("placement: redundancy exceeds pool size")

// ErrNoCapacity is returned when no positive-weight candidate remains
// during the draw — either the pool starts at zero total weight, or the
// nonzero-weight candidates were all picked before reaching r.
var ErrNoCapacity = errors.New("placement: no remaining capacity")

// Rng is the subset of math/rand/v2.Rand the placement draw consumes.
type Rng interface {
	Int64N(n int64) int64
}

// WeightedRandom returns r unique items from pool, drawn without
// replacement and weighted by weight(item). r == 0 returns an empty
// slice; r < 0 is rejected. The input pool is not mutated.
func WeightedRandom[T any](pool []T, weight func(T) int64, r int, rng Rng) ([]T, error) {
	if r < 0 {
		return nil, fmt.Errorf("placement: redundancy must be >= 0, got %d", r)
	}
	if r == 0 {
		return []T{}, nil
	}
	if rng == nil {
		return nil, errors.New("placement: rng is nil")
	}
	if len(pool) < r {
		return nil, fmt.Errorf("%w: pool=%d, r=%d", ErrInsufficientPeers, len(pool), r)
	}

	remaining := make([]T, len(pool))
	copy(remaining, pool)
	weights := make([]int64, len(pool))
	for i, c := range remaining {
		w := weight(c)
		if w < 0 {
			return nil, fmt.Errorf("placement: negative weight at index %d: %d", i, w)
		}
		weights[i] = w
	}

	out := make([]T, 0, r)
	for k := 0; k < r; k++ {
		var total int64
		for _, w := range weights {
			if w > math.MaxInt64-total {
				return nil, fmt.Errorf("placement: weight sum overflows int64 (cap individual weights below ~maxInt64/poolSize)")
			}
			total += w
		}
		if total == 0 {
			return nil, fmt.Errorf("%w: %d picks remaining, sum=0", ErrNoCapacity, r-k)
		}
		pick := rng.Int64N(total)
		idx := -1
		var acc int64
		for i, w := range weights {
			acc += w
			if pick < acc {
				idx = i
				break
			}
		}
		out = append(out, remaining[idx])
		// Swap-remove the picked index from both slices.
		last := len(remaining) - 1
		remaining[idx] = remaining[last]
		weights[idx] = weights[last]
		remaining = remaining[:last]
		weights = weights[:last]
	}
	return out, nil
}

// Verify rand.Rand satisfies the local Rng interface at compile time.
var _ Rng = (*rand.Rand)(nil)
