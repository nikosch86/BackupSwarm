package daemon

import (
	bsquic "backupswarm/internal/quic"

	"golang.org/x/time/rate"
)

// limiterBurstFloor is the minimum burst (in bytes) applied to constructed
// limiters so a single full chunk write doesn't stall on a too-small bucket.
const limiterBurstFloor = 1 << 20 // 1 MiB

// buildLimiters constructs node-wide upload/download limiters from the
// configured byte rates. Zero on either side returns a nil limiter
// (pass-through); burst is max(rate, limiterBurstFloor).
func buildLimiters(uploadBytes, downloadBytes int64) bsquic.Limiters {
	return bsquic.Limiters{
		Up:   newLimiter(uploadBytes),
		Down: newLimiter(downloadBytes),
	}
}

func newLimiter(bytesPerSec int64) *rate.Limiter {
	if bytesPerSec <= 0 {
		return nil
	}
	burst := int(bytesPerSec)
	if int64(burst) < limiterBurstFloor {
		burst = limiterBurstFloor
	}
	return rate.NewLimiter(rate.Limit(bytesPerSec), burst)
}
