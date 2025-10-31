package ntru

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// SeedPolyBounds defines the inclusive range [Min, Max] from which seed-derived
// polynomial coefficients are sampled before being embedded modulo q.
type SeedPolyBounds struct {
	Min int64
	Max int64
}

// DefaultSeedPolyBounds contains the default coefficient range [-7,7] used for
// seed-derived polynomials m, x0, x1 so they stay within the l_infty chain LSD window.
var DefaultSeedPolyBounds = SeedPolyBounds{
	Min: -7,
	Max: 7,
}

var currentSeedPolyBounds atomic.Value

func init() {
	currentSeedPolyBounds.Store(DefaultSeedPolyBounds)
}

// SetSeedPolyBounds updates the global bounds used for seed-derived polynomials.
// The update is process-wide and affects any subsequent sampling.
func SetSeedPolyBounds(bounds SeedPolyBounds) error {
	if err := validateSeedPolyBounds(bounds); err != nil {
		return err
	}
	currentSeedPolyBounds.Store(bounds)
	return nil
}

// CurrentSeedPolyBounds returns the bounds in use for seed-derived polynomials.
func CurrentSeedPolyBounds() SeedPolyBounds {
	return currentSeedPolyBounds.Load().(SeedPolyBounds)
}

// FillPolyBoundedFromPRNG fills the provided polynomial with coefficients
// sampled uniformly from the inclusive range [bounds.Min, bounds.Max], then
// embeds them modulo the ring modulus. Sampling is deterministic given the
// supplied PRNG.
func FillPolyBoundedFromPRNG(r *ring.Ring, prng utils.PRNG, out *ring.Poly, bounds SeedPolyBounds) error {
	if r == nil || out == nil {
		return fmt.Errorf("nil ring or polynomial")
	}
	if prng == nil {
		return fmt.Errorf("nil PRNG")
	}
	if err := validateSeedPolyBounds(bounds); err != nil {
		return err
	}

	numLevels := len(out.Coeffs)
	if numLevels == 0 {
		return fmt.Errorf("polynomial has no levels")
	}
	if len(r.Modulus) < numLevels {
		return fmt.Errorf("ring modulus vector shorter than polynomial levels")
	}
	coeffsPerLevel := len(out.Coeffs[0])
	for level := 1; level < numLevels; level++ {
		if len(out.Coeffs[level]) != coeffsPerLevel {
			return fmt.Errorf("inconsistent polynomial level length at level %d", level)
		}
	}

	span := bounds.Max - bounds.Min + 1
	if span <= 0 {
		return fmt.Errorf("invalid seed bounds: empty or overflowing range")
	}
	rangeSize := uint64(span)
	maxUint64 := uint64(^uint64(0))
	threshold := (maxUint64 / rangeSize) * rangeSize

	buf := make([]byte, 8)
	for i := 0; i < coeffsPerLevel; i++ {
		var word uint64
		for {
			if _, err := io.ReadFull(prng, buf); err != nil {
				return fmt.Errorf("prng read: %w", err)
			}
			word = binary.LittleEndian.Uint64(buf)
			if word < threshold {
				break
			}
		}
		sample := int64(word%rangeSize) + bounds.Min
		for level := 0; level < numLevels; level++ {
			modulus := r.Modulus[level]
			if sample >= 0 {
				out.Coeffs[level][i] = uint64(sample) % modulus
			} else {
				neg := uint64(-sample) % modulus
				if neg == 0 {
					out.Coeffs[level][i] = 0
				} else {
					out.Coeffs[level][i] = (modulus - neg) % modulus
				}
			}
		}
	}
	return nil
}

func validateSeedPolyBounds(bounds SeedPolyBounds) error {
	if bounds.Max < bounds.Min {
		return fmt.Errorf("invalid seed bounds: max < min (%d < %d)", bounds.Max, bounds.Min)
	}
	span := bounds.Max - bounds.Min + 1
	if span <= 0 {
		return fmt.Errorf("invalid seed bounds range (overflow)")
	}
	return nil
}
