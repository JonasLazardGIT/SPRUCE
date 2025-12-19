package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// deriveMaskingConfig computes masking parameters and degree targets from the
// constraint sets, mirroring buildSimWith. Returns degree target/bound, the
// MaskConfig, and whether clipping occurred.
func deriveMaskingConfig(ringQ *ring.Ring, opts SimOpts, fparAll, faggAll []*ring.Poly, omega []uint64) (parallelDeg, aggDeg, maskDegreeTarget, maskDegreeBound int, cfg MaskConfig, maskDegreeClipped bool, err error) {
	opts.applyDefaults()
	cfg = MaskConfigFromOpts(opts)
	if cfg.Rho <= 0 {
		cfg.Rho = 1
	}
	if cfg.EllPrime <= 0 {
		cfg.EllPrime = 1
	}
	// Degree targets based on max degree of F-par/F-agg over omega.
	maxDeg := func(list []*ring.Poly) int {
		d := -1
		for _, p := range list {
			if p == nil {
				continue
			}
			deg := maxPolyDegree(ringQ, p)
			if deg > d {
				d = deg
			}
		}
		return d
	}
	parallelDeg = maxDeg(fparAll)
	aggDeg = maxDeg(faggAll)
	if parallelDeg < 0 {
		if len(fparAll) == 0 {
			err = fmt.Errorf("empty constraint lists")
			return
		}
		parallelDeg = 0
	}
	if aggDeg < 0 {
		if len(faggAll) == 0 {
			aggDeg = 0 // allow pure Fpar statements
		} else {
			err = fmt.Errorf("empty constraint lists")
			return
		}
	}
	// Compute dQ if not overridden.
	if cfg.DQ <= 0 {
		cfg.DQ = computeDQFromConstraintDegrees(parallelDeg, aggDeg, len(omega), opts.EllPrime)
	}
	// Target = dQ (as in PACS path), but clip to ring size if needed.
	maskDegreeBound = cfg.DQ
	maskDegreeTarget = cfg.DQ
	ringBound := 0
	if len(omega) > 0 {
		ringBound = len(omega) - 1
	}
	if ringBound > 0 && maskDegreeTarget > ringBound {
		maskDegreeTarget = ringBound
		maskDegreeClipped = true
	}
	return
}
