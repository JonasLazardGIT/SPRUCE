package PIOP

import (
	"fmt"

	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// loadParamsAndOmega loads Parameters.json, constructs the ring, and derives
// the evaluation set Ω exactly as buildSimWith currently does. It returns the
// ring, omega, and ncols (ring dimension).
func loadParamsAndOmega(opts SimOpts) (*ring.Ring, []uint64, int, error) {
	opts.applyDefaults()
	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("load params: %w", err)
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ring.NewRing: %w", err)
	}
	q := ringQ.Modulus[0]
	ncols := opts.NCols
	if ncols <= 0 {
		ncols = int(ringQ.N)
	}
	if opts.NLeaves > 0 && opts.NLeaves != ncols {
		return nil, nil, 0, fmt.Errorf("SimOpts.NLeaves=%d mismatch ring dimension %d", opts.NLeaves, ncols)
	}
	// Derive omega exactly as buildSimWith: take NTT of X and slice first ncols.
	px := ringQ.NewPoly()
	px.Coeffs[0][1] = 1
	pts := ringQ.NewPoly()
	ringQ.NTT(px, pts)
	omega := pts.Coeffs[0][:ncols]
	if err := checkOmega(omega, q); err != nil {
		return nil, nil, 0, fmt.Errorf("invalid omega: %w", err)
	}
	return ringQ, omega, ncols, nil
}
