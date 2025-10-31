package ntru

import (
	"errors"
	"math/big"
	"os"
)

type SolveOpts struct {
	Prec     uint
	Reduce   bool
	MaxIters int
	// Note: solver selection is ignored; we always run the C-style tower+Babai
	// solver to match the C reference (ext=2 for power-of-two N).
	UseCTower bool
}

// NTRUSolve computes integer F,G such that f*G - g*F = q in Z[x]/(x^N+1).
// Inputs f and g are centered int64 slices of length N.
func NTRUSolve(f, g []int64, par Params, opts SolveOpts) (F, G []int64, err error) {
	dbg(os.Stderr, "[NTRUSolve] enter N=%d Q=%s Prec=%d Reduce=%v MaxIters=%d (solver=C-tower+Babai)\n", par.N, par.Q.String(), opts.Prec, opts.Reduce, opts.MaxIters)
	if len(f) != par.N || len(g) != par.N {
		return nil, nil, errors.New("dimension mismatch")
	}
	// C-style tower + Babai path
	F, G, err = ntruCSolveTowerBabai(f, g, par, opts)
	if err != nil {
		dbg(os.Stderr, "[NTRUSolve] error: %v\n", err)
		return nil, nil, err
	}
	dbg(os.Stderr, "[NTRUSolve] done\n")
	return F, G, nil
}

// helper to convert int64 arrays to ModQPoly maybe? (not required here)

// Int64ToModQPoly converts []int64 to ModQPoly modulo Q.
func Int64ToModQPoly(coeffs []int64, par Params) ModQPoly {
	p := NewModQPoly(par.N, par.Q)
	for i := 0; i < par.N; i++ {
		if coeffs[i] < 0 {
			p.Coeffs[i].Add(p.Coeffs[i], par.Q)
		}
		p.Coeffs[i].Add(p.Coeffs[i], big.NewInt(coeffs[i]))
		p.Coeffs[i].Mod(p.Coeffs[i], par.Q)
	}
	return p
}
