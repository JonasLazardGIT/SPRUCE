package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// thetaPolyFromNTT interpolates a public row polynomial Θ from its values on Ω.
// The input is expected in NTT (evaluation-domain) form; only the first ncols
// values are used. The output is returned in NTT form for direct use in
// constraint polynomials.
func thetaPolyFromNTT(ringQ *ring.Ring, pNTT *ring.Poly, ncols int) (*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if pNTT == nil {
		return nil, nil
	}
	if ncols <= 0 || ncols > int(ringQ.N) {
		return nil, fmt.Errorf("invalid ncols %d", ncols)
	}
	head := append([]uint64(nil), pNTT.Coeffs[0][:ncols]...)
	coeff, err := interpolateRowLocal(ringQ, head, nil, ncols, 0)
	if err != nil {
		return nil, err
	}
	ringQ.NTT(coeff, coeff)
	return coeff, nil
}

// thetaCoeffFromNTT interpolates a public row polynomial Θ from its values on Ω
// and returns the coefficient vector (in base field) for evaluation in K.
func thetaCoeffFromNTT(ringQ *ring.Ring, pNTT *ring.Poly, ncols int) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if pNTT == nil {
		return nil, nil
	}
	if ncols <= 0 || ncols > int(ringQ.N) {
		return nil, fmt.Errorf("invalid ncols %d", ncols)
	}
	head := append([]uint64(nil), pNTT.Coeffs[0][:ncols]...)
	coeff, err := interpolateRowLocal(ringQ, head, nil, ncols, 0)
	if err != nil {
		return nil, err
	}
	out := append([]uint64(nil), coeff.Coeffs[0]...)
	q := ringQ.Modulus[0]
	for i := range out {
		out[i] %= q
	}
	return out, nil
}
