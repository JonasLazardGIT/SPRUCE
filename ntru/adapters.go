package ntru

import (
	"errors"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// PolyNTTToEval converts an NTT-domain polynomial to its evaluation vector.
func PolyNTTToEval(r *ring.Ring, a *ring.Poly, par Params, epar EmbedParams) (EvalVec, error) {
	if a.N() != par.N {
		return EvalVec{}, errors.New("degree mismatch")
	}
	tmp := a.CopyNew()
	FromNTT(r, tmp)
	r.InvMForm(tmp, tmp)
	coeffs := make([]int64, par.N)
	for i := 0; i < par.N; i++ {
		coeffs[i] = int64(tmp.Coeffs[0][i])
	}
	centered := CenterModQ(coeffs, r.Modulus[0])
	return ToEval(centered, par, epar)
}

// CoeffIntToPolyNTT converts centered int64 coefficients to an NTT-domain polynomial.
func CoeffIntToPolyNTT(r *ring.Ring, a []int64, par Params) (*ring.Poly, error) {
	if len(a) != par.N {
		return nil, errors.New("dimension mismatch")
	}
	poly := r.NewPoly()
	coeffs := DecenterToModQ(a, r.Modulus[0])
	for i := 0; i < par.N; i++ {
		poly.Coeffs[0][i] = coeffs[i]
	}
	r.MForm(poly, poly)
	ToNTT(r, poly)
	return poly, nil
}
