package PIOP

import (
	"math/big"

	measure "vSIS-Signature/measure"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildFparRangeMembership adds one parallel constraint row per input row:
// for each row P, it appends the true composition P_B(P(X)).
func buildFparRangeMembership(
	r *ring.Ring,
	rows []*ring.Poly,
	spec RangeMembershipSpec,
) (Fpar []*ring.Poly) {
	q := r.Modulus[0]
	for _, row := range rows {
		coeff := r.NewPoly()
		r.InvNTT(row, coeff)
		out := r.NewPoly()
		for i, c := range coeff.Coeffs[0] {
			out.Coeffs[0][i] = EvalPoly(spec.Coeffs, c%q, q)
		}
		r.NTT(out, out)
		Fpar = append(Fpar, out)
	}
	if measure.Enabled && len(Fpar) > 0 {
		qb := new(big.Int).SetUint64(r.Modulus[0])
		bytesR := measure.BytesRing(r.N, qb)
		measure.Global.Add("piop/Fpar/membership", int64(len(Fpar))*int64(bytesR))
	}
	return
}

// buildFparRangeMembershipCompose builds parallel constraints as the true
// polynomial composition P_B(P_i(X)). This is required for θ>1 K-point replay,
// because the verifier evaluates F_j at random points outside Ω.
// Inputs are expected in NTT domain; output polys are in NTT domain.
func buildFparRangeMembershipCompose(
	r *ring.Ring,
	rows []*ring.Poly,
	spec RangeMembershipSpec,
) (Fpar []*ring.Poly) {
	q := r.Modulus[0]
	if len(spec.Coeffs) == 0 {
		return nil
	}
	for _, row := range rows {
		if row == nil {
			Fpar = append(Fpar, nil)
			continue
		}
		// Horner composition in coefficient domain: res = P_B(P(X)).
		resCoeff := r.NewPoly()
		tmpNTT := r.NewPoly()
		for i := len(spec.Coeffs) - 1; i >= 0; i-- {
			// res = res * row (polynomial multiplication).
			r.NTT(resCoeff, tmpNTT)
			r.MulCoeffs(tmpNTT, row, tmpNTT)
			r.InvNTT(tmpNTT, resCoeff)
			c := spec.Coeffs[i] % q
			if c != 0 {
				resCoeff.Coeffs[0][0] = (resCoeff.Coeffs[0][0] + c) % q
			}
		}
		resNTT := r.NewPoly()
		r.NTT(resCoeff, resNTT)
		Fpar = append(Fpar, resNTT)
	}
	if measure.Enabled && len(Fpar) > 0 {
		qb := new(big.Int).SetUint64(r.Modulus[0])
		bytesR := measure.BytesRing(r.N, qb)
		measure.Global.Add("piop/Fpar/membership_compose", int64(len(Fpar))*int64(bytesR))
	}
	return
}
