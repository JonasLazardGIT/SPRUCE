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
