package PIOP

import (
	"math/big"
	"time"

	measure "vSIS-Signature/measure"
	prof "vSIS-Signature/prof"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildFparLinfChain constructs the parallel constraints for the membership-chain gadget.
func buildFparLinfChain(r *ring.Ring, P []*ring.Poly, cd ChainDecomp, spec LinfSpec) (Fpar []*ring.Poly) {
	defer prof.Track(time.Now(), "buildFparLinfChain")
	q := r.Modulus[0]
	for t := 0; t < len(P); t++ {
		// (1) Tie magnitude to witness row: M_t^2 - P_t^2 = 0.
		msq := r.NewPoly()
		psq := r.NewPoly()
		r.MulCoeffs(cd.M[t], cd.M[t], msq)
		r.MulCoeffs(P[t], P[t], psq)
		r.Sub(msq, psq, msq)
		Fpar = append(Fpar, msq)

		// (2) Digit assembly: M_t - Σ_i R^i·D_i = 0.
		recon := r.NewPoly()
		tmp := r.NewPoly()
		for i := 0; i < spec.L; i++ {
			scalePolyNTT(r, cd.D[t][i], spec.RPows[i]%q, tmp)
			addInto(r, recon, tmp)
		}
		assem := r.NewPoly()
		r.Sub(cd.M[t], recon, assem)
		Fpar = append(Fpar, assem)

		// (3) Membership checks for digits: F_i(X) = P_{D_i}(D_i(X)).
		for i := 0; i < spec.L; i++ {
			Fpar = append(Fpar, composePolyNTT(r, cd.D[t][i], spec.PDi[i]))
		}
	}
	if measure.Enabled {
		qb := new(big.Int).SetUint64(q)
		bytesR := measure.BytesRing(r.N, qb)
		measure.Global.Add("piop/Fpar/linf_chain", int64(len(Fpar))*int64(bytesR))
	}
	return
}
