package ntru

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// MatOp represents the operator [g | -f] acting on pairs (z0,z1).
type MatOp struct {
	par   Params
	rings []*ring.Ring
	gNTT  []*ring.Poly
	fNTT  []*ring.Poly
}

// NewMatOpFG precomputes the operator for multiplying by g and f.
func NewMatOpFG(f, g ModQPoly, par Params) (*MatOp, error) {
	rings, err := par.BuildRings()
	if err != nil {
		return nil, err
	}
	if len(rings) == 0 {
		return nil, fmt.Errorf("no rings")
	}
	limbsF := ToRNS(f, par)
	limbsG := ToRNS(g, par)
	fNTT := make([]*ring.Poly, len(rings))
	gNTT := make([]*ring.Poly, len(rings))
	for i, r := range rings {
		F := r.NewPoly()
		copy(F.Coeffs[0], limbsF[i].Coeffs[0])
		r.MForm(F, F)
		ToNTT(r, F)
		fNTT[i] = F

		G := r.NewPoly()
		copy(G.Coeffs[0], limbsG[i].Coeffs[0])
		r.MForm(G, G)
		ToNTT(r, G)
		gNTT[i] = G
	}
	return &MatOp{par: par, rings: rings, gNTT: gNTT, fNTT: fNTT}, nil
}

// ApplyPair computes y = g*z0 - f*z1 (mod q), returning coeff-domain ModQPoly.
func (op *MatOp) ApplyPair(z0, z1 ModQPoly) (ModQPoly, error) {
	limbs0 := ToRNS(z0, op.par)
	limbs1 := ToRNS(z1, op.par)
	outLimbs := make([]*ring.Poly, len(op.rings))
	for i, r := range op.rings {
		Z0 := r.NewPoly()
		copy(Z0.Coeffs[0], limbs0[i].Coeffs[0])
		r.MForm(Z0, Z0)
		ToNTT(r, Z0)

		Z1 := r.NewPoly()
		copy(Z1.Coeffs[0], limbs1[i].Coeffs[0])
		r.MForm(Z1, Z1)
		ToNTT(r, Z1)

		Y := r.NewPoly()
		tmp := r.NewPoly()
		r.MulCoeffsMontgomery(Z0, op.gNTT[i], Y)
		r.MulCoeffsMontgomery(Z1, op.fNTT[i], tmp)
		r.Sub(Y, tmp, Y)
		FromNTT(r, Y)
		r.InvMForm(Y, Y)
		outLimbs[i] = Y
	}
	return FromRNS(outLimbs, op.par), nil
}
