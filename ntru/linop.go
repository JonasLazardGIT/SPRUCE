package ntru

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type Op struct {
	par   Params
	rings []*ring.Ring
	hNTT  []*ring.Poly
}

func NewOpFromH(h ModQPoly, par Params) (*Op, error) {
	rings, err := par.BuildRings()
	if err != nil {
		return nil, err
	}
	if len(rings) == 0 {
		return nil, fmt.Errorf("no rings")
	}
	limbs := ToRNS(h, par)
	hNTT := make([]*ring.Poly, len(rings))
	for i, r := range rings {
		p := r.NewPoly()
		copy(p.Coeffs[0], limbs[i].Coeffs[0])
		r.MForm(p, p)
		ToNTT(r, p)
		hNTT[i] = p
	}
	return &Op{par: par, rings: rings, hNTT: hNTT}, nil
}

func (op *Op) Apply(s ModQPoly) (ModQPoly, error) {
	limbs := ToRNS(s, op.par)
	outLimbs := make([]*ring.Poly, len(op.rings))
	for i, r := range op.rings {
		a := r.NewPoly()
		copy(a.Coeffs[0], limbs[i].Coeffs[0])
		r.MForm(a, a)
		ToNTT(r, a)
		y := r.NewPoly()
		r.MulCoeffsMontgomery(a, op.hNTT[i], y)
		FromNTT(r, y)
		r.InvMForm(y, y)
		outLimbs[i] = y
	}
	y := FromRNS(outLimbs, op.par)
	return y, nil
}
