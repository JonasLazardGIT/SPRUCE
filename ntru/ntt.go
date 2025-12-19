package ntru

import (
	"github.com/tuneinsight/lattigo/v4/ring"
	"os"
)

// ToNTT applies the forward Number Theoretic Transform for a given limb.
func ToNTT(r *ring.Ring, a *ring.Poly) {
	r.NTT(a, a)
}

// FromNTT applies the inverse NTT for a given limb.
func FromNTT(r *ring.Ring, a *ring.Poly) {
	r.InvNTT(a, a)
}

// MulNTT performs coefficient-wise multiplication in the NTT domain.
func MulNTT(r *ring.Ring, a, b, out *ring.Poly) {
	r.MulCoeffsMontgomery(a, b, out)
}

// Add adds two polynomials modulo the limb modulus.
func Add(r *ring.Ring, a, b, out *ring.Poly) {
	r.Add(a, b, out)
}

// Sub subtracts two polynomials modulo the limb modulus.
func Sub(r *ring.Ring, a, b, out *ring.Poly) {
	r.Sub(a, b, out)
}

// Neg negates a polynomial modulo the limb modulus.
func Neg(r *ring.Ring, a, out *ring.Poly) {
	r.Neg(a, out)
}

// ConvolveRNS performs convolution modulo (x^N+1,Q) using RNS/NTT.
func ConvolveRNS(a, b ModQPoly, p Params) (ModQPoly, error) {
	dbg(os.Stderr, "[NTT] ConvolveRNS begin N=%d limbs=%d\n", p.N, len(p.Qi))
	rings, err := p.BuildRings()
	if err != nil {
		return ModQPoly{}, err
	}
	limbsA := ToRNS(a, p)
	limbsB := ToRNS(b, p)
	resLimbs := make([]*ring.Poly, len(rings))
	for i, r := range rings {
		r.MForm(limbsA[i], limbsA[i])
		r.MForm(limbsB[i], limbsB[i])
		ToNTT(r, limbsA[i])
		ToNTT(r, limbsB[i])
		res := r.NewPoly()
		MulNTT(r, limbsA[i], limbsB[i], res)
		FromNTT(r, res)
		r.InvMForm(res, res)
		resLimbs[i] = res
	}
	res := FromRNS(resLimbs, p)
	dbg(os.Stderr, "[NTT] ConvolveRNS done\n")
	return res, nil
}
