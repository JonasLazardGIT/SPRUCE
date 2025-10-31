// vsishash/hash_exact.go
//
// Exact-ring implementation of the vSIS-BBS hash.
// Floating-point “field” arithmetic has been removed; every operand is an
// *ring.Poly in NTT (evaluation) domain and all products are Hadamard
// multiplications. The only non-trivial step is the slot-wise inverse of the
// denominator, implemented below as polyInverseNTT.
//
// Public API
//
//  - GenerateB (samples B in coefficient domain; caller may NTT)
//  - ComputeBBSHash (exact, returns NTT-domain result)
//
// Note: ComputeBBSHash NTT-lifts m/x0/x1 in place. Callers that need the
// original operands should pass copies.
package vsishash

import (
	"errors"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// -----------------------------------------------------------------------------
// GenerateB – unchanged (still coeff domain)
// -----------------------------------------------------------------------------

// GenerateB samples a common random string B ∈ Rq^(1×4), returns the four
// polynomials in **coefficient** domain; the caller must NTT them if needed.
func GenerateB(ringQ *ring.Ring, prng utils.PRNG) ([]*ring.Poly, error) {
	uni := ring.NewUniformSampler(prng, ringQ)
	B := make([]*ring.Poly, 4)
	for i := 0; i < 4; i++ {
		p := ringQ.NewPoly()
		uni.Read(p)
		B[i] = p
	}
	return B, nil
}

// -----------------------------------------------------------------------------
// polyInverseNTT  – slot-wise inverse in the NTT domain
// -----------------------------------------------------------------------------

func polyInverseNTT(r *ring.Ring, a *ring.Poly) (*ring.Poly, bool) {
	q := r.Modulus[0]

	invScalar := func(x uint64) uint64 { // x⁻¹ mod q  (q fits in 64-bit)
		// Extended GCD on uint64
		var t, newT int64 = 0, 1
		var r0, newR int64 = int64(q), int64(x)
		for newR != 0 {
			quot := r0 / newR
			t, newT = newT, t-quot*newT
			r0, newR = newR, r0-quot*newR
		}
		if r0 != 1 {
			return 0 // non-invertible
		}
		if t < 0 {
			t += int64(q)
		}
		return uint64(t)
	}

	out := r.NewPoly()
	for i, coeff := range a.Coeffs[0] {
		if coeff == 0 {
			return nil, false
		}
		out.Coeffs[0][i] = invScalar(coeff)
	}
	return out, true
}

// -----------------------------------------------------------------------------
// ComputeBBSHash  – exact ring variant (keeps same name)
// -----------------------------------------------------------------------------

// ComputeBBSHash takes B0…B3 **already in NTT**, lifts m,x0,x1 to NTT, and
// returns   t = (B0 + B1 m + B2 x0) * (B3 − x1)⁻¹  in NTT form.
func ComputeBBSHash(
	ringQ *ring.Ring,
	B []*ring.Poly, // B[0..3]  – MUST be NTT
	m, x0, x1 *ring.Poly, // coeff domain, will be lifted
) (*ring.Poly, error) {

	// 0) sanity
	if len(B) != 4 {
		return nil, errors.New("need four B polynomials")
	}

	// 1) lift message / masks to NTT
	ringQ.NTT(m, m)
	ringQ.NTT(x0, x0)
	ringQ.NTT(x1, x1)

	tmp := ringQ.NewPoly()
	r := ringQ.NewPoly()

	// r = B0
	ring.Copy(B[0], r)

	// r += B1 * m
	ringQ.MulCoeffs(B[1], m, tmp)
	ringQ.Add(r, tmp, r)

	// r += B2 * x0
	ringQ.MulCoeffs(B[2], x0, tmp)
	ringQ.Add(r, tmp, r)

	// d = B3 - x1
	d := ringQ.NewPoly()
	ringQ.Sub(B[3], x1, d)

	// dInv = d⁻¹
	dInv, ok := polyInverseNTT(ringQ, d)
	if !ok {
		return nil, errors.New("denominator not invertible")
	}

	// t = r * dInv
	t := ringQ.NewPoly()
	ringQ.MulCoeffs(r, dInv, t)

	return t, nil
}

// -----------------------------------------------------------------------------
// test: slot-wise inverse really works
// -----------------------------------------------------------------------------

func TestPolyInverseNTT(t *testing.T) {
	const N = 8
	const q = 8380417

	ringQ, _ := ring.NewRing(N, []uint64{q})
	uni, _ := utils.NewPRNG()
	us := ring.NewUniformSampler(uni, ringQ)

	a := ringQ.NewPoly()
	us.Read(a)
	ringQ.NTT(a, a) // lift ← this is what polyInverseNTT expects

	ainv, ok := polyInverseNTT(ringQ, a)
	if !ok {
		t.Fatal("poly not invertible (rare event)")
	}

	// verify Hadamard(a,ainv)==1
	prod := ringQ.NewPoly()
	ringQ.MulCoeffs(a, ainv, prod)

	for i, c := range prod.Coeffs[0] {
		if c != 1 {
			t.Fatalf("slot %d : a*ainv=%d ≠ 1", i, c)
		}
	}
}
