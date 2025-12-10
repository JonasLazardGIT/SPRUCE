package credential

import (
	"fmt"

	ntrurio "vSIS-Signature/ntru/io"
	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// CenterBounded wraps v back into [-B, B] using modular arithmetic with modulus
// 2B+1. It assumes B > 0.
func CenterBounded(v, bound int64) int64 {
	mod := 2*bound + 1
	w := (v + bound) % mod
	if w < 0 {
		w += mod
	}
	return w - bound
}

// CombineRandomness computes center(rU + rI) component-wise with the provided
// bound. The output is guaranteed to lie in [-bound, bound].
func CombineRandomness(rUser, rIssuer []int64, bound int64) ([]int64, error) {
	if bound <= 0 {
		return nil, fmt.Errorf("bound must be > 0")
	}
	if len(rUser) != len(rIssuer) {
		return nil, fmt.Errorf("length mismatch: user=%d issuer=%d", len(rUser), len(rIssuer))
	}
	out := make([]int64, len(rUser))
	for i := range rUser {
		out[i] = CenterBounded(rUser[i]+rIssuer[i], bound)
	}
	return out, nil
}

// HashMessage builds t = h_{m,(r0,r1)}(B) using explicit polynomials for the
// message and randomness, mirroring BuildWitnessFromDisk but without seeds.
// All inputs are expected in coefficient domain; B must be in NTT form.
// The returned coefficients are centered in [-q/2, q/2] and can be fed
// directly to the sampler.
func HashMessage(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m1, m2, r0, r1 *ring.Poly,
) ([]int64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(B) != 4 {
		return nil, fmt.Errorf("B must contain 4 polynomials, got %d", len(B))
	}
	if m1 == nil || m2 == nil || r0 == nil || r1 == nil {
		return nil, fmt.Errorf("nil input polynomial")
	}

	// Combine m1 || m2 into a single polynomial placeholder via coefficient-wise
	// addition; callers can swap this aggregator when a concrete encoding is set.
	mCombined := ringQ.NewPoly()
	ring.Copy(m1, mCombined)
	ringQ.Add(mCombined, m2, mCombined)

	clone := func(p *ring.Poly) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		return cp
	}

	mPoly := clone(mCombined)
	x0 := clone(r0)
	x1 := clone(r1)

	tNTT, err := vsishash.ComputeBBSHash(ringQ, B, mPoly, x0, x1)
	if err != nil {
		return nil, err
	}
	tCoeff := ringQ.NewPoly()
	ringQ.InvNTT(tNTT, tCoeff)

	q := int64(ringQ.Modulus[0])
	half := q / 2
	out := make([]int64, ringQ.N)
	for i, c := range tCoeff.Coeffs[0] {
		v := int64(c)
		if v > half {
			v -= q
		}
		out[i] = v
	}
	return out, nil
}

// LoadDefaultRing loads the Parameters.json ring for helpers that need it
// without duplicating boilerplate in callers.
func LoadDefaultRing() (*ring.Ring, error) {
	par, err := ntrurio.LoadParams("Parameters/Parameters.json", true)
	if err != nil {
		if parUp, errUp := ntrurio.LoadParams("../Parameters/Parameters.json", true); errUp == nil {
			par = parUp
		} else {
			return nil, err
		}
	}
	return ring.NewRing(par.N, []uint64{par.Q})
}
