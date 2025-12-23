package credential

import (
	"fmt"

	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// CenterBounded wraps v into [-bound, bound] using modulus 2*bound+1.
func CenterBounded(v, bound int64) int64 {
	mod := 2*bound + 1
	w := (v + bound) % mod
	if w < 0 {
		w += mod
	}
	return w - bound
}

// CombineRandomness computes center(rUser + rIssuer) component-wise.
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

// PolyToElems converts a coefficient-domain poly to a slice of uint64 mod q, truncated to maxLen.
// If maxLen exceeds the number of coefficients, it truncates to len(coeffs).
func PolyToElems(p *ring.Poly, q uint64, maxLen int) []uint64 {
	coeffs := p.Coeffs[0]
	n := len(coeffs)
	if maxLen > n {
		maxLen = n
	}
	out := make([]uint64, maxLen)
	for i := 0; i < maxLen; i++ {
		out[i] = coeffs[i] % q
	}
	return out
}

// HashMessage computes t = h_{m,(r0,r1)}(B) from explicit polynomials.
// Inputs m1, m2, r0, r1 are expected in coefficient domain; B in NTT.
// The output coefficients are centered in [-q/2, q/2].
func HashMessage(
	ringQ *ring.Ring,
	B []*ring.Poly,
	m1, m2, r0, r1 *ring.Poly,
) ([]int64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(B) != 4 {
		return nil, fmt.Errorf("b must contain 4 polynomials, got %d", len(B))
	}
	if m1 == nil || m2 == nil || r0 == nil || r1 == nil {
		return nil, fmt.Errorf("nil input polynomial")
	}

	clone := func(p *ring.Poly) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		return cp
	}

	mCombined := clone(m1)
	ringQ.Add(mCombined, m2, mCombined)

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
