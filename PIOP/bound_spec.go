package PIOP

import "fmt"

// LinfSpec holds parameters for the membership-chain ℓ∞ bound proof.
type LinfSpec struct {
	Q      uint64     // modulus q
	R      uint64     // radix R = 2^W (must satisfy R < q)
	W      int        // bits per limb
	L      int        // number of digits
	Ell    int        // blinding points per row
	LSDLo  int        // least-significant digit minimum (balanced)
	LSDHi  int        // least-significant digit maximum (balanced)
	DMax   []int      // per-digit bound (balanced for digit 0, unsigned otherwise)
	PDi    [][]uint64 // membership polynomial coefficients per digit
	RPows  []uint64   // R^i mod q for i∈[0,L)
	MaxAbs uint64     // largest magnitude representable by the gadget
}

// buildBalancedMembershipPoly returns ∏_{u=lo}^{hi} (X - u) with roots lifted to F_q.
func buildBalancedMembershipPoly(q uint64, lo, hi int) []uint64 {
	if lo > hi {
		return []uint64{1}
	}
	P := []uint64{1}
	for u := lo; u <= hi; u++ {
		var root uint64
		if u >= 0 {
			root = uint64(u) % q
		} else {
			root = q - uint64(-u)%q
		}
		P = polyMul(P, []uint64{modSub(0, root, q), 1}, q)
	}
	return P
}

func buildMembershipPolyRange(q uint64, lo, hi int) []uint64 {
	if lo > hi {
		return []uint64{1}
	}
	P := []uint64{1}
	for u := lo; u <= hi; u++ {
		var root uint64
		if u >= 0 {
			root = uint64(u) % q
		} else {
			root = q - uint64(-u)%q
		}
		P = polyMul(P, []uint64{modSub(0, root, q), 1}, q)
	}
	return P
}

// NewLinfChainSpec instantiates the membership-chain parameters for the ℓ∞ gadget.
func NewLinfChainSpec(q uint64, W, L, ell int, beta uint64) LinfSpec {
	if (q & 1) == 0 {
		panic("q must be odd")
	}
	if ell < 1 {
		panic("ell must be ≥ 1")
	}
	if W <= 0 {
		panic("W must be ≥ 1")
	}
	if L < 2 {
		panic("L must be ≥ 2")
	}
	R := uint64(1) << uint(W)
	if R >= q {
		panic("R >= q")
	}

	dMax := make([]int, L)
	pols := make([][]uint64, L)

	// Least significant digit: balanced window [-2^{W-1}, 2^{W-1}]
	lsdLo := -(1 << (W - 1))
	lsdHi := (1 << (W - 1)) - 1
	d0max := 1 << (W - 1)
	dMax[0] = d0max
	pols[0] = buildBalancedMembershipPoly(q, lsdLo, lsdHi)

	// Higher digits: unsigned range [0, R-1]
	for i := 1; i < L; i++ {
		dMax[i] = int(R) - 1
		pols[i] = buildMembershipPolyRange(q, 0, dMax[i])
	}

	// Compute the maximum magnitude representable by the gadget.
	maxAbs := uint64(dMax[0])
	weight := R
	for i := 1; i < L; i++ {
		term := uint64(dMax[i]) * weight
		if term/weight != uint64(dMax[i]) {
			panic("linf chain: overflow while computing digit capacity")
		}
		if maxAbs > ^uint64(0)-term {
			panic("linf chain: maxAbs overflow")
		}
		maxAbs += term
		if i+1 < L {
			if weight > ^uint64(0)/R {
				panic("linf chain: R^i exceeds uint64 range")
			}
			weight *= R
		}
	}
	if beta > maxAbs {
		panic(fmt.Sprintf("linf chain: beta=%d exceeds representable range %d for W=%d and L=%d", beta, maxAbs, W, L))
	}

	RPows := make([]uint64, L)
	RPows[0] = 1 % q
	for i := 1; i < L; i++ {
		RPows[i] = (RPows[i-1] * (R % q)) % q
	}
	return LinfSpec{
		Q: q, R: R, W: W, L: L, Ell: ell,
		LSDLo: lsdLo, LSDHi: lsdHi,
		DMax: dMax, PDi: pols, RPows: RPows, MaxAbs: maxAbs,
	}
}

// RangeMembershipSpec holds the vanishing polynomial for [-B, +B].
type RangeMembershipSpec struct {
	B      int
	Coeffs []uint64 // coefficients of P_B(X) in F_q, low-to-high degree
}

// NewRangeMembershipSpec builds P_B(X) = ∏_{i=-B}^B (X - ⟨i⟩_q).
func NewRangeMembershipSpec(q uint64, B int) RangeMembershipSpec {
	if B < 0 {
		panic("B must be >= 0")
	}
	roots := make([]uint64, 0, 2*B+1)
	for i := -B; i <= B; i++ {
		var r uint64
		if i >= 0 {
			r = uint64(i) % q
		} else {
			neg := uint64(-i) % q
			r = (q - neg) % q
		}
		roots = append(roots, r)
	}
	coeffs := []uint64{1}
	for _, r := range roots {
		next := make([]uint64, len(coeffs)+1)
		for d := range coeffs {
			next[d+1] = (next[d+1] + coeffs[d]) % q
			next[d] = (next[d] + q - (coeffs[d]*r)%q) % q
		}
		coeffs = next
	}
	return RangeMembershipSpec{B: B, Coeffs: coeffs}
}
