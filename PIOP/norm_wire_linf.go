package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// LinfChainAux carries metadata about the membership-chain rows appended to w1.
type LinfChainAux struct {
	Spec     LinfSpec
	Rows     ChainDecomp
	RowBase  int
	SigCount int
}

func minimalChainDigits(beta uint64, W int) (int, error) {
	if W <= 0 {
		return 0, fmt.Errorf("invalid chain window bits: %d", W)
	}
	// Enforce at least two digits (mask + one digit row).
	minDigits := 2
	if beta == 0 {
		return minDigits, nil
	}
	base := uint64(1) << uint(W)
	if base <= 1 {
		return 0, fmt.Errorf("invalid base derived from W=%d", W)
	}
	// Positive LSD range cap is (base/2 - 1); geometric series covers higher digits.
	// maxPos(L) = (base^L - base) + (base/2 - 1)
	maxPositive := func(digits int) (uint64, bool) {
		if digits <= 0 {
			return 0, false
		}
		pow := uint64(1)
		for i := 0; i < digits; i++ {
			if pow > ^uint64(0)/base {
				return 0, false
			}
			pow *= base
		}
		if pow < base {
			return 0, false
		}
		res := pow - base
		lsd := (base / 2)
		if lsd > 0 {
			res += lsd - 1
		}
		return res, true
	}
	for digits := minDigits; digits < 64; digits++ {
		if capPos, ok := maxPositive(digits); ok && capPos >= beta {
			return digits, nil
		}
	}
	return 0, fmt.Errorf("unable to cover beta=%d with base=2^%d (digits limit exceeded)", beta, W)
}

func maxAbsInRows(r *ring.Ring, polys []*ring.Poly, omega []uint64, q uint64) uint64 {
	if len(polys) == 0 || len(omega) == 0 {
		return 0
	}
	coeff := r.NewPoly()
	maxObserved := uint64(0)
	for _, row := range polys {
		if row == nil {
			continue
		}
		r.InvNTT(row, coeff)
		for _, w := range omega {
			val := EvalPoly(coeff.Coeffs[0], w%q, q)
			a := int64(val)
			if a > int64(q)/2 {
				a -= int64(q)
			}
			if a < 0 {
				if v := uint64(-a); v > maxObserved {
					maxObserved = v
				}
			} else {
				if v := uint64(a); v > maxObserved {
					maxObserved = v
				}
			}
		}
	}
	return maxObserved
}

func buildLinfChainForPolys(
	r *ring.Ring,
	polys []*ring.Poly,
	spec LinfSpec,
	omega []uint64,
	ell int,
) (ChainDecomp, []*ring.Poly, error) {
	cd := appendChainDigits(r, len(polys), spec.L)
	if err := ProverFillLinfChain(r, polys, spec, omega, ell, cd); err != nil {
		return ChainDecomp{}, nil, err
	}
	fpar := buildFparLinfChain(r, polys, cd, spec)
	return cd, fpar, nil
}

func appendChainRows(w []*ring.Poly, cd ChainDecomp) []*ring.Poly {
	for t := range cd.M {
		w = append(w, cd.M[t])
		for i := 0; i < len(cd.D[t]); i++ {
			w = append(w, cd.D[t][i])
		}
	}
	return w
}

// makeNormConstraintsLinfChain wires the ℓ∞ membership-chain gadget.
func makeNormConstraintsLinfChain(
	r *ring.Ring,
	q uint64,
	omega []uint64,
	ell int,
	mSig int,
	w1 []*ring.Poly,
	beta uint64,
	chainWindowBits int,
	chainDigits int,
	extra []*ring.Poly,
) (newW1 []*ring.Poly, Fpar []*ring.Poly, aux LinfChainAux, err error) {
	newW1 = append([]*ring.Poly{}, w1...)
	observed := maxAbsInRows(r, w1, omega, q)
	if len(extra) > 0 {
		if extraMax := maxAbsInRows(r, extra, omega, q); extraMax > observed {
			observed = extraMax
		}
	}
	if observed > beta {
		beta = observed
	}
	digits := chainDigits
	if digits <= 0 {
		var errDigits error
		digits, errDigits = minimalChainDigits(beta, chainWindowBits)
		if errDigits != nil {
			return nil, nil, LinfChainAux{}, errDigits
		}
	}
	spec := NewLinfChainSpec(q, chainWindowBits, digits, ell, beta)
	cd, Fpar, err := buildLinfChainForPolys(r, newW1[:mSig], spec, omega, ell)
	if err != nil {
		return
	}
	rowBase := len(newW1)
	newW1 = appendChainRows(newW1, cd)
	aux = LinfChainAux{Spec: spec, Rows: cd, RowBase: rowBase, SigCount: mSig}
	return
}
