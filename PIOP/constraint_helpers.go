package PIOP

import (
	"fmt"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// BuildBoundConstraints scans the supplied polys (coeff domain) and fails if any
// coefficient exceeds |bound| after centering into [-q/2, q/2]. It is a
// lightweight helper so credential/PACS builders can reuse a consistent bound
// check without duplicating code.
func BuildBoundConstraints(ringQ *ring.Ring, polys []*ring.Poly, bound int64) error {
	if ringQ == nil {
		return fmt.Errorf("nil ring")
	}
	if bound <= 0 {
		return fmt.Errorf("invalid bound %d", bound)
	}
	q := int64(ringQ.Modulus[0])
	half := q / 2
	for idx, p := range polys {
		if p == nil {
			return fmt.Errorf("nil poly at %d", idx)
		}
		for _, c := range p.Coeffs[0] {
			cv := int64(c)
			if cv > half {
				cv -= q
			}
			if cv < -half {
				cv += q
			}
			if cv > bound || cv < -bound {
				return fmt.Errorf("bound exceeded at poly %d", idx)
			}
		}
	}
	return nil
}

// BuildCommitConstraints builds residual polys for Ac·vec - Com. All inputs
// must be in the same domain (NTT). Returns one poly per row of Ac.
func BuildCommitConstraints(ringQ *ring.Ring, Ac [][]*ring.Poly, vec []*ring.Poly, com []*ring.Poly) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(Ac) == 0 {
		return nil, fmt.Errorf("empty Ac")
	}
	rows := len(Ac)
	cols := len(Ac[0])
	if len(vec) != cols {
		return nil, fmt.Errorf("vec length mismatch: got %d want %d", len(vec), cols)
	}
	if len(com) != rows {
		return nil, fmt.Errorf("com length mismatch: got %d want %d", len(com), rows)
	}
	residuals := make([]*ring.Poly, rows)
	tmp := ringQ.NewPoly()
	for i := 0; i < rows; i++ {
		if len(Ac[i]) != cols {
			return nil, fmt.Errorf("ragged Ac row %d", i)
		}
		res := ringQ.NewPoly()
		for j := 0; j < cols; j++ {
			ringQ.MulCoeffs(Ac[i][j], vec[j], tmp)
			ringQ.Add(res, tmp, res)
		}
		// res = Ac·vec - Com
		ringQ.Sub(res, com[i], res)
		residuals[i] = res
	}
	return residuals, nil
}

// BuildCenterConstraints returns residual polys center(RU+RI) - R. Inputs are
// expected in NTT domain; this helper converts to coeff, recenters using
// credential.CenterBounded, lifts back to NTT, and returns residuals.
func BuildCenterConstraints(ringQ *ring.Ring, bound int64, ru []*ring.Poly, ri []*ring.Poly, r []*ring.Poly) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(ru) != len(ri) || len(ru) != len(r) {
		return nil, fmt.Errorf("length mismatch ru=%d ri=%d r=%d", len(ru), len(ri), len(r))
	}
	q := int64(ringQ.Modulus[0])
	half := q / 2
	toCoeff := func(p *ring.Poly) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		ringQ.InvNTT(cp, cp)
		return cp
	}
	res := make([]*ring.Poly, len(ru))
	for i := range ru {
		ruC := toCoeff(ru[i])
		riC := toCoeff(ri[i])
		out := ringQ.NewPoly()
		for idx := 0; idx < ringQ.N; idx++ {
			auv := int64(ruC.Coeffs[0][idx])
			bv := int64(riC.Coeffs[0][idx])
			if auv > half {
				auv -= q
			}
			if bv > half {
				bv -= q
			}
			cv := credential.CenterBounded(auv+bv, bound)
			if cv < 0 {
				out.Coeffs[0][idx] = uint64(cv + q)
			} else {
				out.Coeffs[0][idx] = uint64(cv)
			}
		}
		ringQ.NTT(out, out)
		diff := ringQ.NewPoly()
		ringQ.Sub(out, r[i], diff)
		res[i] = diff
	}
	return res, nil
}

// BuildSignatureConstraint builds residual polys for A·U - T (T in coeff domain).
func BuildSignatureConstraint(ringQ *ring.Ring, A [][]*ring.Poly, U []*ring.Poly, T []int64) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(A) == 0 || len(U) == 0 {
		return nil, fmt.Errorf("empty A or U")
	}
	rows := len(A)
	cols := len(A[0])
	if len(U) != cols {
		return nil, fmt.Errorf("u length mismatch: got %d want %d", len(U), cols)
	}
	if len(T) != ringQ.N {
		return nil, fmt.Errorf("t length mismatch: got %d want %d", len(T), ringQ.N)
	}
	residuals := make([]*ring.Poly, rows)
	tmp := ringQ.NewPoly()
	tPoly := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i := 0; i < ringQ.N; i++ {
		v := T[i]
		if v < 0 {
			v += q
		}
		tPoly.Coeffs[0][i] = uint64(v % q)
	}
	ringQ.NTT(tPoly, tPoly)
	for i := 0; i < rows; i++ {
		acc := ringQ.NewPoly()
		for j := 0; j < cols; j++ {
			ringQ.MulCoeffs(A[i][j], U[j], tmp)
			ringQ.Add(acc, tmp, acc)
		}
		ringQ.Sub(acc, tPoly, acc)
		residuals[i] = acc
	}
	return residuals, nil
}
