package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

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

// BuildCenterConstraints returns residual polys ru+ri-r. Inputs are expected in
// NTT domain; the caller should recenter externally. Bound is unused here; it
// is kept for future modular-wrap gadgets.
func BuildCenterConstraints(ringQ *ring.Ring, _ int64, ru []*ring.Poly, ri []*ring.Poly, r []*ring.Poly) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(ru) != len(ri) || len(ru) != len(r) {
		return nil, fmt.Errorf("length mismatch ru=%d ri=%d r=%d", len(ru), len(ri), len(r))
	}
	res := make([]*ring.Poly, len(ru))
	tmp := ringQ.NewPoly()
	for i := range ru {
		acc := ringQ.NewPoly()
		ringQ.Add(ru[i], ri[i], acc)
		ringQ.Sub(acc, r[i], tmp)
		res[i] = tmp.CopyNew()
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
		return nil, fmt.Errorf("U length mismatch: got %d want %d", len(U), cols)
	}
	if len(T) != ringQ.N {
		return nil, fmt.Errorf("T length mismatch: got %d want %d", len(T), ringQ.N)
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
