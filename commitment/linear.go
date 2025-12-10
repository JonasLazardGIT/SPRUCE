package commitment

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Matrix is a row-major matrix of NTT-domain polynomials.
type Matrix [][]*ring.Poly

// Vector is a helper alias for a slice of polynomials.
type Vector []*ring.Poly

// Commit computes com = A_c · vec, where A_c is a row-major matrix and vec is
// the concatenation [m1 || m2 || rU0 || rU1 || r]. All polynomials must live in
// the same ring/domain (NTT or coefficient) so that MulCoeffs is well defined.
func Commit(ringQ *ring.Ring, Ac Matrix, vec Vector) (Vector, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(Ac) == 0 || len(Ac[0]) == 0 {
		return nil, fmt.Errorf("empty matrix")
	}
	nCols := len(Ac[0])
	if nCols != len(vec) {
		return nil, fmt.Errorf("dimension mismatch: cols=%d vec=%d", nCols, len(vec))
	}
	com := make(Vector, len(Ac))
	for i := range Ac {
		if len(Ac[i]) != nCols {
			return nil, fmt.Errorf("ragged matrix at row %d", i)
		}
		acc := ringQ.NewPoly()
		tmp := ringQ.NewPoly()
		for j := 0; j < nCols; j++ {
			if Ac[i][j] == nil || vec[j] == nil {
				return nil, fmt.Errorf("nil polynomial at row %d col %d", i, j)
			}
			ringQ.MulCoeffs(Ac[i][j], vec[j], tmp)
			ringQ.Add(acc, tmp, acc)
		}
		com[i] = acc
	}
	return com, nil
}

// Verify recomputes the commitment and checks it matches the provided value.
func Verify(ringQ *ring.Ring, Ac Matrix, vec, com Vector) error {
	if len(com) != len(Ac) {
		return fmt.Errorf("commitment length mismatch: got %d want %d", len(com), len(Ac))
	}
	recomputed, err := Commit(ringQ, Ac, vec)
	if err != nil {
		return err
	}
	zero := ringQ.NewPoly()
	diff := ringQ.NewPoly()
	for i := range recomputed {
		ringQ.Sub(recomputed[i], com[i], diff)
		if !ringQ.Equal(diff, zero) {
			return fmt.Errorf("commitment mismatch at row %d", i)
		}
	}
	return nil
}

// Open recomputes the commitment from the opening (vec) and returns it; this is
// a convenience for callers who want both the value and verification.
func Open(ringQ *ring.Ring, Ac Matrix, vec Vector) (Vector, error) {
	return Commit(ringQ, Ac, vec)
}
