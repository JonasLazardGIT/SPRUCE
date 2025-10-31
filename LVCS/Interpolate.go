package lvcs

import (
	"errors"
	"math/big"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// interpolateRow builds the unique deg< (ncols+ell) polynomial P
// satisfying
//
//	P(ω^i)       = row[i]  for i=0..ncols-1
//	P(ω^(ncols+i)) = mask[i] for i=0..ell-1
func interpolateRow(
	ringQ *ring.Ring,
	row []uint64, // length = ncols
	mask []uint64, // length = ell
	ncols int,
	ell int,
) (*ring.Poly, error) {
	mod := ringQ.Modulus[0]
	N := ringQ.N
	m := ncols + ell
	if m > N {
		return nil, errors.New("interpolateRow: degree exceed ring.N")
	}

	// 1) Derive the m domain points xs[i] = ω^i via NTT of X
	px := ringQ.NewPoly()
	px.Coeffs[0][1] = 1 // f(X)=X
	pvs := ringQ.NewPoly()
	ringQ.NTT(px, pvs)
	xs := pvs.Coeffs[0][:m] // xs[i] = ω^i

	// 2) Build the combined y-values
	ys := make([]uint64, m)
	copy(ys[:ncols], row)
	copy(ys[ncols:], mask)

	// 3) Compute T(X) = ∏_{j=0..m-1} (X - xs[j]), deg=m
	T := make([]uint64, m+1)
	T[0] = 1
	for _, xj := range xs {
		for k := m; k >= 1; k-- {
			// T[k] = T[k-1] - xj*T[k] mod q
			T[k] = (T[k-1] + mod - (xj * T[k] % mod)) % mod
		}
		// T[0] = - xj * T[0]
		T[0] = (mod - (xj * T[0] % mod)) % mod
	}

	// 4) Interpolate via sum_i [ y_i * Qi(X) * invDenom_i ]
	Pcoefs := make([]uint64, m)
	tmp := make([]uint64, m)
	for i, xi := range xs {
		// 4.1 synthetic‐division: Qi = T/(X - xi)
		tmp[m-1] = T[m]
		for k := m - 2; k >= 0; k-- {
			tmp[k] = (T[k+1] + xi*tmp[k+1]) % mod
		}
		// 4.2 denom_i = ∏_{j≠i}(xi - xj)
		denom := uint64(1)
		for j, xj := range xs {
			if j == i {
				continue
			}
			diff := (xi + mod - xj) % mod
			denom = (denom * diff) % mod
		}
		// 4.3 invert denom
		inv := new(big.Int).ModInverse(
			new(big.Int).SetUint64(denom),
			new(big.Int).SetUint64(mod),
		)
		if inv == nil {
			return nil, errors.New("interpolateRow: denom not invertible")
		}
		invDen := inv.Uint64()

		// 4.4 accumulate: Pcoefs += (y_i * invDen) * tmp
		scale := (ys[i] * invDen) % mod
		for k := 0; k < m; k++ {
			Pcoefs[k] = (Pcoefs[k] + tmp[k]*scale) % mod
		}
	}

	// 5) Pack into ring.Poly and zero-pad above deg<m
	P := ringQ.NewPoly()
	copy(P.Coeffs[0][:m], Pcoefs)
	for k := m; k < N; k++ {
		P.Coeffs[0][k] = 0
	}
	return P, nil
}
