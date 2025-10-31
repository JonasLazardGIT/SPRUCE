package ntru

import (
	"math/big"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// IntPoly represents polynomials over Z with degree < N.
type IntPoly struct {
	Coeffs []*big.Int
}

// ModQPoly represents polynomials modulo Q.
type ModQPoly struct {
	Coeffs []*big.Int
	Q      *big.Int
}

// NewIntPoly allocates an IntPoly of size N.
func NewIntPoly(N int) IntPoly {
	coeffs := make([]*big.Int, N)
	for i := range coeffs {
		coeffs[i] = new(big.Int)
	}
	return IntPoly{Coeffs: coeffs}
}

// NewModQPoly allocates a ModQPoly of size N.
func NewModQPoly(N int, Q *big.Int) ModQPoly {
	coeffs := make([]*big.Int, N)
	for i := range coeffs {
		coeffs[i] = new(big.Int)
	}
	return ModQPoly{Coeffs: coeffs, Q: new(big.Int).Set(Q)}
}

// Add adds two IntPolys.
func (p IntPoly) Add(q IntPoly) IntPoly {
	r := NewIntPoly(len(p.Coeffs))
	for i := range p.Coeffs {
		r.Coeffs[i].Add(p.Coeffs[i], q.Coeffs[i])
	}
	return r
}

// Sub subtracts q from p.
func (p IntPoly) Sub(q IntPoly) IntPoly {
	r := NewIntPoly(len(p.Coeffs))
	for i := range p.Coeffs {
		r.Coeffs[i].Sub(p.Coeffs[i], q.Coeffs[i])
	}
	return r
}

// Neg negates polynomial.
func (p IntPoly) Neg() IntPoly {
	r := NewIntPoly(len(p.Coeffs))
	for i := range p.Coeffs {
		r.Coeffs[i].Neg(p.Coeffs[i])
	}
	return r
}

// ScalarMul multiplies by scalar s.
func (p IntPoly) ScalarMul(s *big.Int) IntPoly {
	r := NewIntPoly(len(p.Coeffs))
	for i := range p.Coeffs {
		r.Coeffs[i].Mul(p.Coeffs[i], s)
	}
	return r
}

// Add adds two ModQPolys modulo Q.
func (p ModQPoly) Add(q ModQPoly) ModQPoly {
	r := NewModQPoly(len(p.Coeffs), p.Q)
	for i := range p.Coeffs {
		r.Coeffs[i].Add(p.Coeffs[i], q.Coeffs[i])
		r.Coeffs[i].Mod(r.Coeffs[i], p.Q)
	}
	return r
}

// Sub subtracts modulo Q.
func (p ModQPoly) Sub(q ModQPoly) ModQPoly {
	r := NewModQPoly(len(p.Coeffs), p.Q)
	for i := range p.Coeffs {
		r.Coeffs[i].Sub(p.Coeffs[i], q.Coeffs[i])
		r.Coeffs[i].Mod(r.Coeffs[i], p.Q)
	}
	return r
}

// Neg negates modulo Q.
func (p ModQPoly) Neg() ModQPoly {
	r := NewModQPoly(len(p.Coeffs), p.Q)
	for i := range p.Coeffs {
		r.Coeffs[i].Neg(p.Coeffs[i])
		r.Coeffs[i].Mod(r.Coeffs[i], p.Q)
	}
	return r
}

// ScalarMul multiplies by scalar s modulo Q.
func (p ModQPoly) ScalarMul(s *big.Int) ModQPoly {
	r := NewModQPoly(len(p.Coeffs), p.Q)
	for i := range p.Coeffs {
		r.Coeffs[i].Mul(p.Coeffs[i], s)
		r.Coeffs[i].Mod(r.Coeffs[i], p.Q)
	}
	return r
}

// ReduceModQ reduces an IntPoly modulo Q.
func (p IntPoly) ReduceModQ(Q *big.Int) ModQPoly {
	r := NewModQPoly(len(p.Coeffs), Q)
	for i := range p.Coeffs {
		r.Coeffs[i].Mod(p.Coeffs[i], Q)
	}
	return r
}

// Lift converts a ModQPoly to IntPoly.
func (p ModQPoly) Lift() IntPoly {
	r := NewIntPoly(len(p.Coeffs))
	for i := range p.Coeffs {
		r.Coeffs[i].Set(p.Coeffs[i])
	}
	return r
}

// ToRNS converts a ModQPoly to RNS limb polynomials.
func ToRNS(p ModQPoly, params Params) []*ring.Poly {
    rings, _ := params.BuildRings()
    limbs := make([]*ring.Poly, len(rings))
    for i, r := range rings {
        pl := r.NewPoly()
        var mod *big.Int
        if len(params.Qi) > 0 {
            mod = new(big.Int).SetUint64(params.Qi[i])
        } else {
            // fallback: use ring modulus if no RNS factorization provided
            mod = new(big.Int).SetUint64(r.Modulus[0])
        }
        for j, c := range p.Coeffs {
            pl.Coeffs[0][j] = new(big.Int).Mod(c, mod).Uint64()
        }
        limbs[i] = pl
    }
	return limbs
}

// FromRNS reconstructs a ModQPoly from limb polynomials via CRT.
func FromRNS(limbs []*ring.Poly, params Params) ModQPoly {
	bigPoly := PackCRT(limbs, params)
	coeffs := make([]*big.Int, params.N)
	for i, c := range bigPoly.Coeffs {
		coeffs[i] = new(big.Int).Mod(c, params.Q)
	}
	return ModQPoly{Coeffs: coeffs, Q: new(big.Int).Set(params.Q)}
}
