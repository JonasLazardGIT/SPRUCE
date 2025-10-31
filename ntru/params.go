package ntru

import (
	"errors"
	"math/big"
)

// Params defines the cyclotomic dimension N and modulus Q with optional RNS limbs.
type Params struct {
	N  int
	Q  *big.Int
	Qi []uint64
	// C-parity knobs
	M      int  // ANTRAG_M (e.g., 4 or 6)
	LOG3_D bool // parity flag for special conj2 at degree==2
}

// NewParams creates new parameters ensuring N is a power of two and Q > 0.
func NewParams(N int, Q *big.Int) (Params, error) {
	if N <= 0 || !isSmooth23(N) {
		return Params{}, errors.New("N must be 2/3-smooth (only factors 2 and/or 3)")
	}
	if Q == nil || Q.Sign() <= 0 {
		return Params{}, errors.New("Q must be positive")
	}
	p := Params{N: N, Q: new(big.Int).Set(Q)}
	// LOG3_D indicates presence of 3-adic factor in N (used by special conj2 at deg=2)
	if N%3 == 0 {
		p.LOG3_D = true
	}
	return p, nil
}

// NewBaselineParams returns the baseline parameters (N=512, Q=1038337).
func NewBaselineParams() (Params, error) {
	return NewParams(512, big.NewInt(1038337))
}

// WithRNSFactorization returns a copy of the parameters using the provided RNS limbs.
func (p Params) WithRNSFactorization(qi []uint64) (Params, error) {
	if len(qi) == 0 {
		return Params{}, errors.New("empty factorization")
	}
	cp := p
	cp.Qi = append([]uint64(nil), qi...)
	return cp, nil
}

// isSmooth23 returns true if n has no prime factors other than 2 or 3.
func isSmooth23(n int) bool {
	if n <= 0 {
		return false
	}
	for n%2 == 0 {
		n /= 2
	}
	for n%3 == 0 {
		n /= 3
	}
	return n == 1
}
