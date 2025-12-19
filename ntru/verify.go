package ntru

import (
	"errors"
	"math/big"
)

// MulNegacyclicZZParam multiplies integer polys a,b in the ring defined by
// x^N + 1 with optional LOG3 adjustment (matching C ipoly_mul_naive when
// ANTRAG_LOG3_D is enabled): for i from 2N-2 down to N, do h[i-N] -= h[i];
// if log3, also h[i-N/2] += h[i]. Returns int64 coefficients or error on overflow.
func MulNegacyclicZZParam(a, b []int64, log3 bool) ([]int64, error) {
	N := len(a)
	deg := 2*N - 1
	acc := make([]*big.Int, deg)
	for i := 0; i < deg; i++ {
		acc[i] = new(big.Int)
	}
	for i, ai64 := range a {
		if ai64 == 0 {
			continue
		}
		ai := big.NewInt(ai64)
		for j, bj64 := range b {
			if bj64 == 0 {
				continue
			}
			bj := big.NewInt(bj64)
			prod := new(big.Int).Mul(ai, bj)
			acc[i+j].Add(acc[i+j], prod)
		}
	}
	for i := deg - 1; i >= N; i-- {
		acc[i-N].Sub(acc[i-N], acc[i])
		if log3 {
			acc[i-N/2].Add(acc[i-N/2], acc[i])
		}
	}
	res := make([]int64, N)
	for i := 0; i < N; i++ {
		if !acc[i].IsInt64() {
			return nil, errors.New("int64 overflow")
		}
		res[i] = acc[i].Int64()
	}
	return res, nil
}

// MulNegacyclicZZ multiplies in the standard negacyclic ring x^N+1 (no LOG3 wrap).
func MulNegacyclicZZ(a, b []int64) ([]int64, error) {
	return MulNegacyclicZZParam(a, b, false)
}

// CheckNTRUIdentity verifies fG - gF == q in Z[x]/(x^N+1).
// f,g,F,G are centered int64 slices; par.Q must fit in int64.
func CheckNTRUIdentity(f, g, F, G []int64, par Params) bool {
	if len(f) != par.N || len(g) != par.N || len(F) != par.N || len(G) != par.N {
		return false
	}
	q := par.Q.Int64()
	fG, err := MulNegacyclicZZParam(f, G, par.LOG3_D)
	if err != nil {
		return false
	}
	gF, err := MulNegacyclicZZParam(g, F, par.LOG3_D)
	if err != nil {
		return false
	}
	for i := 0; i < par.N; i++ {
		want := int64(0)
		if i == 0 {
			want = q
		}
		if fG[i]-gF[i] != want {
			return false
		}
	}
	return true
}

// CheckPublicKey verifies h = g * f^{-1} (mod q) by testing h*f ≡ g (mod q).
func CheckPublicKey(f, g, h ModQPoly, par Params) bool {
	hf, err := ConvolveRNS(h, f, par)
	if err != nil {
		return false
	}
	for i := 0; i < par.N; i++ {
		gi := new(big.Int).Mod(new(big.Int).Set(g.Coeffs[i]), par.Q)
		hi := new(big.Int).Mod(hf.Coeffs[i], par.Q)
		if gi.Cmp(hi) != 0 {
			return false
		}
	}
	return true
}
