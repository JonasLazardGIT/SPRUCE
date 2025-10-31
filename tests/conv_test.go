package tests

import (
	"math/big"
	"testing"

	"vSIS-Signature/ntru"
)

func TestConvolutionMatchesNaive(t *testing.T) {
	N := 16
	Qbig := new(big.Int).Mul(big.NewInt(12289), big.NewInt(40961))
	p, _ := ntru.NewParams(N, Qbig)
	p, _ = p.WithRNSFactorization([]uint64{12289, 40961})
	rng := ntru.NewRNG(3)
	for trial := 0; trial < 10; trial++ {
		a := ntru.NewModQPoly(N, Qbig)
		b := ntru.NewModQPoly(N, Qbig)
		for i := 0; i < N; i++ {
			a.Coeffs[i].Set(rng.RandBigInt(Qbig))
			b.Coeffs[i].Set(rng.RandBigInt(Qbig))
		}
		want := ntru.NaiveConvolutionModQ(a, b, N)
		got, err := ntru.ConvolveRNS(a, b, p)
		if err != nil {
			t.Fatalf("ConvolveRNS error: %v", err)
		}
		for i := 0; i < N; i++ {
			if want.Coeffs[i].Cmp(got.Coeffs[i]) != 0 {
				t.Fatalf("convolution mismatch")
			}
		}
	}
}
