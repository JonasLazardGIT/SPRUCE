package tests

import (
	"math/big"
	"testing"

	"vSIS-Signature/ntru"
)

func TestNTTRoundTrip(t *testing.T) {
	Qbig := new(big.Int).Mul(big.NewInt(12289), big.NewInt(40961))
	p, _ := ntru.NewParams(16, Qbig)
	p, _ = p.WithRNSFactorization([]uint64{12289, 40961})
	rings, _ := p.BuildRings()
	rng := ntru.NewRNG(1)
	for i, r := range rings {
		poly := r.NewPoly()
		for j := 0; j < p.N; j++ {
			poly.Coeffs[0][j] = uint64(rng.Intn(int(p.Qi[i])))
		}
		want := poly.CopyNew()
		ntru.ToNTT(r, poly)
		ntru.FromNTT(r, poly)
		for j := 0; j < p.N; j++ {
			if poly.Coeffs[0][j] != want.Coeffs[0][j] {
				t.Fatalf("roundtrip mismatch")
			}
		}
	}
}
