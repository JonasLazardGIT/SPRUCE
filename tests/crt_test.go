package tests

import (
	"math/big"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
	"vSIS-Signature/ntru"
)

func TestCRTRoundTrip(t *testing.T) {
	Qbig := new(big.Int).Mul(big.NewInt(12289), big.NewInt(40961))
	p, _ := ntru.NewParams(16, Qbig)
	p, _ = p.WithRNSFactorization([]uint64{12289, 40961})
	rng := ntru.NewRNG(2)
	limbs := make([]*ring.Poly, len(p.Qi))
	rings, _ := p.BuildRings()
	for i, r := range rings {
		poly := r.NewPoly()
		for j := 0; j < p.N; j++ {
			poly.Coeffs[0][j] = uint64(rng.Intn(int(p.Qi[i])))
		}
		limbs[i] = poly
	}
	bigPoly := ntru.PackCRT(limbs, p)
	limbs2 := ntru.UnpackCRT(bigPoly, p)
	for i := range limbs {
		for j := 0; j < p.N; j++ {
			if limbs[i].Coeffs[0][j] != limbs2[i].Coeffs[0][j] {
				t.Fatalf("crt roundtrip mismatch")
			}
		}
	}
}
