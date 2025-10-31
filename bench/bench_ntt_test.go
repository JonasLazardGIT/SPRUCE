package bench

import (
	"math/big"
	"testing"

	"vSIS-Signature/ntru"
)

func BenchmarkNTTForwardInverse(b *testing.B) {
	Q := big.NewInt(12289)
	p, _ := ntru.NewParams(512, Q)
	rings, _ := p.BuildRings()
	r := rings[0]
	poly := r.NewPoly()
	for i := 0; i < p.N; i++ {
		poly.Coeffs[0][i] = uint64(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ntru.ToNTT(r, poly)
		ntru.FromNTT(r, poly)
	}
}
