package Preimage_Sampler

import (
	"math/rand"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestNegacyclicRoundTrip(t *testing.T) {
	ringQ, err := ring.NewRing(1024, []uint64{1038337})
	if err != nil {
		t.Fatalf("NewRing failed: %v", err)
	}
	prng := rand.New(rand.NewSource(1))
	for it := 0; it < 50; it++ {
		p := ringQ.NewPoly()
		for i := range p.Coeffs[0] {
			p.Coeffs[0][i] = uint64(prng.Int63()) % ringQ.Modulus[0]
		}
		eval := NegacyclicEvaluatePoly(p, ringQ, 192)
		p2 := NegacyclicInterpolateElem(eval, ringQ)
		for i := range p.Coeffs[0] {
			if p.Coeffs[0][i] != p2.Coeffs[0][i] {
				t.Fatalf("round-trip mismatch at %d: got %d want %d", i, p2.Coeffs[0][i], p.Coeffs[0][i])
			}
		}
	}
}
