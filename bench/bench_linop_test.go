package bench

import (
	"testing"

	ntru "vSIS-Signature/ntru"
)

func BenchmarkOpApply(b *testing.B) {
	par := benchmarkParams()
	rng := ntru.NewRNG(7)
	h := randSmallPolyForBench(rng, par.N, par.Q)
	s := randSmallPolyForBench(rng, par.N, par.Q)
	op, err := ntru.NewOpFromH(h, par)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := op.Apply(s); err != nil {
			b.Fatal(err)
		}
	}
}
