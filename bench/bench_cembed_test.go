package bench

import (
	"math/big"
	"testing"

	"vSIS-Signature/ntru"
)

func BenchmarkToEval(b *testing.B) {
	N := 512
	Q := big.NewInt(17)
	p, _ := ntru.NewParams(N, Q)
	epar := ntru.EmbedParams{Prec: 128}
	coeffs := make([]int64, N)
	for i := 0; i < N; i++ {
		coeffs[i] = int64(i % 7)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ntru.ToEval(coeffs, p, epar)
	}
}

func BenchmarkToCoeffInt(b *testing.B) {
	N := 512
	Q := big.NewInt(17)
	p, _ := ntru.NewParams(N, Q)
	epar := ntru.EmbedParams{Prec: 128}
	coeffs := make([]int64, N)
	for i := 0; i < N; i++ {
		coeffs[i] = int64(i % 7)
	}
	ev, _ := ntru.ToEval(coeffs, p, epar)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ntru.ToCoeffInt(ev, p, epar)
	}
}
