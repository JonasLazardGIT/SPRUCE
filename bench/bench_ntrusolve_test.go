package bench

import (
	"math/big"
	"testing"

	ntru "vSIS-Signature/ntru"
)

func benchmarkParams() ntru.Params {
	N := 16
	q1 := uint64(12289)
	q2 := uint64(40961)
	Qbig := new(big.Int).Mul(big.NewInt(int64(q1)), big.NewInt(int64(q2)))
	p, _ := ntru.NewParams(N, Qbig)
	p, _ = p.WithRNSFactorization([]uint64{q1, q2})
	return p
}

func BenchmarkInvertModQ(b *testing.B) {
	par := benchmarkParams()
	rng := ntru.NewRNG(3)
	var f ntru.ModQPoly
	for {
		f = randSmallPolyForBench(rng, par.N, par.Q)
		if _, ok := ntru.InvertModQ(f, par); ok {
			break
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := ntru.InvertModQ(f, par); !ok {
			b.Fatal("inverse failed")
		}
	}
}

func randSmallPolyForBench(rng *ntru.RNG, N int, Q *big.Int) ntru.ModQPoly {
	p := ntru.NewModQPoly(N, Q)
	for i := 0; i < N; i++ {
		v := int64(rng.Intn(7)) - 3
		if v < 0 {
			p.Coeffs[i].Add(p.Coeffs[i], Q)
		}
		p.Coeffs[i].Add(p.Coeffs[i], big.NewInt(v))
		p.Coeffs[i].Mod(p.Coeffs[i], Q)
	}
	return p
}

func BenchmarkNTRUSolve(b *testing.B) {
	par := benchmarkParams()
	f := make([]int64, par.N)
	g := make([]int64, par.N)
	f[0] = 1
	g[1] = 1
	opts := ntru.SolveOpts{Prec: 128, Reduce: true, MaxIters: 2}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := ntru.NTRUSolve(f, g, par, opts); err != nil {
			b.Fatal(err)
		}
	}
}
