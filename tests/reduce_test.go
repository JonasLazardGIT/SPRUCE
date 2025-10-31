package tests

import (
	"testing"

	ntru "vSIS-Signature/ntru"
)

func TestReduceOnce(t *testing.T) {
	par := quickParamsNQ()
	prec := uint(128)
	// simple f,g
	f := make([]int64, par.N)
	g := make([]int64, par.N)
	f[0], f[1] = 1, 1
	g[0], g[1] = 1, -1
	// construct F,G with added k*f,k*g
	k := make([]int64, par.N)
	k[0] = 3
	Kf, _ := ntru.MulNegacyclicZZ(k, f)
	Kg, _ := ntru.MulNegacyclicZZ(k, g)
	F := make([]int64, par.N)
	G := make([]int64, par.N)
	for i := 0; i < par.N; i++ {
		F[i] = Kf[i]
		G[i] = Kg[i]
	}
	n0, _ := ntru.PairNorm2(F, G, par, prec)
	F2, G2, dec, err := ntru.ReduceOnce(F, G, f, g, par, prec)
	if err != nil {
		t.Fatalf("ReduceOnce error: %v", err)
	}
	n1, _ := ntru.PairNorm2(F2, G2, par, prec)
	if !(dec && n1 < n0 || (!dec && n1 == n0)) {
		t.Fatalf("unexpected norm behavior")
	}
}
