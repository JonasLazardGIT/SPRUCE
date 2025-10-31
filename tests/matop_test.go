package tests

import (
	"math/big"
	"testing"

	ntru "vSIS-Signature/ntru"
)

func TestMatOpApplyPair(t *testing.T) {
	par := quickParamsNQ()
	rng := ntru.NewRNG(11)
	f := randSmallModQPoly(rng, par.N, par.Q)
	g := randSmallModQPoly(rng, par.N, par.Q)
	z0 := randSmallModQPoly(rng, par.N, par.Q)
	z1 := randSmallModQPoly(rng, par.N, par.Q)

	op, err := ntru.NewMatOpFG(f, g, par)
	if err != nil {
		t.Fatal(err)
	}
	y1, err := op.ApplyPair(z0, z1)
	if err != nil {
		t.Fatal(err)
	}

	gz, err := ntru.ConvolveRNS(g, z0, par)
	if err != nil {
		t.Fatal(err)
	}
	fz, err := ntru.ConvolveRNS(f, z1, par)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < par.N; i++ {
		tmp := new(big.Int).Sub(gz.Coeffs[i], fz.Coeffs[i])
		tmp.Mod(tmp, par.Q)
		a := new(big.Int).Mod(y1.Coeffs[i], par.Q)
		if tmp.Cmp(a) != 0 {
			t.Fatalf("mismatch at %d", i)
		}
	}
}
