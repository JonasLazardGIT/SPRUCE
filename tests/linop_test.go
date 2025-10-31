package tests

import (
	"math/big"
	"testing"

	ntru "vSIS-Signature/ntru"
)

func TestOpApplyMatchesConvolveRNS(t *testing.T) {
	par := quickParamsNQ()
	rng := ntru.NewRNG(42)
	h := randSmallModQPoly(rng, par.N, par.Q)
	s := randSmallModQPoly(rng, par.N, par.Q)
	op, err := ntru.NewOpFromH(h, par)
	if err != nil {
		t.Fatal(err)
	}
	y1, err := op.Apply(s)
	if err != nil {
		t.Fatal(err)
	}
	y2, err := ntru.ConvolveRNS(h, s, par)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < par.N; i++ {
		a := new(big.Int).Mod(y1.Coeffs[i], par.Q)
		b := new(big.Int).Mod(y2.Coeffs[i], par.Q)
		if a.Cmp(b) != 0 {
			t.Fatalf("mismatch at %d", i)
		}
	}
}
