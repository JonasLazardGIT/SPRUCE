package tests

import (
	"math/big"
	"testing"

	ntru "vSIS-Signature/ntru"
)

func TestPublicKeyH(t *testing.T) {
	par := quickParamsNQ()
	rng := ntru.NewRNG(7)
	var f ntru.ModQPoly
	for {
		f = randSmallModQPoly(rng, par.N, par.Q)
		if _, ok := ntru.InvertModQ(f, par); ok {
			break
		}
	}
	g := randSmallModQPoly(rng, par.N, par.Q)
	h, err := ntru.PublicKeyH(f, g, par)
	if err != nil {
		t.Fatalf("PublicKeyH error: %v", err)
	}
	hf, err := ntru.ConvolveRNS(h, f, par)
	if err != nil {
		t.Fatalf("ConvolveRNS error: %v", err)
	}
	for i := 0; i < par.N; i++ {
		got := new(big.Int).Mod(hf.Coeffs[i], par.Q)
		want := new(big.Int).Mod(new(big.Int).Set(g.Coeffs[i]), par.Q)
		if got.Cmp(want) != 0 {
			t.Fatalf("mismatch at %d", i)
		}
	}
}
