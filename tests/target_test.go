package tests

import (
	"testing"

	ntru "vSIS-Signature/ntru"
)

func TestTargetCenterEmbedRoundTrip(t *testing.T) {
	par := quickParamsNQ()
	rng := ntru.NewRNG(9)
	tpoly := randSmallModQPoly(rng, par.N, par.Q)
	epar := ntru.EmbedParams{Prec: 128}
	ev, err := ntru.TargetToEval(tpoly, par, epar)
	if err != nil {
		t.Fatal(err)
	}
	coeffs, err := ntru.EvalToTargetInt(ev, par, epar)
	if err != nil {
		t.Fatal(err)
	}
	centered, err := ntru.CenterModQToInt64(tpoly, par)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < par.N; i++ {
		if coeffs[i] != centered[i] {
			t.Fatalf("roundtrip mismatch at %d: got %d want %d", i, coeffs[i], centered[i])
		}
	}
}
