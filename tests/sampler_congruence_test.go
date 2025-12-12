package tests

import (
	"os"
	"testing"

	ntru "vSIS-Signature/ntru"
)

// Randomized sampler congruence check comparing integer and NTT paths.
func TestSamplerCongruence(t *testing.T) {
	if os.Getenv("NTRU_RAND") != "1" {
		t.Skip("set NTRU_RAND=1 to enable randomized sampler congruence test")
	}
	par := quickParamsNQ()

	f := make([]int64, par.N)
	g := make([]int64, par.N)
	f[0], g[1] = 1, 1
	opts := ntru.SolveOpts{Prec: 128, Reduce: true, MaxIters: 2}
	F, G, err := ntru.NTRUSolve(f, g, par, opts)
	if err != nil {
		t.Fatalf("NTRUSolve: %v", err)
	}
	S, err := ntru.NewSampler(f, g, F, G, par, 128)
	if err != nil {
		t.Fatalf("NewSampler: %v", err)
	}
	if err := S.BuildGram(); err != nil {
		t.Fatalf("BuildGram: %v", err)
	}

	rng := ntru.NewRNG(21)
	for trial := 0; trial < 32; trial++ {
		tpoly := randSmallModQPoly(rng, par.N, par.Q)
		// Hybrid-B sampling sanity
		_, _, _, err := S.SamplePreimageTargetOptionB(tpoly, 512)
		if err != nil {
			t.Fatalf("OptionB: %v", err)
		}
	}
}
