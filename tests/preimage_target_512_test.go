package tests

import (
	"math/big"
	"os"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Baseline N=512, Q=1038337 preimage sampler sanity (gated by NTRU_RAND).
func TestPreimage_TargetSampler_N512(t *testing.T) {
	if os.Getenv("NTRU_RAND") != "1" {
		t.Skip("set NTRU_RAND=1 to enable N=512 preimage sampler test")
	}
	par, opts, err := ntru.PresetPower2_512_Q1038337()
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	f, g, F, G := genTrapdoorKey(t, par, opts.Alpha)
	// Lower precision for test runtime; 64 bits is sufficient here
	S, err := ntru.NewSampler(f, g, F, G, par, 64)
	if err != nil {
		t.Fatalf("NewSampler: %v", err)
	}
	// Use preset and allow extra slack for preimage acceptance
	S.Opts = opts
	S.Opts.Slack = 12.0
	S.Opts.MaxSignTrials = 1024
	if err := S.BuildGram(); err != nil {
		t.Fatalf("BuildGram: %v", err)
	}

	rng := ntru.NewRNG(42)
	tpoly := randSmallModQPoly(rng, par.N, par.Q)
	s0, s1, trials, err := S.SamplePreimageTargetOptionB(tpoly, S.Opts.MaxSignTrials)
	if err != nil {
		t.Fatalf("HybridB (N=512): %v", err)
	}
	if trials <= 0 {
		t.Fatalf("expected positive trials used")
	}
	// verify congruence: s0 + h*s1 == t (mod Q)
	h, err := ntru.PublicKeyH(ntru.Int64ToModQPoly(f, par), ntru.Int64ToModQPoly(g, par), par)
	if err != nil {
		t.Fatalf("PublicKeyH: %v", err)
	}
	s0Q := ntru.Int64ToModQPoly(intsOf(*s0), par)
	s1Q := ntru.Int64ToModQPoly(intsOf(*s1), par)
	hS1, err := ntru.ConvolveRNS(s1Q, h, par)
	if err != nil {
		t.Fatalf("ConvolveRNS: %v", err)
	}
	lhs := hS1.Add(s0Q)
	for i := 0; i < par.N; i++ {
		got := new(big.Int).Mod(lhs.Coeffs[i], par.Q)
		want := new(big.Int).Mod(tpoly.Coeffs[i], par.Q)
		if got.Cmp(want) != 0 {
			t.Fatalf("congruence failed at %d", i)
		}
	}
}

func intsOf(p ntru.IntPoly) []int64 {
	out := make([]int64, len(p.Coeffs))
	for i := range out {
		out[i] = p.Coeffs[i].Int64()
	}
	return out
}
