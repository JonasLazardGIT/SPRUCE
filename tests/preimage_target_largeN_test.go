//go:build large
// +build large

package tests

import (
	"math/big"
	"os"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Gated large-N preimage sampler sanity.
func TestPreimage_TargetSampler_LargeN(t *testing.T) {
	if os.Getenv("NTRU_RAND") != "1" {
		t.Skip("set NTRU_RAND=1 to enable large-N preimage sampler test")
	}
	N := 128
	q1 := uint64(12289)
	q2 := uint64(40961)
	Qbig := new(big.Int).Mul(big.NewInt(int64(q1)), big.NewInt(int64(q2)))
	par, _ := ntru.NewParams(N, Qbig)
	par, _ = par.WithRNSFactorization([]uint64{q1, q2})

	// Generate small trapdoor for this (N,Q)
	f, g, F, G := genTrapdoorKey(t, par, 1.5)
	S, err := ntru.NewSampler(f, g, F, G, par, 128)
	if err != nil {
		t.Fatalf("NewSampler: %v", err)
	}
	S.Opts.Alpha = 1.5
	S.Opts.RSquare = ntru.CReferenceRSquare()
	S.Opts.Slack = 6.0
	S.Opts.MaxSignTrials = 2000
	if err := S.BuildGram(); err != nil {
		t.Fatalf("BuildGram: %v", err)
	}

	rng := ntru.NewRNG(17)
	tpoly := randSmallModQPoly(rng, par.N, par.Q)
	s0, s1, trials, err := S.SamplePreimageTargetOptionB(tpoly, S.Opts.MaxSignTrials)
	if err != nil {
		t.Fatalf("HybridB (N=128): %v", err)
	}
	if trials <= 0 {
		t.Fatalf("expected positive trials used")
	}
	// verify congruence
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
