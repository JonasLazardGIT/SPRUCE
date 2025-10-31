package tests

import (
	"math/big"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Small, deterministic sanity for Hybrid‑B sampler on trivial trapdoor and t=0.
func TestPreimageTarget_Small_TrivialZero(t *testing.T) {
	// Tiny ring
	par, err := ntru.NewParams(16, big.NewInt(12289))
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	// Single-limb RNS to satisfy PublicKeyH/ConvolveRNS paths
	par, _ = par.WithRNSFactorization([]uint64{12289})

	// Trivial small trapdoor
	f := make([]int64, par.N)
	g := make([]int64, par.N)
	f[0] = 1
	if par.N > 1 {
		g[1] = 1
	} else {
		g[0] = 1
	}
	F, G, err := ntru.NTRUSolve(f, g, par, ntru.SolveOpts{Prec: 128, Reduce: true, MaxIters: 2})
	if err != nil {
		t.Fatalf("NTRUSolve: %v", err)
	}
	if !ntru.CheckNTRUIdentity(f, g, F, G, par) {
		t.Fatalf("identity check failed")
	}

	// Sampler with generous acceptance to avoid flakiness
	S, err := ntru.NewSampler(f, g, F, G, par, 128)
	if err != nil {
		t.Fatalf("NewSampler: %v", err)
	}
	S.Opts.Alpha = 1.20
	S.Opts.RSquare = ntru.CReferenceRSquare()
	S.Opts.Slack = 1e6
	S.Opts.MaxSignTrials = 4096
	if err := S.BuildGram(); err != nil {
		t.Fatalf("BuildGram: %v", err)
	}

	// Zero target
	tpoly := ntru.NewModQPoly(par.N, par.Q)
	// Hybrid-B sampler should accept quickly with generous Slack
	s0, s1, _, err := S.SamplePreimageTargetOptionB(tpoly, 1024)
	if err != nil {
		t.Fatalf("OptionB: %v", err)
	}
	if len(s0.Coeffs) != par.N || len(s1.Coeffs) != par.N {
		t.Fatalf("unexpected lengths")
	}
}
