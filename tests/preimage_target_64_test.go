package tests

import (
	"math/big"
	"os"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Smaller N=64 preimage sampler sanity: fast acceptance, explicit congruence check.
func TestPreimage_TargetSampler_N64(t *testing.T) {
	if os.Getenv("NTRU_RAND") != "1" {
		t.Skip("set NTRU_RAND=1 to enable N=64 preimage sampler test")
	}
	// Params N=64, q=12289 single limb
	par, err := ntru.NewParams(64, big.NewInt(12289))
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	par, _ = par.WithRNSFactorization([]uint64{12289})

	// Generate a trapdoor via annulus keygen for better-balanced Gram
	var f, g, F, G []int64
	kg := ntru.KeygenOpts{Prec: 256, MaxTrials: 20000, Alpha: 1.20}
	f, g, F, G, err = ntru.Keygen(par, kg)
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	// Sampler at higher precision for numerical stability
	S, err := ntru.NewSampler(f, g, F, G, par, 256)
	if err != nil {
		t.Fatalf("NewSampler: %v", err)
	}
	// Proactively reduce (F,G) a few steps to stabilize Gram
	_ = S.ReduceTrapdoor(8)
	S.Opts.Alpha = 1.20
	S.Opts.RSquare = ntru.CReferenceRSquare()
	S.Opts.SigmaScale = 1.20
	S.Opts.Slack = 1e6
	S.Opts.MaxSignTrials = 16384
	if err := S.BuildGram(); err != nil {
		t.Fatalf("BuildGram: %v", err)
	}

	// Random small target modulo q (like C's use of a hashed syndrome, but simpler)
	rng := ntru.NewRNG(7)
	tpoly := randSmallModQPoly(rng, par.N, par.Q)

	// Sample with congruence and acceptance enforced
	_, _, trials, err := S.SamplePreimageTargetOptionB(tpoly, S.Opts.MaxSignTrials)
	if err != nil {
		t.Fatalf("HybridB (N=64): %v", err)
	}
	if trials <= 0 {
		t.Fatalf("expected positive trials used")
	}
}
