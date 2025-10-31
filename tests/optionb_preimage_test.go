package tests

import (
	"math/big"
	"os"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Test that OptionB hybrid sampler terminates and yields a valid preimage.
func TestOptionB_Preimage_N64_TerminatesAndMatchesCongruence(t *testing.T) {
	if os.Getenv("NTRU_RAND") != "1" {
		t.Skip("set NTRU_RAND=1 to enable OptionB preimage test")
	}
	par, err := ntru.NewParams(64, big.NewInt(12289))
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	par, _ = par.WithRNSFactorization([]uint64{12289})

	kg := ntru.KeygenOpts{Prec: 256, MaxTrials: 20000, Alpha: 1.20}
	f, g, F, G, err := ntru.Keygen(par, kg)
	if err != nil {
		t.Fatalf("Keygen: %v", err)
	}

	rng := ntru.NewRNG(9)
	tpoly := randSmallModQPoly(rng, par.N, par.Q)

	cases := []struct {
		name  string
		shape string
	}{{"cstyle", "cstyle"}, {"s0first", "s0first"}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			S, err := ntru.NewSampler(f, g, F, G, par, 256)
			if err != nil {
				t.Fatalf("NewSampler: %v", err)
			}
			S.Opts.Alpha = 1.20
			S.Opts.RSquare = ntru.CReferenceRSquare()
			S.Opts.SigmaScale = 1.20
			S.Opts.Slack = 1e6
			S.Opts.UseExactResidual = true
			S.Opts.BoundShape = tc.shape
			if err := S.BuildGram(); err != nil {
				t.Fatalf("BuildGram: %v", err)
			}

			s0, s1, trials, err := S.SamplePreimageTargetOptionB(tpoly, 1<<16)
			if err != nil {
				t.Fatalf("OptionB: %v", err)
			}
			if trials <= 0 {
				t.Fatalf("expected positive trials used")
			}

			h, herk := ntru.PublicKeyH(ntru.Int64ToModQPoly(f, par), ntru.Int64ToModQPoly(g, par), par)
			if herk != nil {
				t.Fatalf("PublicKeyH: %v", herk)
			}
			hS1, errc := ntru.ConvolveRNS(ntru.Int64ToModQPoly(coeffToInt64(s1), par), h, par)
			if errc != nil {
				t.Fatalf("ConvolveRNS: %v", errc)
			}
			lhs := hS1.Add(ntru.Int64ToModQPoly(coeffToInt64(s0), par))
			for i := 0; i < par.N; i++ {
				want := new(big.Int).Mod(new(big.Int).Set(tpoly.Coeffs[i]), par.Q)
				got := new(big.Int).Mod(lhs.Coeffs[i], par.Q)
				if want.Cmp(got) != 0 {
					t.Fatalf("congruence mismatch at %d", i)
				}
			}
		})
	}
}

func coeffToInt64(p *ntru.CoeffPoly) []int64 {
	out := make([]int64, len(p.Coeffs))
	for i := range p.Coeffs {
		out[i] = p.Coeffs[i].Int64()
	}
	return out
}
