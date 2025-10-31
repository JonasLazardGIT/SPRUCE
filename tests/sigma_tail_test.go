package tests

import (
	"math/big"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Verify that ComputeSigmasC() produces zeros in the tail (i >= N/2) and non-negative values in the head.
func TestComputeSigmasC_TailZeros(t *testing.T) {
	par, _ := ntru.NewParams(16, big.NewInt(12289))
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
	S, err := ntru.NewSampler(f, g, F, G, par, 128)
	if err != nil {
		t.Fatalf("NewSampler: %v", err)
	}
	S.Opts.Alpha = 1.23
	S.Opts.RSquare = ntru.CReferenceRSquare()
	if err := S.BuildGram(); err != nil {
		t.Fatalf("BuildGram: %v", err)
	}
	s1, s2, err := S.ComputeSigmasC()
	if err != nil {
		t.Fatalf("ComputeSigmasC: %v", err)
	}
	for i := 0; i < par.N/2; i++ {
		if s1[i] < 0 || s2[i] < 0 {
			t.Fatalf("negative sigma at head index %d", i)
		}
	}
	for i := par.N / 2; i < par.N; i++ {
		if s1[i] != 0 || s2[i] != 0 {
			t.Fatalf("expected tail sigmas zero at %d", i)
		}
	}
}
