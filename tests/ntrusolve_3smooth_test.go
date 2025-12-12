package tests

import (
	"math/big"
	"math/rand"
	"os"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Attempts identity checks for small 3-smooth Ns; gated due to randomized search.
func TestNTRUSolve_3Smooth_Small(t *testing.T) {
	if os.Getenv("NTRU_3SMOOTH") != "1" {
		t.Skip("set NTRU_3SMOOTH=1 to enable 3-smooth small-N tests")
	}
	cases := []struct{ N, M int }{
		{6, 6}, {12, 12},
	}
	for _, cs := range cases {
		par, err := ntru.NewParams(cs.N, big.NewInt(12289))
		if err != nil {
			t.Fatalf("NewParams(%d): %v", cs.N, err)
		}
		par.M = cs.M
		par.LOG3_D = (cs.N%3 == 0)
		// Try randomized small vectors until a solution is found or max tries hit
		const maxTries = 200
		var f, g, F, G []int64
		var ok bool
		for try := 0; try < maxTries; try++ {
			f = make([]int64, cs.N)
			g = make([]int64, cs.N)
			for i := 0; i < cs.N; i++ {
				f[i] = int64(rand.Intn(5) - 2)
				g[i] = int64(rand.Intn(5) - 2)
			}
			var err2 error
			F, G, err2 = ntru.NTRUSolve(f, g, par, ntru.SolveOpts{Prec: 128, Reduce: false})
			if err2 == nil && ntru.CheckNTRUIdentity(f, g, F, G, par) {
				ok = true
				break
			}
		}
		if !ok {
			t.Fatalf("NTRUSolve failed to produce identity at N=%d within tries", cs.N)
		}
	}
}
