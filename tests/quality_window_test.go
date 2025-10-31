package tests

import (
	"math"
	"testing"

	ntru "vSIS-Signature/ntru"
)

// Computes alpha window from slot sums and checks AlphaWindowOK.
func TestQualityWindow_AlphaOK(t *testing.T) {
	par := quickParamsNQ()
	epar := ntru.EmbedParams{Prec: 128}

	f := make([]int64, par.N)
	g := make([]int64, par.N)
	f[0] = 1
	g[1] = 1

	Svals, _, _, err := ntru.SlotSumsSquared(f, g, par, epar)
	if err != nil {
		t.Fatalf("SlotSumsSquared: %v", err)
	}
	qf := float64(par.Q.Uint64())
	alpha := 1.0
	for _, s := range Svals {
		if s <= 0 {
			t.Fatalf("non-positive slot sum")
		}
		val := math.Sqrt(math.Max(s/qf, qf/s))
		if val > alpha {
			alpha = val
		}
	}
	alpha *= (1 + 1e-9)
	if !ntru.AlphaWindowOK(Svals, par.Q.Uint64(), alpha) {
		t.Fatalf("AlphaWindowOK rejected alpha=%f", alpha)
	}
}
