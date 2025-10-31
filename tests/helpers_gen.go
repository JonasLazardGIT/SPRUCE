package tests

import (
	"testing"
	ntru "vSIS-Signature/ntru"
)

// genTrapdoorKey produces a trapdoor using the annulus key generator.
func genTrapdoorKey(t *testing.T, par ntru.Params, alpha float64) (f, g, F, G []int64) {
	t.Helper()
	if alpha <= 0 {
		alpha = 1.20
	}
	kg := ntru.KeygenOpts{Prec: 256, MaxTrials: 20000, Alpha: alpha}
	var err error
	for tries := 0; tries < 10; tries++ {
		f, g, F, G, err = ntru.Keygen(par, kg)
		if err != nil {
			continue
		}
		if ntru.IsUnitModQ(ntru.Int64ToModQPoly(f, par), par) {
			return
		}
	}
	t.Fatalf("Keygen: failed to generate invertible trapdoor: %v", err)
	return
}
