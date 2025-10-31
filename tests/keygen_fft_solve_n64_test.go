package tests

import (
	"math/big"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Attempts a small N=64 run of KeygenFFT to confirm it can return a trapdoor
// within MaxTrials under a relaxed alpha (pending full normalization/Phase 4).
func TestKeygenFFT_Solve_N64(t *testing.T) {
	// if os.Getenv("NTRU_RAND") != "1" {
	//     t.Skip("set NTRU_RAND=1 to enable randomized KeygenFFT solve test")
	// }
	par, err := ntru.NewParams(64, big.NewInt(12289))
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	// Set solver parity knobs if needed; defaults are safe
	par.M = 4
	par.LOG3_D = false

	opts := ntru.KeygenOpts{Prec: 256, MaxTrials: 50000, Alpha: 1.20}
	f, g, F, G, err := ntru.KeygenFFT(par, opts)
	if err != nil {
		t.Fatalf("KeygenFFT: %v", err)
	}
	if !ntru.CheckNTRUIdentity(f, g, F, G, par) {
		t.Fatalf("identity check failed: fG - gF != q")
	}
}
