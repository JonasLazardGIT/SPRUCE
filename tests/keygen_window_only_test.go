package tests

import (
	"math/big"
	"os"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Validates that the Keygen FFT path (radial sampling + decode_odd) produces (f,g)
// whose slot sums S_i satisfy the α-window. Solver is not exercised here.
func TestKeygenFFT_WindowOnly_N64(t *testing.T) {
	if os.Getenv("NTRU_RAND") != "1" {
		t.Skip("set NTRU_RAND=1 to run KeygenFFT window test")
	}
	par, err := ntru.NewParams(64, big.NewInt(12289))
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	alpha := 1.20
	f, g, err := ntru.KeygenWindowSample(par, alpha, 128, 20000)
	if err != nil {
		t.Fatalf("KeygenWindowSample: %v", err)
	}
	epar := ntru.EmbedParams{Prec: 128}
	S, _, _, err := ntru.SlotSumsSquared(f, g, par, epar)
	if err != nil {
		t.Fatalf("SlotSumsSquared: %v", err)
	}
	half := par.N / 2
	if !ntru.AlphaWindowOK(S[:half], par.Q.Uint64(), alpha) {
		t.Fatalf("AlphaWindowOK rejected generated f,g at alpha=%.2f", alpha)
	}
}
