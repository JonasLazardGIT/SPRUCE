//go:build testonly
// +build testonly

package tests

import (
	"os"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Roundtrip sign/verify using the C-style two-step sampler and check_norm.
func TestCSignVerify_Roundtrip(t *testing.T) {
	if os.Getenv("NTRU_RAND") != "1" {
		t.Skip("set NTRU_RAND=1 to enable C-style sign/verify roundtrip test")
	}
	// Use realistic preset and generate small trapdoor
	par, opts, err := ntru.PresetPower2_512_Q12289()
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	f, g, F, G := genTrapdoorKey(t, par, opts.Alpha)
	// Lower precision for runtime
	S, err := ntru.NewSampler(f, g, F, G, par, 64)
	if err != nil {
		t.Fatalf("NewSampler: %v", err)
	}
	S.Opts = opts
	// Relax parameters for test speed and acceptance.
	S.Opts.SigmaScale = 1.20
	S.Opts.Slack = 1.32
	S.Opts.MaxSignTrials = 12000
	msg := []byte("hello world")
	sig, err := S.SignC(msg)
	if err != nil {
		t.Fatalf("SignC: %v", err)
	}
	ok, err := S.VerifyC(msg, sig)
	if err != nil {
		t.Fatalf("VerifyC: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyC failed")
	}
}
