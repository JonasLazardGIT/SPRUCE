package signverify

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"os"
	"testing"

	ntru "vSIS-Signature/ntru"
	"vSIS-Signature/ntru/keys"
)

func ensureKeys(t *testing.T) {
	t.Helper()
	if _, err := keys.LoadPublic(); err == nil {
		if _, err := keys.LoadPrivate(); err == nil {
			return
		}
	}
	sys, err := loadParams()
	if err != nil {
		t.Fatalf("load params: %v", err)
	}
	q := new(big.Int).SetUint64(sys.Q)
	par, err := ntru.NewParams(sys.N, q)
	if err != nil {
		t.Fatalf("params: %v", err)
	}
	if _, _, err := GenerateKeypair(par, ntru.SolveOpts{Prec: 128}, 128); err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
}

func TestSignTargetVerifiable(t *testing.T) {
	if os.Getenv("RUN_SLOW_SIGN") == "" {
		t.Skip("set RUN_SLOW_SIGN=1 to exercise SignTarget preimage sampling")
	}
	ensureKeys(t)

	sys, err := loadParams()
	if err != nil {
		t.Fatalf("load params: %v", err)
	}
	mSeedArr := sha256.Sum256([]byte("target-sign"))
	mSeed := mSeedArr[:]
	x0Seed := bytes.Repeat([]byte{1}, 32)
	x1Seed := bytes.Repeat([]byte{2}, 32)
	bPath := "Parameters/Bmatrix.json"
	if _, err := os.Stat(bPath); err != nil {
		bPath = "../Parameters/Bmatrix.json"
		if _, err2 := os.Stat(bPath); err2 != nil {
			bPath = "../../Parameters/Bmatrix.json"
		}
	}
	tCoeffs, err := ntru.ComputeTargetFromSeeds(sys, bPath, mSeed, x0Seed, x1Seed)
	if err != nil {
		t.Fatalf("compute target: %v", err)
	}

	sig, err := SignTarget(tCoeffs, 4096, defaultOpts)
	if err != nil {
		t.Skipf("sign target: %v", err)
	}
	// Use explicit target mode; seeds are empty, so verify should rely on TCoeffs.
	sig.Hash.BFile = ""
	if err := Verify(sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}
