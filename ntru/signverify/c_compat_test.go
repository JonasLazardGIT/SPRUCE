package signverify

import (
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	ntru "vSIS-Signature/ntru"
	"vSIS-Signature/ntru/keys"
)

func copyDir(t *testing.T, src, dst string) {
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("readdir %s: %v", src, err)
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dst, err)
	}
	for _, entry := range entries {
		sp := filepath.Join(src, entry.Name())
		dp := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			copyDir(t, sp, dp)
			continue
		}
		data, err := os.ReadFile(sp)
		if err != nil {
			t.Fatalf("read %s: %v", sp, err)
		}
		if err := os.WriteFile(dp, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", dp, err)
		}
	}
}

func prepareCTestWorkdir(t *testing.T) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	tmp := t.TempDir()
	root, err := filepath.Abs(filepath.Join(wd, "..", ".."))
	if err != nil {
		t.Fatalf("abs root: %v", err)
	}
	copyDir(t, filepath.Join(root, "Parameters"), filepath.Join(tmp, "Parameters"))
	copyDir(t, filepath.Join(root, "ntru_keys"), filepath.Join(tmp, "ntru_keys"))
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore wd: %v", err)
		}
	})
}

func TestCStyleSignVerifyRoundtrip(t *testing.T) {
	prepareCTestWorkdir(t)

	sys, err := LoadParamsForCLI()
	if err != nil {
		t.Fatalf("load params: %v", err)
	}
	sig, err := keys.Load()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			t.Skip("signature fixture not present; skipping C compatibility test")
		}
		t.Fatalf("load signature: %v", err)
	}

	if err := Verify(sig); err != nil {
		t.Fatalf("verify: %v", err)
	}

	mSeed, err := keys.DecodeSeed(sig.Hash.MSeed)
	if err != nil {
		t.Fatalf("decode mseed: %v", err)
	}
	x0Seed, err := keys.DecodeSeed(sig.Hash.X0Seed)
	if err != nil {
		t.Fatalf("decode x0: %v", err)
	}
	x1Seed, err := keys.DecodeSeed(sig.Hash.X1Seed)
	if err != nil {
		t.Fatalf("decode x1: %v", err)
	}
<<<<<<< ours
=======
	// If BFile is invalid (e.g., a directory), skip as a missing fixture.
	if info, statErr := os.Stat(sig.Hash.BFile); statErr == nil && info.IsDir() {
		t.Skipf("BFile %q is a directory; skipping hash bridge check", sig.Hash.BFile)
	}
>>>>>>> theirs
	tCoeffs, err := ntru.ComputeTargetFromSeeds(sys, sig.Hash.BFile, mSeed, x0Seed, x1Seed)
	if err != nil {
		t.Fatalf("hash bridge: %v", err)
	}
	if len(tCoeffs) != len(sig.Hash.TCoeffs) {
		t.Fatalf("target length mismatch: got %d want %d", len(sig.Hash.TCoeffs), len(tCoeffs))
	}
	for i := range tCoeffs {
		if tCoeffs[i] != sig.Hash.TCoeffs[i] {
			t.Fatalf("target coeff mismatch at %d", i)
		}
	}

	qSig := new(big.Int)
	if _, ok := qSig.SetString(sig.Params.Q, 16); !ok {
		t.Fatalf("parse Q from signature: %q", sig.Params.Q)
	}
	parSig, err := ntru.NewParams(sig.Params.N, qSig)
	if err != nil {
		t.Fatalf("params from signature: %v", err)
	}

	h := ntru.Int64ToModQPoly(sig.PublicKey.HCoeffs, parSig)
	s1 := ntru.Int64ToModQPoly(sig.Signature.S1, parSig)
	hs1, err := ntru.ConvolveRNS(s1, h, parSig)
	if err != nil {
		t.Fatalf("convolve hs1: %v", err)
	}
	c1 := ntru.Int64ToModQPoly(tCoeffs, parSig)
	s2 := hs1.Add(c1)
	for i := 0; i < parSig.N; i++ {
		s2.Coeffs[i].Mod(s2.Coeffs[i], parSig.Q)
	}
	s2c, err := ntru.CenterModQToInt64(s2, parSig)
	if err != nil {
		t.Fatalf("center s2: %v", err)
	}
	if len(sig.Signature.S2) != parSig.N {
		t.Fatalf("signature missing s2 coefficients (got %d)", len(sig.Signature.S2))
	}
	for i := 0; i < parSig.N; i++ {
		if sig.Signature.S2[i] != s2c[i] {
			t.Fatalf("s2 mismatch at coeff %d: got %d want %d", i, sig.Signature.S2[i], s2c[i])
		}
	}
	resOpts := defaultOpts
	resOpts.UseLog3Cross = parSig.LOG3_D
	if !ntru.CheckNormC(sig.Signature.S1, sig.Signature.S2, parSig, resOpts) {
		t.Fatalf("C-style residual predicate rejected signature")
	}

	s0 := ntru.Int64ToModQPoly(sig.Signature.S0, parSig)
	lhs := hs1.Add(s0)
	for i := 0; i < parSig.N; i++ {
		lhs.Coeffs[i].Mod(lhs.Coeffs[i], parSig.Q)
	}
	target := ntru.Int64ToModQPoly(tCoeffs, parSig)
	for i := 0; i < parSig.N; i++ {
		target.Coeffs[i].Mod(target.Coeffs[i], parSig.Q)
		if lhs.Coeffs[i].Cmp(target.Coeffs[i]) != 0 {
			t.Fatalf("congruence mismatch at coeff %d", i)
		}
	}
}
