package credential

import (
	"os"
	"testing"

	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	ntrukeys "vSIS-Signature/ntru/keys"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

func TestCombineRandomness(t *testing.T) {
	rU := []int64{5, -5, 3}
	rI := []int64{3, 5, -9}
	out, err := CombineRandomness(rU, rI, 5)
	if err != nil {
		t.Fatalf("combine: %v", err)
	}
	want := []int64{-3, 0, 5}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("idx %d got %d want %d", i, out[i], want[i])
		}
	}
}

func TestHashMessageMatchesSeededTarget(t *testing.T) {
	ringQ, err := LoadDefaultRing()
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	sig, err := ntrukeys.Load()
	if err != nil {
		t.Skip("signature fixture missing; run signer to materialise ntru_keys/signature.json")
	}

	// B matrix in NTT domain.
	bPath := "Parameters/Bmatrix.json"
	if _, err := os.Stat(bPath); err != nil {
		bPath = "../Parameters/Bmatrix.json"
	}
	Bcoeffs, err := ntrurio.LoadBMatrixCoeffs(bPath)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	toNTT := func(raw []uint64) *ring.Poly {
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], raw)
		ringQ.NTT(p, p)
		return p
	}
	B := []*ring.Poly{
		toNTT(Bcoeffs[0]),
		toNTT(Bcoeffs[1]),
		toNTT(Bcoeffs[2]),
		toNTT(Bcoeffs[3]),
	}

	// Rebuild message/randomness from seeds.
	m := ringQ.NewPoly()
	r0 := ringQ.NewPoly()
	r1 := ringQ.NewPoly()
	mSeed, _ := ntrukeys.DecodeSeed(sig.Hash.MSeed)
	x0Seed, _ := ntrukeys.DecodeSeed(sig.Hash.X0Seed)
	x1Seed, _ := ntrukeys.DecodeSeed(sig.Hash.X1Seed)
	prngM, _ := utils.NewKeyedPRNG(mSeed)
	prngX0, _ := utils.NewKeyedPRNG(x0Seed)
	prngX1, _ := utils.NewKeyedPRNG(x1Seed)
	if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngM, m, ntru.CurrentSeedPolyBounds()); err != nil {
		t.Fatalf("m from seed: %v", err)
	}
	if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngX0, r0, ntru.CurrentSeedPolyBounds()); err != nil {
		t.Fatalf("x0 from seed: %v", err)
	}
	if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngX1, r1, ntru.CurrentSeedPolyBounds()); err != nil {
		t.Fatalf("x1 from seed: %v", err)
	}

	// Use zero m2 to stay aligned with seeded target.
	m2 := ringQ.NewPoly()
	tCoeffs, err := HashMessage(ringQ, B, m, m2, r0, r1)
	if err != nil {
		t.Fatalf("hash message: %v", err)
	}

	sys, err := ntrurio.LoadParams("Parameters/Parameters.json", true)
	if err != nil {
		if sysUp, errUp := ntrurio.LoadParams("../Parameters/Parameters.json", true); errUp == nil {
			sys = sysUp
		} else {
			t.Fatalf("load params: %v", err)
		}
	}
	ref, err := ntru.ComputeTargetFromSeeds(&sys, sig.Hash.BFile, mSeed, x0Seed, x1Seed)
	if err != nil {
		t.Fatalf("target from seeds: %v", err)
	}
	if len(ref) != len(tCoeffs) {
		t.Fatalf("size mismatch: ref=%d got=%d", len(ref), len(tCoeffs))
	}
	for i := range ref {
		if ref[i] != tCoeffs[i] {
			t.Fatalf("coeff %d mismatch: got %d want %d", i, tCoeffs[i], ref[i])
		}
	}
}
