package tests

import (
	"testing"

	ntru "vSIS-Signature/ntru"
)

func TestNTRUSolve(t *testing.T) {
	par := quickParamsNQ()
	// Use a realistic small trapdoor
	f, g, _, _ := genTrapdoorKey(t, par, 1.2)
	// Default now uses the C-style tower+Babai solver, no need to set UseCTower.
	opts := ntru.SolveOpts{Prec: 128, Reduce: true, MaxIters: 3}
	F, G, err := ntru.NTRUSolve(f, g, par, opts)
	if err != nil {
		t.Fatalf("NTRUSolve error: %v", err)
	}
	if !ntru.CheckNTRUIdentity(f, g, F, G, par) {
		t.Fatalf("identity check failed")
	}
	fq := ntru.Int64ToModQPoly(f, par)
	gq := ntru.Int64ToModQPoly(g, par)
	h, err := ntru.PublicKeyH(fq, gq, par)
	if err != nil {
		t.Fatalf("PublicKeyH error: %v", err)
	}
	if !ntru.CheckPublicKey(fq, gq, h, par) {
		t.Fatalf("public key check failed")
	}
}
