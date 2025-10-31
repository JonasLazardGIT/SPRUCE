package tests

import (
	"math"
	"math/cmplx"
	"testing"

	ntru "vSIS-Signature/ntru"
)

// Verifies per-slot Gram positivity and self-consistency.
func TestFFSampler_GramPositivity(t *testing.T) {
    par := quickParamsNQ()
    // Use a realistic small trapdoor
    f, g, F, G := genTrapdoorKey(t, par, 1.2)
    _ = ntru.SolveOpts{Prec: 128, Reduce: true, MaxIters: 3}
    if !ntru.CheckNTRUIdentity(f, g, F, G, par) {
        t.Fatalf("solver identity failed")
    }
	if !ntru.CheckNTRUIdentity(f, g, F, G, par) {
		t.Fatalf("solver identity failed")
	}
	S, err := ntru.NewSampler(f, g, F, G, par, 128)
	if err != nil {
		t.Fatalf("NewSampler error: %v", err)
	}
	if err := S.BuildGram(); err != nil {
		t.Fatalf("BuildGram error: %v", err)
	}

	epar := ntru.EmbedParams{Prec: 128}
	fev, _ := ntru.ToEval(f, par, epar)
	gev, _ := ntru.ToEval(g, par, epar)
	Fev, _ := ntru.ToEval(F, par, epar)
	Gev, _ := ntru.ToEval(G, par, epar)

	tol := 1e-8
	for i := 0; i < par.N; i++ {
		fi, gi := fev.V[i], gev.V[i]
		Fi, Gi := Fev.V[i], Gev.V[i]
		a := cmplx.Abs(Gi)*cmplx.Abs(Gi) + cmplx.Abs(Fi)*cmplx.Abs(Fi)
		d := cmplx.Abs(gi)*cmplx.Abs(gi) + cmplx.Abs(fi)*cmplx.Abs(fi)
		b := gi*cmplx.Conj(Gi) + fi*cmplx.Conj(Fi)
		if !(a > 0 && d > 0) {
			t.Fatalf("non-positive diag at slot %d", i)
		}
		lam2 := a - (real(b)*real(b)+imag(b)*imag(b))/d
		if lam2 <= -tol*math.Max(1, math.Abs(a)) {
			t.Fatalf("non-positive lambda2 at slot %d", i)
		}
		det := d * lam2
		if det <= -tol*math.Max(1, math.Abs(a*d)) {
			t.Fatalf("non-positive det at slot %d", i)
		}
	}
}
