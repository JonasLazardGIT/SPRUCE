package tests

import (
    "math"
    "math/big"
    "testing"
    ntru "vSIS-Signature/ntru"
)

// Verifies the Eval-domain radial sampler produces per-slot constant energy rad^2,
// matching the C keygen_fg construction prior to decode and windowing.
func TestKeygen_RadialSampler_EnergyConstant(t *testing.T) {
    par, err := ntru.NewParams(64, big.NewInt(12289))
    if err != nil { t.Fatalf("NewParams: %v", err) }

    alphas := []float64{1.10, 1.20, 1.30}
    for _, alpha := range alphas {
        fEval, gEval, err := ntru.KeygenRadialFG(par, alpha)
        if err != nil { t.Fatalf("KeygenRadialFG: %v", err) }
        if len(fEval.V) != par.N || len(gEval.V) != par.N {
            t.Fatalf("Eval length mismatch: got %d,%d want %d", len(fEval.V), len(gEval.V), par.N)
        }
        q := float64(par.Q.Uint64())
        rad := math.Sqrt(q) * 0.5 * (alpha + 1.0/alpha)
        want := rad * rad
        half := par.N / 2
        // Check first N/2 slots; these carry the complex slots
        for i := 0; i < half; i++ {
            fr, fi := real(fEval.V[i]), imag(fEval.V[i])
            gr, gi := real(gEval.V[i]), imag(gEval.V[i])
            got := fr*fr + fi*fi + gr*gr + gi*gi
            // relative tolerance; allow a tiny slack for float trig rounding
            if math.Abs(got-want) > 1e-9*math.Max(1.0, want) {
                t.Fatalf("alpha=%.2f slot %d: energy mismatch got %.12g want %.12g", alpha, i, got, want)
            }
        }
    }
}

