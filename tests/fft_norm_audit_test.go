package tests

import (
	"math"
	"math/big"
	"math/rand"
	"testing"
	ps "vSIS-Signature/Preimage_Sampler"
	ntru "vSIS-Signature/ntru"
)

// Checks that the negacyclic Eval embedding has a consistent energy scaling factor
// across random inputs: sum_k |Eval[k]|^2 = C * sum_j coeff[j]^2 for a constant C.
func TestFFTAudit_EnergyScalingConsistency(t *testing.T) {
	N := 32
	_, _ = ntru.NewParams(N, bigU(12289))
	prec := uint(128)
	rng := rand.New(rand.NewSource(123))
	trials := 16
	var ratios []float64
	for tr := 0; tr < trials; tr++ {
		coeffs := make([]float64, N)
		for i := 0; i < N; i++ {
			coeffs[i] = rng.NormFloat64()
		}
		// To Eval via negacyclic embedding
		cf := ps.NewFieldElemBig(N, prec)
		for i := 0; i < N; i++ {
			cf.Coeffs[i].Real.SetFloat64(coeffs[i])
		}
		ev := ps.FloatToEvalNegacyclic(cf, prec)
		// Compute energies
		var eCoeff, eEval float64
		for i := 0; i < N; i++ {
			eCoeff += coeffs[i] * coeffs[i]
		}
		for i := 0; i < N; i++ {
			r, _ := ev.Coeffs[i].Real.Float64()
			im, _ := ev.Coeffs[i].Imag.Float64()
			eEval += r*r + im*im
		}
		if eCoeff == 0 {
			t.Fatalf("zero coeff energy")
		}
		ratios = append(ratios, eEval/eCoeff)
	}
	// Check ratios are consistent within a small relative tolerance
	mean := 0.0
	for _, r := range ratios {
		mean += r
	}
	mean /= float64(len(ratios))
	var dev float64
	for _, r := range ratios {
		d := r - mean
		dev += d * d
	}
	dev = math.Sqrt(dev / float64(len(ratios)))
	if dev > 1e-8*math.Max(1, math.Abs(mean)) {
		t.Fatalf("energy scaling factor not consistent: mean=%.6e stdev=%.6e", mean, dev)
	}
}

func bigU(u uint64) *big.Int { return new(big.Int).SetUint64(u) }
