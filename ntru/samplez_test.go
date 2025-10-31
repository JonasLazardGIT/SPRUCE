package ntru

import (
	"math"
	"math/rand"
	"testing"

	ps "vSIS-Signature/Preimage_Sampler"
)

func TestSampleZVecStatistics(t *testing.T) {
	const prec = 256
	const trials = 2000
	sigma := CReferenceSmoothing()
	targetVar := sigma * sigma

	coeff := ps.NewFieldElemBig(1, prec)
	coeff.Domain = ps.Coeff

	coeff.Coeffs[0].Real.SetFloat64(0)
	coeff.Coeffs[0].Imag.SetFloat64(0)
	mean := 0.0
	m2 := 0.0
	count := 0
	for seed := int64(0); seed < 8; seed++ {
		rand.Seed(0x12345678 + seed)
		for i := 0; i < trials; i++ {
			coeff.Coeffs[0].Real.SetFloat64(0)
			coeff.Coeffs[0].Imag.SetFloat64(0)
			samples, err := sampleZVec(coeff, sigma)
			if err != nil {
				t.Fatalf("sampleZVec zero mean trial %d seed %d: %v", i, seed, err)
			}
			x := float64(samples[0])
			count++
			delta := x - mean
			mean += delta / float64(count)
			m2 += delta * (x - mean)
		}
	}
	variance := m2 / float64(count-1)
	if math.Abs(mean) > 0.15 {
		t.Fatalf("zero-mean sampler drift: mean=%f", mean)
	}
	if variance < 0.7*targetVar || variance > 1.3*targetVar {
		t.Fatalf("zero-mean variance out of range: got %f want ~%f", variance, targetVar)
	}

	// Non-half-integer mean
	coeff.Coeffs[0].Real.SetFloat64(0.37)
	coeff.Coeffs[0].Imag.SetFloat64(0)
	mean = 0.0
	m2 = 0.0
	count = 0
	for seed := int64(0); seed < 8; seed++ {
		rand.Seed(0x98765432 + seed)
		for i := 0; i < trials; i++ {
			samples, err := sampleZVec(coeff, sigma)
			if err != nil {
				t.Fatalf("sampleZVec non-zero mean trial %d seed %d: %v", i, seed, err)
			}
			x := float64(samples[0])
			count++
			delta := x - mean
			mean += delta / float64(count)
			m2 += delta * (x - mean)
		}
	}
	variance = m2 / float64(count-1)
	if math.Abs(mean-0.37) > 0.15 {
		t.Fatalf("non-zero mean mismatch: got %f want ~0.37", mean)
	}
	if variance < 0.7*targetVar || variance > 1.3*targetVar {
		t.Fatalf("non-zero variance out of range: got %f want ~%f", variance, targetVar)
	}
}
