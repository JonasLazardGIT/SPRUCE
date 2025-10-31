package tests

import (
	"math"
	"testing"

	ntru "vSIS-Signature/ntru"
)

func TestKeygenWindowAndSigmas(t *testing.T) {
	par := quickParamsNQ()
	f, g, F, G := genTrapdoorKey(t, par, 1.2)
	sampler, err := ntru.NewSampler(f, g, F, G, par, 256)
	if err != nil {
		t.Fatalf("NewSampler: %v", err)
	}
	sampler.Opts.Alpha = 1.2
	sampler.Opts.RSquare = ntru.CReferenceRSquare()
	sampler.Opts.UseCNormalDist = true
	if err := sampler.BuildGram(); err != nil {
		t.Fatalf("BuildGram: %v", err)
	}
	norm1, norm2, err := sampler.NormsGSO()
	if err != nil {
		t.Fatalf("NormsGSO: %v", err)
	}
	sigma1, sigma2, err := sampler.ComputeSigmasC()
	if err != nil {
		t.Fatalf("ComputeSigmasC: %v", err)
	}
	epar := ntru.EmbedParams{Prec: 256}
	slotSums, _, _, err := ntru.SlotSumsSquared(f, g, par, epar)
	if err != nil {
		t.Fatalf("SlotSumsSquared: %v", err)
	}
	sigmaSq := sampler.Opts.RSquare * sampler.Opts.Alpha * sampler.Opts.Alpha * float64(par.Q.Uint64())
	for i := 0; i < par.N/2; i++ {
		if math.Abs(norm1[i]-slotSums[i]) > 1e-6 {
			t.Fatalf("norm1 mismatch at slot %d: got %f want %f", i, norm1[i], slotSums[i])
		}
		expect1 := sigmaSq/norm1[i] - sampler.Opts.RSquare
		if expect1 < 0 {
			expect1 = 0
		}
		expect1 = math.Sqrt(expect1)
		if math.Abs(expect1-sigma1[i]) > 1e-6 {
			t.Fatalf("sigma1 mismatch at slot %d: got %f want %f", i, sigma1[i], expect1)
		}
		expect2 := sigmaSq/norm2[i] - sampler.Opts.RSquare
		if expect2 < 0 {
			expect2 = 0
		}
		expect2 = math.Sqrt(expect2)
		if math.Abs(expect2-sigma2[i]) > 1e-6 {
			t.Fatalf("sigma2 mismatch at slot %d: got %f want %f", i, sigma2[i], expect2)
		}
	}
}
