package tests

import (
	"math/big"
	"math/rand"
	"testing"

	"vSIS-Signature/ntru"
)

func TestToEvalToCoeffIntRoundTrip(t *testing.T) {
	N := 8
	Q := big.NewInt(17)
	p, _ := ntru.NewParams(N, Q)
	epar := ntru.EmbedParams{Prec: 128, Real: true}
	rng := rand.New(rand.NewSource(0))
	// random tests
	for i := 0; i < 20; i++ {
		coeffs := make([]int64, N)
		for j := 0; j < N; j++ {
			coeffs[j] = int64(rng.Intn(33) - 16)
		}
		ev, err := ntru.ToEval(coeffs, p, epar)
		if err != nil {
			t.Fatal(err)
		}
		back, err := ntru.ToCoeffInt(ev, p, epar)
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < N; j++ {
			if back.Int[j] != coeffs[j] {
				t.Fatalf("roundtrip mismatch")
			}
		}
	}
	// patterns
	patterns := [][]int64{
		{1, 0, 0, 0, 0, 0, 0, 0},
		{1, -1, 1, -1, 1, -1, 1, -1},
		{1, 2, 3, 4, 4, 3, 2, 1},
	}
	for _, coeffs := range patterns {
		ev, _ := ntru.ToEval(coeffs, p, epar)
		back, _ := ntru.ToCoeffInt(ev, p, epar)
		for j := 0; j < N; j++ {
			if back.Int[j] != coeffs[j] {
				t.Fatalf("pattern roundtrip failed")
			}
		}
	}
}

func TestFloatRoundTripAndRounding(t *testing.T) {
	N := 8
	Q := big.NewInt(17)
	p, _ := ntru.NewParams(N, Q)
	epar := ntru.EmbedParams{Prec: 128, Real: true}
	floats := []float64{0.5, -0.5, 1.5, -1.5, 2.5, -2.5, 3.5, -3.5}
	ev, err := ntru.ToEvalFloat(floats, p, epar)
	if err != nil {
		t.Fatal(err)
	}
	backFloats, err := ntru.ToCoeffFloat(ev, p, epar)
	if err != nil {
		t.Fatal(err)
	}
	ints, err := ntru.ToCoeffInt(ev, p, epar)
	if err != nil {
		t.Fatal(err)
	}
	for i := range floats {
		want := ntru.RoundAwayFromZero(backFloats[i])
		if ints.Int[i] != want {
			t.Fatalf("rounding mismatch at %d", i)
		}
	}
}

func TestEvalConvolution(t *testing.T) {
	N := 8
	Q := big.NewInt(17)
	p, _ := ntru.NewParams(N, Q)
	epar := ntru.EmbedParams{Prec: 128, Real: true}
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 10; i++ {
		a := make([]int64, N)
		b := make([]int64, N)
		for j := 0; j < N; j++ {
			a[j] = int64(rng.Intn(5) - 2)
			b[j] = int64(rng.Intn(5) - 2)
		}
		ae, _ := ntru.ToEval(a, p, epar)
		be, _ := ntru.ToEval(b, p, epar)
		prod := make([]complex128, N)
		for j := 0; j < N; j++ {
			prod[j] = ae.V[j] * be.V[j]
		}
		ce, _ := ntru.ToCoeffInt(ntru.EvalVec{V: prod}, p, epar)
		// naive convolution
		ap := ntru.NewIntPoly(N)
		bp := ntru.NewIntPoly(N)
		for j := 0; j < N; j++ {
			ap.Coeffs[j].SetInt64(a[j])
			bp.Coeffs[j].SetInt64(b[j])
		}
		want := ntru.NaiveConvolutionZ(ap, bp, N)
		for j := 0; j < N; j++ {
			if ce.Int[j] != want.Coeffs[j].Int64() {
				t.Fatalf("convolution mismatch")
			}
		}
	}
}

func TestAdaptersRoundTrip(t *testing.T) {
	// build ring with NTT-friendly prime
	N := 16
	qi := uint64(12289)
	Q := big.NewInt(int64(qi))
	p, _ := ntru.NewParams(N, Q)
	p, _ = p.WithRNSFactorization([]uint64{qi})
	rings, _ := p.BuildRings()
	r := rings[0]
	coeffs := make([]int64, N)
	for i := 0; i < N; i++ {
		coeffs[i] = int64(i%5 - 2)
	}
	poly, err := ntru.CoeffIntToPolyNTT(r, coeffs, p)
	if err != nil {
		t.Fatal(err)
	}
	ev, err := ntru.PolyNTTToEval(r, poly, p, ntru.EmbedParams{Prec: 128})
	if err != nil {
		t.Fatal(err)
	}
	back, err := ntru.ToCoeffInt(ev, p, ntru.EmbedParams{Prec: 128})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < N; i++ {
		if back.Int[i] != coeffs[i] {
			t.Fatalf("adapter mismatch")
		}
	}
}
