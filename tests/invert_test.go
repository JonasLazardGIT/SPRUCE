package tests

import (
	"math/big"
	"testing"

	"vSIS-Signature/ntru"
)

func quickParamsNQ() ntru.Params {
	N := 16
	q1 := uint64(12289)
	q2 := uint64(40961)
	Qbig := new(big.Int).Mul(big.NewInt(int64(q1)), big.NewInt(int64(q2)))
	p, _ := ntru.NewParams(N, Qbig)
	p, _ = p.WithRNSFactorization([]uint64{q1, q2})
	return p
}

func randSmallModQPoly(rng *ntru.RNG, N int, Q *big.Int) ntru.ModQPoly {
	poly := ntru.NewModQPoly(N, Q)
	for i := 0; i < N; i++ {
		v := int64(rng.Intn(7)) - 3
		if v < 0 {
			poly.Coeffs[i].Add(poly.Coeffs[i], Q)
		}
		poly.Coeffs[i].Add(poly.Coeffs[i], big.NewInt(v))
		poly.Coeffs[i].Mod(poly.Coeffs[i], Q)
	}
	return poly
}

func TestInvertModQ_RandomUnits(t *testing.T) {
	par := quickParamsNQ()
	rng := ntru.NewRNG(1)
	trials := 0
	for trials < 32 {
		f := randSmallModQPoly(rng, par.N, par.Q)
		fInv, ok := ntru.InvertModQ(f, par)
		if !ok {
			continue
		}
		one, err := ntru.ConvolveRNS(f, fInv, par)
		if err != nil {
			t.Fatalf("ConvolveRNS error: %v", err)
		}
		for i := 0; i < par.N; i++ {
			coeff := new(big.Int).Mod(one.Coeffs[i], par.Q)
			if i == 0 {
				if coeff.Cmp(big.NewInt(1)) != 0 {
					t.Fatalf("inverse incorrect")
				}
			} else if coeff.Sign() != 0 {
				t.Fatalf("inverse incorrect")
			}
		}
		trials++
	}
}

func TestInvertModQ_NonUnits(t *testing.T) {
	par := quickParamsNQ()
	zero := ntru.NewModQPoly(par.N, par.Q)
	if _, ok := ntru.InvertModQ(zero, par); ok {
		t.Fatalf("zero polynomial should not be invertible")
	}
	nonunit := ntru.NewModQPoly(par.N, par.Q)
	nonunit.Coeffs[0].SetUint64(40961)
	if _, ok := ntru.InvertModQ(nonunit, par); ok {
		t.Fatalf("polynomial with zero limb should not be invertible")
	}
}

func TestIsUnitModQ_AgreesWithInvert(t *testing.T) {
	par := quickParamsNQ()
	rng := ntru.NewRNG(2)
	for i := 0; i < 20; i++ {
		f := randSmallModQPoly(rng, par.N, par.Q)
		inv, ok1 := ntru.InvertModQ(f, par)
		_ = inv
		ok2 := ntru.IsUnitModQ(f, par)
		if ok1 != ok2 {
			t.Fatalf("IsUnitModQ mismatch")
		}
	}
}
