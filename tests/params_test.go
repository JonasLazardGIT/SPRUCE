package tests

import (
	"math/big"
	"testing"

	"vSIS-Signature/ntru"
)

func TestParamsAndRings(t *testing.T) {
	Q := big.NewInt(12289)
	p, err := ntru.NewParams(16, Q)
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	rings, err := p.BuildRings()
	if err != nil || len(rings) != 1 {
		t.Fatalf("BuildRings single: %v", err)
	}
	Qbig := new(big.Int).Mul(big.NewInt(12289), big.NewInt(40961))
	p2, _ := ntru.NewParams(16, Qbig)
	p2, _ = p2.WithRNSFactorization([]uint64{12289, 40961})
	rings, err = p2.BuildRings()
	if err != nil || len(rings) != 2 {
		t.Fatalf("BuildRings RNS: %v", err)
	}
}
