package tests

import (
	"testing"

	"vSIS-Signature/ntru"
)

func TestIntPolyAddSub(t *testing.T) {
	a := ntru.NewIntPoly(4)
	b := ntru.NewIntPoly(4)
	for i := 0; i < 4; i++ {
		a.Coeffs[i].SetInt64(int64(i))
		b.Coeffs[i].SetInt64(int64(2*i + 1))
	}
	c := a.Add(b)
	d := c.Sub(b)
	for i := 0; i < 4; i++ {
		if d.Coeffs[i].Cmp(a.Coeffs[i]) != 0 {
			t.Fatalf("add/sub failed")
		}
	}
	if neg := a.Neg().Add(a); !allZero(neg) {
		t.Fatalf("neg failed")
	}
}

func allZero(p ntru.IntPoly) bool {
	for _, c := range p.Coeffs {
		if c.Sign() != 0 {
			return false
		}
	}
	return true
}
