package PIOP

import "testing"

func TestMaskConfigFromOpts(t *testing.T) {
	o := SimOpts{Rho: 3, EllPrime: 2, Ell: 5, Eta: 7, DQOverride: 11}
	m := MaskConfigFromOpts(o)
	if m.Rho != 3 || m.EllPrime != 2 || m.Ell != 5 || m.Eta != 7 || m.DQ != 11 {
		t.Fatalf("mask config mismatch: %+v", m)
	}
}
