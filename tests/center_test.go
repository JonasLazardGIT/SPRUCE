package tests

import (
	"math/rand"
	"testing"

	"vSIS-Signature/ntru"
)

func TestCenterDecenter(t *testing.T) {
	q := uint64(12289)
	rng := rand.New(rand.NewSource(0))
	coeffs := make([]int64, 100)
	for i := range coeffs {
		coeffs[i] = int64(rng.Intn(int(q)))
	}
	centered := ntru.CenterModQ(coeffs, q)
	// range check
	half := int64(q / 2)
	for _, c := range centered {
		if c <= -half || c > half {
			t.Fatalf("centered value %d out of range", c)
		}
	}
	dec := ntru.DecenterToModQ(centered, q)
	for i := range coeffs {
		if uint64(coeffs[i]) != dec[i] {
			t.Fatalf("roundtrip mismatch")
		}
	}
}
