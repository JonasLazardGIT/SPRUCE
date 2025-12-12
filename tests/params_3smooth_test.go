package tests

import (
	"math/big"
	"testing"
	ntru "vSIS-Signature/ntru"
)

func TestNewParams_3Smooth(t *testing.T) {
	for _, N := range []int{6, 12, 16, 24} {
		par, err := ntru.NewParams(N, big.NewInt(12289))
		if err != nil {
			t.Fatalf("NewParams(%d): %v", N, err)
		}
		if par.N != N {
			t.Fatalf("wrong N")
		}
		// LOG3_D should be true when divisible by 3
		if (N%3 == 0) != par.LOG3_D {
			t.Fatalf("LOG3_D mismatch for N=%d: got %v", N, par.LOG3_D)
		}
	}
}
