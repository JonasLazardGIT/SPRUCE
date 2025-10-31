package tests

import (
	"math/big"
	"math/rand"
	"testing"

	"vSIS-Signature/ntru"
)

func TestSlotSumsAndAlpha(t *testing.T) {
	N := 8
	Q := big.NewInt(17)
	p, _ := ntru.NewParams(N, Q)
	epar := ntru.EmbedParams{Prec: 128}
	rng := rand.New(rand.NewSource(2))
	f := make([]int64, N)
	g := make([]int64, N)
	for i := 0; i < N; i++ {
		f[i] = int64(rng.Intn(5) - 2)
		g[i] = int64(rng.Intn(5) - 2)
	}
	S, Smin, Smax, err := ntru.SlotSumsSquared(f, g, p, epar)
	if err != nil {
		t.Fatal(err)
	}
	// recompute min/max to verify
	minv, maxv := S[0], S[0]
	for _, v := range S {
		if v < minv {
			minv = v
		}
		if v > maxv {
			maxv = v
		}
	}
	if minv != Smin || maxv != Smax {
		t.Fatalf("min/max mismatch")
	}
	boundOK := ntru.AlphaWindowOK(S, 17, 10.0)
	if !boundOK {
		t.Fatalf("alpha check should pass")
	}
	// create failing case
	S[0] = 2000
	if ntru.AlphaWindowOK(S, 17, 10.0) {
		t.Fatalf("alpha check should fail")
	}
}
