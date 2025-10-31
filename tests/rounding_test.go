package tests

import (
	"math"
	"math/rand"
	"testing"

	"vSIS-Signature/ntru"
)

func TestRoundAwayFromZero(t *testing.T) {
	cases := []struct {
		in   float64
		want int64
	}{
		{0.5, 1},
		{-0.5, -1},
		{1.5, 2},
		{-1.5, -2},
		{2.5, 3},
		{-2.5, -3},
		{123456789.5, 123456790},
		{-123456789.5, -123456790},
		{1e-308, 0},
		{-1e-308, 0},
	}
	for _, tc := range cases {
		got := ntru.RoundAwayFromZero(tc.in)
		if got != tc.want {
			t.Fatalf("round(%f)=%d want %d", tc.in, got, tc.want)
		}
	}
	// randomized around half-integers
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 1000; i++ {
		k := rng.Int63n(1000) - 500
		x := float64(k) + 0.5
		eps := (rng.Float64() - 0.5) * 1e-12
		v := x + eps
		got := ntru.RoundAwayFromZero(v)
		var want int64
		if v >= 0 {
			want = int64(math.Floor(v + 0.5))
		} else {
			want = -int64(math.Floor(-v + 0.5))
		}
		if got != want {
			t.Fatalf("round(%f)=%d want %d", v, got, want)
		}
	}
}

func TestRoundAwayFromZeroVec(t *testing.T) {
	xs := []float64{0.5, -0.5, 1.2, -1.2}
	got := ntru.RoundAwayFromZeroVec(xs)
	want := []int64{1, -1, 1, -1}
	for i := range xs {
		if got[i] != want[i] {
			t.Fatalf("vec[%d]=%d want %d", i, got[i], want[i])
		}
	}
}
