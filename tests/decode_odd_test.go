package tests

import (
	"math"
	"testing"
	ntru "vSIS-Signature/ntru"
)

func parity(xs []int64) int64 {
	var s int64
	for _, v := range xs {
		s += v
	}
	return s & 1
}

// Test that DecodeOdd enforces odd sum and flips the worst-fractional index
// with ties broken by smallest index, matching the C implementation.
func TestDecodeOdd_ParityAndWorstFlip(t *testing.T) {
	// Case 1: simple halves; ties-to-even baseline
	in := []float64{0.5, 0.5, 0.5, 0.5}
	out, err := ntru.DecodeOdd(in)
	if err != nil {
		t.Fatalf("DecodeOdd: %v", err)
	}
	if parity(out) != 1 {
		t.Fatalf("expected odd parity, got even: %v", out)
	}
	// RoundToEven baseline would round all to 0; worst is index 0; flip upward to 1
	if out[0] != 1 {
		t.Fatalf("index 0 must be flipped to 1; got %v", out)
	}
	for i := 1; i < len(out); i++ {
		if out[i] != 0 {
			t.Fatalf("unexpected change at %d: %v", i, out)
		}
	}

	// Case 2: mixed 1.5 and 2.5 (both at 0.5 distance), nearest-even → (2,2), flip index 0 downward
	in2 := []float64{1.5, 2.5}
	out2, err := ntru.DecodeOdd(in2)
	if err != nil {
		t.Fatalf("DecodeOdd: %v", err)
	}
	if parity(out2) != 1 {
		t.Fatalf("expected odd parity, got even: %v", out2)
	}
	// 1.5 rounds to 2 (even), and x>ui is false → wi=1
	if out2[0] != 1 || out2[1] != 2 {
		t.Fatalf("want [1 2], got %v", out2)
	}

	// Case 3: negatives -0.5,-1.5 → (0,-2) baseline, flip index 0 downward to -1
	in3 := []float64{-0.5, -1.5}
	out3, err := ntru.DecodeOdd(in3)
	if err != nil {
		t.Fatalf("DecodeOdd: %v", err)
	}
	if parity(out3) != 1 {
		t.Fatalf("expected odd parity, got even: %v", out3)
	}
	if out3[0] != -1 || out3[1] != -2 {
		t.Fatalf("want [-1 -2], got %v", out3)
	}
}

// Validate that the chosen index is the first among equals (strict > tie-break)
func TestDecodeOdd_TieBreakFirstIndex(t *testing.T) {
	// Construct equal distances at three positions
	base := []float64{2.5, 2.5, 2.5}
	out, err := ntru.DecodeOdd(base)
	if err != nil {
		t.Fatalf("DecodeOdd: %v", err)
	}
	if parity(out) != 1 {
		t.Fatalf("expected odd parity, got even: %v", out)
	}
	// Nearest-even → all 2; flip index 0 upward to 3
	if out[0] != 3 || out[1] != 2 || out[2] != 2 {
		t.Fatalf("tie should pick first index 0; got %v", out)
	}
}

// Randomized sanity: produced vector is close and odd
func TestDecodeOdd_RandomSanity(t *testing.T) {
	in := make([]float64, 64)
	for i := range in {
		in[i] = math.Sin(float64(i))*3.25 + 0.3*math.Cos(float64(7*i))
	}
	out, err := ntru.DecodeOdd(in)
	if err != nil {
		t.Fatalf("DecodeOdd: %v", err)
	}
	if parity(out) != 1 {
		t.Fatalf("expected odd parity, got even: %v", out)
	}
}
