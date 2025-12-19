package ntru

import (
	"errors"
	"math"
)

// DecodeOdd implements the Conway–Sloane odd-sum decoder, matching the C code
// in antrag/keygen.c:
//   - Round each coefficient with ties-to-even (C lrint semantics).
//   - If the sum is even, find the index with the largest distance to Z
//     (max |x[i] - round_to_even(x[i])|). On ties, pick the smallest index.
//   - Flip that coefficient by ±1 in the direction away from round_to_even:
//     if x > ui then ui+1 else ui-1.
//
// Returns integer coefficients with an odd sum.
func DecodeOdd(coeffs []float64) ([]int64, error) {
	n := len(coeffs)
	if n == 0 {
		return nil, errors.New("DecodeOdd: empty input")
	}
	out := make([]int64, n)
	var sum int64

	// First pass: round (ties-to-even), track worst fractional distance
	worstIdx := 0
	maxdiff := -1.0
	var wi int64 = 0 // candidate flipped value for worst index
	for i, x := range coeffs {
		// ui = lrint(x) equivalent: nearest with ties-to-even
		ui := int64(math.RoundToEven(x))
		out[i] = ui
		sum += ui
		diff := math.Abs(x - float64(ui))
		if diff > maxdiff {
			maxdiff = diff
			worstIdx = i
			if x > float64(ui) {
				wi = ui + 1
			} else {
				wi = ui - 1
			}
		}
	}

	// If sum is even, flip worstIdx in the recorded direction
	if (sum & 1) == 0 {
		out[worstIdx] = wi
	}
	return out, nil
}
