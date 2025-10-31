package ntru

import "math"

// RoundAwayFromZero implements C99 round semantics: ties are rounded away from zero.
func RoundAwayFromZero(x float64) int64 {
	if math.IsNaN(x) {
		return 0
	}
	if x >= 0 {
		return int64(math.Floor(x + 0.5))
	}
	return -int64(math.Floor(-x + 0.5))
}

// RoundAwayFromZeroVec applies RoundAwayFromZero element-wise.
func RoundAwayFromZeroVec(xs []float64) []int64 {
	out := make([]int64, len(xs))
	for i, x := range xs {
		out[i] = RoundAwayFromZero(x)
	}
	return out
}
