package ntru

import "fmt"

// CenterModQ maps coefficients in [0,q) to the symmetric interval (-q/2, q/2].
func CenterModQ(a []int64, q uint64) []int64 {
	fmt.Print("ModQ is with q=", q, "\n")
	out := make([]int64, len(a))
	half := int64(q / 2)
	qint := int64(q)
	for i, v := range a {
		if v > half {
			out[i] = v - qint
		} else {
			out[i] = v
		}
	}
	return out
}

// DecenterToModQ maps centered coefficients back to [0,q).
func DecenterToModQ(a []int64, q uint64) []uint64 {
	out := make([]uint64, len(a))
	qint := int64(q)
	for i, v := range a {
		t := v
		if t < 0 {
			t += qint
		}
		out[i] = uint64(t)
	}
	return out
}
