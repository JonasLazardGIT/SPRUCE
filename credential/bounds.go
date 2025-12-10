package credential

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// CheckBound asserts every coefficient of each polynomial lies in [-bound, bound].
func CheckBound(vec []*ring.Poly, bound int64, name string, ringQ *ring.Ring) error {
	if bound <= 0 {
		return fmt.Errorf("%s: bound must be > 0", name)
	}
	halfQ := int64(ringQ.Modulus[0] / 2)
	q := int64(ringQ.Modulus[0])
	for idx, p := range vec {
		if p == nil {
			return fmt.Errorf("%s[%d]: nil polynomial", name, idx)
		}
		for _, c := range p.Coeffs[0] {
			v := int64(c)
			if v > halfQ {
				v -= q
			}
			if v < -bound || v > bound {
				return fmt.Errorf("%s[%d]: coefficient %d out of bound [%d,%d]", name, idx, v, -bound, bound)
			}
		}
	}
	return nil
}

// CheckLengths validates the expected number of polynomials in a slice.
func CheckLengths(vec []*ring.Poly, want int, name string) error {
	if len(vec) != want {
		return fmt.Errorf("%s length=%d want=%d", name, len(vec), want)
	}
	return nil
}
