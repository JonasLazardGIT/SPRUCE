package ntru

import (
	"math/big"
	"math/bits"
)

// bitlenMaxAbsBig returns the maximum bit length among the absolute values
// of the big integers in s.
func bitlenMaxAbsBig(s []*big.Int) int {
	var m big.Int
	for _, v := range s {
		if v == nil {
			continue
		}
		if v.Sign() < 0 {
			var t big.Int
			t.Neg(v)
			if t.Cmp(&m) > 0 {
				m.Set(&t)
			}
		} else {
			if v.Cmp(&m) > 0 {
				m.Set(v)
			}
		}
	}
	return m.BitLen()
}

// bitlenMaxAbsInt64 returns the maximum bit length among the absolute values
// of the int64 coefficients in s.
func bitlenMaxAbsInt64(s []int64) int {
	m := 0
	for _, v := range s {
		if v < 0 {
			v = -v
		}
		b := bits.Len64(uint64(v))
		if b > m {
			m = b
		}
	}
	return m
}

// extraBitsBig mirrors the C extra_bits helper: it returns
// max(bitlen(a), bitlen(b), base) - base so the result is never negative.
func extraBitsBig(a, b []*big.Int, base int) int {
	maxBits := base
	if bl := bitlenMaxAbsBig(a); bl > maxBits {
		maxBits = bl
	}
	if bl := bitlenMaxAbsBig(b); bl > maxBits {
		maxBits = bl
	}
	return maxBits - base
}

// extraBitsInt64 is the int64 analogue of extraBitsBig.
func extraBitsInt64(a, b []int64, base int) int {
	maxBits := base
	if bl := bitlenMaxAbsInt64(a); bl > maxBits {
		maxBits = bl
	}
	if bl := bitlenMaxAbsInt64(b); bl > maxBits {
		maxBits = bl
	}
	return maxBits - base
}
