package lvcs

import "math/bits"

// MulAddMod64 returns (sum + a*b) mod mod in constant-time on 64-bit words.
func MulAddMod64(sum, a, b, mod uint64) uint64 {
	a %= mod
	b %= mod
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, mod)
	sum %= mod
	s, c := bits.Add64(sum, rem, 0)
	if c == 1 || s >= mod {
		s -= mod
	}
	return s
}

// MulMod64 returns (a*b) mod mod using 128-bit intermediate multiplication.
func MulMod64(a, b, mod uint64) uint64 {
	a %= mod
	b %= mod
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, mod)
	return rem
}

// AddMod64 returns (a+b) mod mod.
func AddMod64(a, b, mod uint64) uint64 {
	a %= mod
	b %= mod
	s, c := bits.Add64(a, b, 0)
	if c == 1 || s >= mod {
		s -= mod
	}
	return s
}
