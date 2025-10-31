package Preimage_Sampler

import (
	"math"
	"math/bits"
	"math/cmplx"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// baseDigits decomposes v (which may be negative) into k little-endian
// base-t digits, each in [0,base).
func baseDigits(v int64, base int64, k int) []int64 {
	digits := make([]int64, k)
	temp := v
	for i := 0; i < k; i++ {
		r := temp % base
		if r < 0 {
			r += base
		}
		digits[i] = r
		// now subtract it off and divide
		temp = (temp - r) / base
	}
	return digits
}

// balancedDigits returns centered base-t digits (least significant first)
// in [-(base/2), ..., +((base-1)/2)] that still sum to v.
func balancedDigits(v int64, base int64, k int) []int64 {
	raw := baseDigits(v, base, k)
	half := base / 2
	for i := 0; i < k; i++ {
		if raw[i] > half {
			raw[i] -= base
			if i+1 < k {
				raw[i+1] += 1
			}
		}
	}
	return raw
}

func AutomorphismTranspose(r *ring.Ring, p *ring.Poly) *ring.Poly {
	N := r.N
	result := r.NewPoly()

	for lvl, q := range r.Modulus {
		// copy index 0 exactly
		result.Coeffs[lvl][0] = p.Coeffs[lvl][0] % q
		for i := 1; i < N; i++ {
			coeff := p.Coeffs[lvl][N-i] % q
			if coeff != 0 {
				result.Coeffs[lvl][i] = (q - coeff) % q
			} else {
				result.Coeffs[lvl][i] = 0
			}
		}
	}

	return result
}

// FFT computes the forward Fast Fourier Transform (FFT) of the input coefficients
// at the primitive 2n-th roots of unity. The input length must be exactly n and n must be a power of 2.
func FFT(coeffs []complex128, n int) []complex128 {
	// Ensure input length is valid
	if len(coeffs) != n {
		panic("FFT: input length must be exactly n")
	}
	if n == 0 || (n&(n-1)) != 0 {
		panic("FFT: n must be a power of 2")
	}

	// Copy input to avoid mutation
	result := make([]complex128, n)
	copy(result, coeffs)

	// Bit-reversal permutation
	logN := bits.Len(uint(n)) - 1
	for i := 0; i < n; i++ {
		j := bitReverse(i, logN)
		if i < j {
			result[i], result[j] = result[j], result[i]
		}
	}

	// Cooley-Tukey iterative FFT
	for size := 2; size <= n; size *= 2 {
		halfSize := size / 2
		angle := -2 * math.Pi / float64(size) // Forward FFT => negative sign
		wn := cmplx.Rect(1, angle)            // e^{-2πi/size}

		for start := 0; start < n; start += size {
			w := complex(1, 0)
			for j := 0; j < halfSize; j++ {
				idx1 := start + j
				idx2 := start + j + halfSize

				temp := w * result[idx2]
				result[idx2] = result[idx1] - temp
				result[idx1] = result[idx1] + temp

				w *= wn
			}
		}
	}

	return result
}

// IFFT performs an Inverse Fast Fourier Transform to convert from evaluation
// representation back to coefficient representation
func IFFT(evals []complex128, n int) []complex128 {
	// Initialize result array and compute logN for bit-reversal
	result := make([]complex128, n)
	copy(result, evals)
	logN := bits.Len(uint(n)) - 1
	// Bit-reversal permutation
	for i := 0; i < n; i++ {
		j := bitReverse(i, logN)
		if i < j {
			result[i], result[j] = result[j], result[i]
		}
	}

	// Cooley-Tukey IFFT algorithm
	for size := 2; size <= n; size *= 2 {
		halfSize := size / 2
		angle := 2 * math.Pi / float64(size) // Positive for inverse FFT

		// Calculate primitive root of unity for this stage
		wn := cmplx.Rect(1, angle)

		for start := 0; start < n; start += size {
			w := complex(1, 0) // Start with w = 1

			for j := 0; j < halfSize; j++ {
				idx1 := start + j
				idx2 := start + j + halfSize

				// Butterfly operation
				temp := w * result[idx2]
				result[idx2] = result[idx1] - temp
				result[idx1] = result[idx1] + temp

				// Update w
				w *= wn
			}
		}
	}

	// Scale by 1/n for inverse FFT
	for i := 0; i < n; i++ {
		result[i] /= complex(float64(n), 0)
	}

	return result
}

// bitReverse computes the bit-reversal of i with respect to logN bits
func bitReverse(i int, logN int) int {
	var reversed int
	for j := 0; j < logN; j++ {
		if (i>>j)&1 == 1 {
			reversed |= 1 << (logN - 1 - j)
		}
	}
	return reversed
}

func ModQToFloat64(x, q uint64) float64 {
	// map to [-⌊q/2⌋ … +⌊(q-1)/2⌋]
	if x > q/2 {
		return float64(int64(x) - int64(q))
	}
	return float64(x)
}

func PolyNorm2(r *ring.Ring, p *ring.Poly) float64 {
	var sum float64
	for _, coeff := range p.Coeffs[0] {
		// Map to centered interval around 0
		centered := float64(int64(coeff))
		if centered > float64(r.Modulus[0])/2 {
			centered -= float64(r.Modulus[0])
		}
		sum += centered * centered
	}
	return math.Sqrt(sum)
}

// UnsignedToSigned maps u ∈ [0,q) to s ∈ [−q/2, q/2).
func UnsignedToSigned(u uint64, q uint64) int64 {
	half := q >> 1
	if (q&1 == 0 && u >= half) || (q&1 == 1 && u > half) {
		// map upper half to negative reps to keep interval [−q/2, q/2)
		return int64(u) - int64(q)
	}
	// u in lower half remains unchanged
	return int64(u)
}

// SignedToUnsigned maps s ∈ [−q/2, q/2) back to u ∈ [0,q).
func SignedToUnsigned(s int64, q uint64) uint64 {
	m := int64(q)
	// reduce mod q into [−q+1, q−1]
	r := s % m
	// now lift negative into [0,q)
	if r < 0 {
		r += m
	}
	return uint64(r)
}

// DotProduct computes the negacyclic dot product \sum_i transpose(a_i) * b_i.
// Both inputs must be in the NTT (evaluation) domain. The result is returned
// in the NTT domain.
func DotProduct(r *ring.Ring, a, b []*ring.Poly) *ring.Poly {
	if len(a) != len(b) {
		panic("DotProduct: length mismatch")
	}
	acc := r.NewPoly()
	tmp := r.NewPoly()
	for i := range a {
		coeff := r.NewPoly()
		r.InvNTT(a[i], coeff)
		coeff = AutomorphismTranspose(r, coeff)
		r.NTT(coeff, coeff)
		r.MulCoeffs(coeff, b[i], tmp)
		r.Add(acc, tmp, acc)
	}
	return acc
}
