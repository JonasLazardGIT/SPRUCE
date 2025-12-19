package Preimage_Sampler

import (
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"math/rand"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Domain indicates whether a CyclotomicFieldElem is in coefficient or evaluation domain.
type Domain int

const (
	Coeff Domain = iota
	Eval
)

// BigComplex represents a complex number with arbitrary-precision parts.
type BigComplex struct {
	Real *big.Float
	Imag *big.Float
}

// NewBigComplex creates a BigComplex with given real, imag and precision.
func NewBigComplex(real, imag float64, prec uint) *BigComplex {
	return &BigComplex{
		Real: new(big.Float).SetPrec(prec).SetFloat64(real),
		Imag: new(big.Float).SetPrec(prec).SetFloat64(imag),
	}
}

// NewBigComplexFromFloat copies floats into a BigComplex.
func NewBigComplexFromFloat(re, im *big.Float) *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Copy(re),
		Imag: new(big.Float).Copy(im),
	}
}

// NewBigComplexZero returns zero BigComplex at precision.
func NewBigComplexZero(prec uint) *BigComplex {
	return NewBigComplex(0, 0, prec)
}

// Add returns z + w.
func (z *BigComplex) Add(w *BigComplex) *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Add(z.Real, w.Real),
		Imag: new(big.Float).Add(z.Imag, w.Imag),
	}
}

// Sub returns z - w.
func (z *BigComplex) Sub(w *BigComplex) *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Sub(z.Real, w.Real),
		Imag: new(big.Float).Sub(z.Imag, w.Imag),
	}
}

// Mul returns z * w.
func (z *BigComplex) Mul(w *BigComplex) *BigComplex {
	ac := new(big.Float).Mul(z.Real, w.Real)
	bd := new(big.Float).Mul(z.Imag, w.Imag)
	ad := new(big.Float).Mul(z.Real, w.Imag)
	bc := new(big.Float).Mul(z.Imag, w.Real)
	return &BigComplex{
		Real: new(big.Float).Sub(ac, bd),
		Imag: new(big.Float).Add(ad, bc),
	}
}

// Conj returns complex conjugate.
func (z *BigComplex) Conj() *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Copy(z.Real),
		Imag: new(big.Float).Neg(z.Imag),
	}
}

// AbsSquared returns |z|^2.
func (z *BigComplex) AbsSquared() *big.Float {
	r2 := new(big.Float).Mul(z.Real, z.Real)
	i2 := new(big.Float).Mul(z.Imag, z.Imag)
	return new(big.Float).Add(r2, i2)
}

// Inv returns 1/z.
func (z *BigComplex) Inv() *BigComplex {
	conj := z.Conj()
	d := z.AbsSquared()
	return &BigComplex{
		Real: new(big.Float).Quo(conj.Real, d),
		Imag: new(big.Float).Quo(conj.Imag, d),
	}
}

// Copy returns a deep copy.
func (z *BigComplex) Copy() *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Copy(z.Real),
		Imag: new(big.Float).Copy(z.Imag),
	}
}

// DivBy divides z by scalar.
func (z *BigComplex) DivBy(scalar *big.Float) *BigComplex {
	return &BigComplex{
		Real: new(big.Float).Quo(z.Real, scalar),
		Imag: new(big.Float).Quo(z.Imag, scalar),
	}
}

// cloneBigComplexSlice returns a deep copy of a slice of BigComplex values.
func cloneBigComplexSlice(in []*BigComplex, prec uint) []*BigComplex {
	out := make([]*BigComplex, len(in))
	for i, z := range in {
		if z == nil {
			out[i] = nil
			continue
		}
		out[i] = &BigComplex{
			Real: new(big.Float).SetPrec(prec).Copy(z.Real),
			Imag: new(big.Float).SetPrec(prec).Copy(z.Imag),
		}
	}
	return out
}

// CyclotomicFieldElem is an element in K_{2N}.
type CyclotomicFieldElem struct {
	N      int
	Coeffs []*BigComplex
	Domain Domain
}

// NewFieldElemBig allocates a zero field element in coeff domain.
func NewFieldElemBig(n int, prec uint) *CyclotomicFieldElem {
	coeffs := make([]*BigComplex, n)
	for i := range coeffs {
		coeffs[i] = NewBigComplexZero(prec)
	}
	return &CyclotomicFieldElem{N: n, Coeffs: coeffs, Domain: Coeff}
}

// DggSampler interface for Gaussian samplers.
type DggSampler interface {
	SampleKarney(mean, stddev float64) int64
}

// Matrix is a generic matrix.
type Matrix[T any] struct {
	Rows, Cols int
	Data       []T
}

// NewMatrix allocates a matrix of zero values.
func NewMatrix[T any](rows, cols int) *Matrix[T] {
	return &Matrix[T]{Rows: rows, Cols: cols, Data: make([]T, rows*cols)}
}

// At returns element (i,j).
func (m *Matrix[T]) At(i, j int) T {
	return m.Data[i*m.Cols+j]
}

// Set assigns element (i,j) = v.
func (m *Matrix[T]) Set(i, j int, v T) {
	m.Data[i*m.Cols+j] = v
}

// ----------------------------------------------------------------
// FFTBig: take “coeffs” (length n, a power of two) in coefficient form and
//
//	return the length-n slice of *BigComplex values evaluated at the
//	primitive 2n-th roots of unity e^{-2πi·k/size} (forward FFT).
//
//	- coeffs: slice of length n of *BigComplex (domain: “time” or “coeff”).
//	- prec: the precision (in bits) that should be used for every BigComplex
//	        in the output and intermediate twiddle factors.
//	- Returns a brand-new slice of length n of *BigComplex in the “evaluation” domain.
//
//	**IMPORTANT**: internally we compute the complex exponentials e^{-2πi/size}
//	by calling math.Cos, math.Sin in float64 and then lifting to big.Float.
//	If you need **full** big‐float accuracy on those sines/cosines, you must
//	replace the calls to math.Cos/math.Sin by a high‐precision big‐float routine.
//
//	NOTE: this is the standard in-place Cooley–Tukey; we allocate a new buffer
//	so that we do not destroy the input argument.
//
// ----------------------------------------------------------------
func FFTBig(coeffs []*BigComplex, prec uint) []*BigComplex {
	n := len(coeffs)
	if n == 0 || (n&(n-1)) != 0 {
		panic("FFTBig: length must be a nonzero power of 2")
	}

	// 1) Copy input into result array
	result := make([]*BigComplex, n)
	for i := 0; i < n; i++ {
		result[i] = coeffs[i].Copy()
	}

	// 2) Bit-reversal reordering
	logN := bits.Len(uint(n)) - 1
	for i := 0; i < n; i++ {
		j := bitReverseBig(i, logN)
		if i < j {
			result[i], result[j] = result[j], result[i]
		}
	}

	// 3) Iterative Cooley–Tukey
	//    “size” loops over 2, 4, 8, …, n
	for size := 2; size <= n; size <<= 1 {
		half := size >> 1

		// angle = −2π/size  (forward FFT => negative)
		// we compute cos(angle) and sin(angle) as float64, then lift to big.Float
		angleF := -2.0 * math.Pi / float64(size)
		cosF := big.NewFloat(0).SetPrec(prec).SetFloat64(math.Cos(angleF))
		sinF := big.NewFloat(0).SetPrec(prec).SetFloat64(math.Sin(angleF))

		// wn = e^{i * angle} in *BigComplex form
		wn := &BigComplex{
			Real: new(big.Float).Copy(cosF),
			Imag: new(big.Float).Copy(sinF),
		}

		for start := 0; start < n; start += size {
			// w = 1 + 0i (as *BigComplex)
			w := &BigComplex{
				Real: big.NewFloat(1).SetPrec(prec),
				Imag: big.NewFloat(0).SetPrec(prec),
			}

			for j := 0; j < half; j++ {
				idx1 := start + j
				idx2 := start + j + half

				// temp = w * result[idx2]
				temp := result[idx2].Mul(w)

				// result[idx2] = result[idx1] - temp
				result[idx2] = result[idx1].Sub(temp)

				// result[idx1] = result[idx1] + temp
				result[idx1] = result[idx1].Add(temp)

				// w = w * wn   (update twiddle)
				w = w.Mul(wn)
			}
		}
	}

	return result
}

// isPow2 returns true if n is a power of two.
func isPow2(n int) bool { return n > 0 && (n&(n-1)) == 0 }

// isSmooth23 returns true if n has no prime factors other than 2 or 3.
func isSmooth23(n int) bool {
	if n <= 0 {
		return false
	}
	for n%2 == 0 {
		n /= 2
	}
	for n%3 == 0 {
		n /= 3
	}
	return n == 1
}

// fftAny computes a forward FFT of length n allowing 2/3-smooth sizes.
// If n is power-of-two, delegates to FFTBig; otherwise uses a recursive
// Cooley–Tukey mixed-radix (2 and 3) implementation.
func fftAny(a []*BigComplex, prec uint) []*BigComplex {
	L := len(a)
	if isPow2(L) {
		return FFTBig(a, prec)
	}
	if !isSmooth23(L) {
		panic("fftAny: length not 2/3-smooth")
	}
	return fftRec(a, prec)
}

func fftRec(a []*BigComplex, prec uint) []*BigComplex {
	L := len(a)
	out := make([]*BigComplex, L)
	if L == 1 {
		out[0] = a[0].Copy()
		return out
	}
	var r int
	if L%2 == 0 {
		r = 2
	} else {
		r = 3
	}
	m := L / r
	// Split into r subsequences of length m
	xs := make([][]*BigComplex, r)
	for s := 0; s < r; s++ {
		xs[s] = make([]*BigComplex, m)
		for t := 0; t < m; t++ {
			xs[s][t] = a[r*t+s]
		}
	}
	// Recursively transform each
	Ys := make([][]*BigComplex, r)
	for s := 0; s < r; s++ {
		Ys[s] = fftRec(xs[s], prec)
	}
	// Combine
	for k := 0; k < L; k++ {
		k0 := k % m
		theta := -2.0 * math.Pi * float64(k) / float64(L)
		wk := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(math.Cos(theta)), Imag: new(big.Float).SetPrec(prec).SetFloat64(math.Sin(theta))}
		sum := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(0), Imag: new(big.Float).SetPrec(prec).SetFloat64(0)}
		// s=0 term
		sum = sum.Add(Ys[0][k0])
		if r >= 2 {
			term1 := Ys[1][k0].Mul(wk)
			if r == 2 {
				sum = sum.Add(term1)
			} else {
				// r == 3
				// omega = e^{-2π i / 3}
				omega := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(-0.5), Imag: new(big.Float).SetPrec(prec).SetFloat64(-math.Sqrt(3) / 2)}
				// y1 = x0 + x1*omega + x2*omega^2
				// We'll add x1*omega part below; x2 part handled when s=2
				term1 = term1.Mul(omega)
				sum = sum.Add(term1)
				// s=2
				wk2 := wk.Mul(wk)
				term2 := Ys[2][k0].Mul(wk2)
				// omega^2 = conjugate of omega
				omega2 := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(-0.5), Imag: new(big.Float).SetPrec(prec).SetFloat64(+math.Sqrt(3) / 2)}
				term2 = term2.Mul(omega2)
				sum = sum.Add(term2)
			}
		}
		out[k] = sum
	}
	return out
}

// ifftAny is the inverse of fftAny and scales by 1/n.
func ifftAny(A []*BigComplex, prec uint) []*BigComplex {
	L := len(A)
	if isPow2(L) {
		return IFFTBig(A, prec)
	}
	if !isSmooth23(L) {
		panic("ifftAny: length not 2/3-smooth")
	}
	res := ifftRec(A, prec)
	// scale by 1/L
	invL := new(big.Float).SetPrec(prec).Quo(big.NewFloat(1).SetPrec(prec), big.NewFloat(float64(L)).SetPrec(prec))
	for i := 0; i < L; i++ {
		res[i].Real = new(big.Float).Mul(res[i].Real, invL)
		res[i].Imag = new(big.Float).Mul(res[i].Imag, invL)
	}
	return res
}

// FFTAnyBig is an exported wrapper around fftAny for 2/3-smooth lengths.
// It returns the forward DFT of the input slice using mixed radix-2/3 recursion.
func FFTAnyBig(a []*BigComplex, prec uint) []*BigComplex { return fftAny(a, prec) }

// IFFTAnyBig is an exported wrapper around ifftAny for 2/3-smooth lengths.
// It returns the inverse DFT of the input slice, scaled by 1/n.
func IFFTAnyBig(A []*BigComplex, prec uint) []*BigComplex { return ifftAny(A, prec) }

func ifftRec(A []*BigComplex, prec uint) []*BigComplex {
	L := len(A)
	out := make([]*BigComplex, L)
	if L == 1 {
		out[0] = A[0].Copy()
		return out
	}
	var r int
	if L%2 == 0 {
		r = 2
	} else {
		r = 3
	}
	m := L / r
	// Split index by modulo classes (inverse of fftRec splitting)
	Ys := make([][]*BigComplex, r)
	for s := 0; s < r; s++ {
		Ys[s] = make([]*BigComplex, m)
	}
	// Decompose A into components by inverse twiddle application
	// We'll reconstruct x via inverse Cooley–Tukey:
	for t := 0; t < m; t++ {
		for s := 0; s < r; s++ {
			Ys[s][t] = &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(0), Imag: new(big.Float).SetPrec(prec).SetFloat64(0)}
		}
	}
	for k := 0; k < L; k++ {
		k0 := k % m
		theta := 2.0 * math.Pi * float64(k) / float64(L)
		wk := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(math.Cos(theta)), Imag: new(big.Float).SetPrec(prec).SetFloat64(math.Sin(theta))}
		// contribution from A[k]
		x0 := A[k]
		// s=0
		Ys[0][k0] = Ys[0][k0].Add(x0)
		if r >= 2 {
			// s=1
			y1 := x0
			omega := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(-0.5), Imag: new(big.Float).SetPrec(prec).SetFloat64(+math.Sqrt(3) / 2)} // conj of forward omega
			term1 := y1.Mul(omega).Mul(wk)
			if r == 2 {
				Ys[1][k0] = Ys[1][k0].Add(term1)
			} else {
				Ys[1][k0] = Ys[1][k0].Add(term1)
				// s=2
				omega2 := &BigComplex{Real: new(big.Float).SetPrec(prec).SetFloat64(-0.5), Imag: new(big.Float).SetPrec(prec).SetFloat64(-math.Sqrt(3) / 2)}
				wk2 := wk.Mul(wk)
				term2 := y1.Mul(omega2).Mul(wk2)
				Ys[2][k0] = Ys[2][k0].Add(term2)
			}
		}
	}
	// Recursively invert each subsequence
	xs := make([][]*BigComplex, r)
	for s := 0; s < r; s++ {
		xs[s] = ifftRec(Ys[s], prec)
	}
	// Interleave back
	for s := 0; s < r; s++ {
		for t := 0; t < m; t++ {
			out[r*t+s] = xs[s][t]
		}
	}
	// scale by 1 (handled cumulatively); divide by r here? We will divide by L at top-level caller
	if len(out) == L {
		// final scaling by 1/L handled by caller path NegacyclicInterpolateElem
	}
	return out
}

// ----------------------------------------------------------------
// IFFTBig: take a slice of length n = power‐of‐two in “evaluation” domain
//
//	(i.e. values at the 2n-th roots e^{-2πik/size}), and return the inverse FFT
//	so that the output is back in “coefficient” form. We scale by 1/n at the end.
//
//	- evals:   slice of length n of *BigComplex in evaluation domain.
//	- prec:    desired precision (bits) for all intermediate big‐floats.
//	- Returns length-n slice of *BigComplex in coefficient domain.
//
//	Again, we do exactly the same bit-reversal + Cooley–Tukey, but we use
//	the opposite sign of the root (angle = +2π/size), and in the end divide
//	every coordinate by n (via big-float division).
//
// ----------------------------------------------------------------
func IFFTBig(evals []*BigComplex, prec uint) []*BigComplex {
	n := len(evals)
	if n == 0 || (n&(n-1)) != 0 {
		panic("IFFTBig: length must be a nonzero power of 2")
	}

	// 1) Copy evals into result
	result := make([]*BigComplex, n)
	for i := 0; i < n; i++ {
		result[i] = evals[i].Copy()
	}

	// 2) Bit-reversal
	logN := bits.Len(uint(n)) - 1
	for i := 0; i < n; i++ {
		j := bitReverseBig(i, logN)
		if i < j {
			result[i], result[j] = result[j], result[i]
		}
	}

	// 3) Inverse Cooley–Tukey (angle = +2π/size)
	for size := 2; size <= n; size <<= 1 {
		half := size >> 1

		angleF := 2.0 * math.Pi / float64(size) // **positive** for inverse FFT
		cosF := big.NewFloat(0).SetPrec(prec).SetFloat64(math.Cos(angleF))
		sinF := big.NewFloat(0).SetPrec(prec).SetFloat64(math.Sin(angleF))

		wn := &BigComplex{
			Real: new(big.Float).Copy(cosF),
			Imag: new(big.Float).Copy(sinF),
		}

		for start := 0; start < n; start += size {
			w := &BigComplex{
				Real: big.NewFloat(1).SetPrec(prec),
				Imag: big.NewFloat(0).SetPrec(prec),
			}
			for j := 0; j < half; j++ {
				idx1 := start + j
				idx2 := start + j + half

				temp := result[idx2].Mul(w)

				result[idx2] = result[idx1].Sub(temp)
				result[idx1] = result[idx1].Add(temp)

				w = w.Mul(wn)
			}
		}
	}

	// 4) Divide everything by n (scale by 1/n in big-float)
	bigN := big.NewFloat(0).SetPrec(prec).SetFloat64(float64(n))
	invN := new(big.Float).SetPrec(prec).Quo(big.NewFloat(1).SetPrec(prec), bigN)

	for i := 0; i < n; i++ {
		result[i].Real = result[i].Real.Mul(result[i].Real, invN)
		result[i].Imag = result[i].Imag.Mul(result[i].Imag, invN)
	}

	return result
}

// ----------------------------------------------------------------
// bitReverseBig: compute the bit-reversal of “i” in a log2(n)-bit space.
//
//	E.g. if n=8 (log2(n)=3), then bitReverseBig(3,3) = 6 because (011)_2 → (110)_2.
//
// ----------------------------------------------------------------
func bitReverseBig(i, logN int) int {
	var rev int
	for b := 0; b < logN; b++ {
		rev = (rev << 1) | ((i >> b) & 1)
	}
	return rev
}

// --------------------------------------------------------------------------------
//
//	ConvertFromPolyBig
//
//	Given a ring.Ring “r” and a *ring.Poly “p” (in coefficient form modulo q),
//	produce a *CyclotomicFieldElem of length n=r.N in the EVAL (FFT) domain.
//	We do exactly:
//
//	    1) Read p.Coeffs[0][i] as an integer mod q, convert to float64.
//	    2) Lift to a BigComplex with (real=float64, imag=0), to high precision.
//	    3) Call FFTBig(...) on that slice of length n.
//	    4) Store the resulting *BigComplex directly into CyclotomicFieldElem.Coeffs.
//
//	Note: we do not round to float64 until *after* the FFT is done in high precision.
//
// --------------------------------------------------------------------------------
func ConvertFromPolyBig(r *ring.Ring, p *ring.Poly, prec uint) *CyclotomicFieldElem {
	n := r.N

	// 1) Build a slice of length n of *BigComplex from p.Coeffs:
	bigSlice := make([]*BigComplex, n)
	for i := 0; i < n; i++ {
		// Convert p.Coeffs[0][i] (a uint64) into a float64 in [0, q).
		f64 := ModQToFloat64(p.Coeffs[0][i], r.Modulus[0])
		// Create a BigComplex(re=f64, im=0) at precision “prec”:
		re := new(big.Float).SetPrec(prec).SetFloat64(f64)
		im := new(big.Float).SetPrec(prec).SetFloat64(0.0)
		bigSlice[i] = NewBigComplexFromFloat(re, im)
	}

	// 2) Run the high‐precision FFT (supports 2/3-smooth sizes):
	var fftResult []*BigComplex
	if isPow2(n) {
		fftResult = FFTBig(bigSlice, prec)
	} else {
		fftResult = fftAny(bigSlice, prec)
	}

	// 3) Copy the result into a new CyclotomicFieldElem (in Eval domain):
	out := NewFieldElemBig(n, prec)
	out.Domain = Eval
	for i := 0; i < n; i++ {
		out.Coeffs[i] = fftResult[i].Copy()
	}
	return out
}

// --------------------------------------------------------------------------------
//
//	ConvertToPolyBig
//
//	Given a *CyclotomicFieldElem “f” (in Eval domain), interpolate it back into
//	a *ring.Poly (coeff domain), then reduce mod q.  Steps:
//
//	  1) Take f.Coeffs[i] (each is *BigComplex), build a slice []*BigComplex.
//	  2) Call IFFTBig(...) to recover the length‐n coefficient vector (high precision).
//	  3) For each output index i: take (Real part, a *big.Float), convert to float64
//	     (via .Float64), round to nearest int64, and reduce mod q.
//
// --------------------------------------------------------------------------------
func ConvertToPolyBig(f *CyclotomicFieldElem, r *ring.Ring) *ring.Poly {
	n := f.N

	// 1) Build a slice of length n of *BigComplex (the “evaluation” values).
	evalSlice := make([]*BigComplex, n)
	for i := 0; i < n; i++ {
		evalSlice[i] = f.Coeffs[i].Copy()
	}

	// 2) Call inverse FFT at the same precision (supports 2/3-smooth sizes)
	prec := f.Coeffs[0].Real.Prec()
	var coeffSlice []*BigComplex
	if isPow2(n) {
		coeffSlice = IFFTBig(evalSlice, prec)
	} else {
		coeffSlice = ifftAny(evalSlice, prec)
	}

	// 3) Create a new ring.Poly and round each coefficient
	P := r.NewPoly()
	for i := 0; i < n && i < r.N; i++ {
		// coeffSlice[i].Real is a high‐precision big.Float
		// Convert to float64 and round to nearest integer:
		realBF := coeffSlice[i].Real
		f64, _ := realBF.Float64()   // lose some bits here, but f64 should be within ±2^53
		ri := int64(math.Round(f64)) // nearest integer
		// reduce mod q
		qi := int64(r.Modulus[0])
		ri = ((ri % qi) + qi) % qi
		P.Coeffs[0][i] = uint64(ri)
	}
	return P
}

// --------------------------------------------------------------------------------
//
//	SampleGaussianFieldElemBig
//
//	“f” is an evaluation‐domain element of length n (FFT domain).  We wish to sample
//	a cyclotomic field element whose coordinates (in Eval domain) are i.i.d.  N(0,σ²).
//	We can do that coordinate‐wise by drawing two independent Normal()’s in float64,
//	then lifting each into a BigComplex at precision “prec.”  (That is exactly what
//	your old code was doing, so no change is strictly required here.)
//
// --------------------------------------------------------------------------------
func SampleGaussianFieldElemBig(n int, sigma float64, prec uint) *CyclotomicFieldElem {
	out := NewFieldElemBig(n, prec)
	out.Domain = Eval
	for i := 0; i < n; i++ {
		re64 := rand.NormFloat64() * sigma
		im64 := rand.NormFloat64() * sigma
		re := new(big.Float).SetPrec(prec).SetFloat64(re64)
		im := new(big.Float).SetPrec(prec).SetFloat64(im64)
		out.Coeffs[i] = NewBigComplexFromFloat(re, im)
	}
	return out
}

// ----------------------------------------------------------------
// NegacyclicEvaluatePoly
//
// Given:
//   - p      : *ring.Poly in “coefficient” form (length = m = ringQ.N, mod q).
//   - ringQ  : *ring.Ring which knows m and the modulus.
//   - prec   : desired bit-precision for all BigComplex arithmetic.
//
// Returns:
//   - *CyclotomicFieldElem of length m, containing p evaluated at the
//     2m-th roots of unity “ω^{2k+1}” (i.e. a negacyclic FFT).
//
// How it works:
//  1. Zero-pad to length 2m.
//  2. Call FFTBig on that 2m-length buffer.
//  3. Extract only the odd indices (2k+1), producing an m-length slice.
//  4. Copy into a *CyclotomicFieldElem with Domain=Eval.
//
// ----------------------------------------------------------------
func NegacyclicEvaluatePoly(p *ring.Poly, ringQ *ring.Ring, prec uint) *CyclotomicFieldElem {
	// m := ring dimension = ringQ.N
	m := ringQ.N
	twoM := 2 * m

	// 1) Build a length-2m slice of *BigComplex, zero-padding after index m-1
	//    We interpret each coefficient p.Coeffs[0][i] as a signed integer in [−q/2..+q/2).

	// allocate and fill the first m entries
	A := make([]*BigComplex, twoM)
	for i := 0; i < m; i++ {
		// Convert p.Coeffs[0][i] to signed int64 in [−q/2..+q/2)
		signed := UnsignedToSigned(p.Coeffs[0][i], ringQ.Modulus[0])
		// lift to BigComplex
		reBF := new(big.Float).SetPrec(prec).SetFloat64(float64(signed))
		imBF := new(big.Float).SetPrec(prec).SetFloat64(0.0)
		A[i] = &BigComplex{Real: reBF, Imag: imBF}
	}
	// fill indices m..2m−1 with fresh zeros
	for i := m; i < twoM; i++ {
		A[i] = &BigComplex{
			Real: new(big.Float).SetPrec(prec).SetFloat64(0.0),
			Imag: new(big.Float).SetPrec(prec).SetFloat64(0.0),
		}
	}

	// 2) perform length-2m forward FFT (angle = −2π/(2m))
	var B []*BigComplex
	if isPow2(twoM) {
		B = FFTBig(A, prec)
	} else {
		B = fftAny(A, prec)
	}

	// 3) extract only the odd indices B[2k+1], k=0..m−1
	evals := make([]*BigComplex, m)
	for k := 0; k < m; k++ {
		evals[k] = B[2*k+1].Copy()
	}

	// 4) pack into a CyclotomicFieldElem in “evaluation” domain
	out := NewFieldElemBig(m, prec)
	out.Domain = Eval
	for k := 0; k < m; k++ {
		out.Coeffs[k] = evals[k]
	}
	return out
}

// ----------------------------------------------------------------
// NegacyclicInterpolateElem
//
// Given:
//   - f      : *CyclotomicFieldElem of length m, Domain=Eval (i.e. f[k] = p(ω^{2k+1})),
//     where ω = e^{2πi/(2m)}.
//   - ringQ  : *ring.Ring which knows m and the modulus.
//   - prec   : bit-precision used when f.Coeffs[*] were constructed.
//
// Returns:
//   - *ring.Poly (length = m, in coefficient form) corresponding to p(x) mod (x^m + 1).
//
// How it works:
//  1. Form a length-2m slice by inserting f.Coeffs[k] into index 2k+1, zeros at evens.
//  2. Call IFFTBig on that length-2m buffer (angle = +2π/(2m), then divide by 2m).
//  3. Take the first m BigComplex results, round Real→int, reduce mod q.
//
// ----------------------------------------------------------------
func NegacyclicInterpolateElem(f *CyclotomicFieldElem, ringQ *ring.Ring) *ring.Poly {
	// m := ring dimension = ringQ.N
	m := ringQ.N
	twoM := 2 * m

	// 1) form length-2m slice A such that A[2k+1] = f.Coeffs[k], A[even]=0
	A := make([]*BigComplex, twoM)

	prec := f.Coeffs[0].Real.Prec()
	// fill evens with distinct zeros
	for i := 0; i < twoM; i += 2 {
		A[i] = &BigComplex{
			Real: new(big.Float).SetPrec(prec).SetFloat64(0.0),
			Imag: new(big.Float).SetPrec(prec).SetFloat64(0.0),
		}
	}
	// copy f.Coeffs[k] into odd slots
	for k := 0; k < m; k++ {
		A[2*k+1] = f.Coeffs[k].Copy()
	}

	// 2) perform length-2m inverse FFT (angle = +2π/(2m), then scale by 1/(2m))
	var inv []*BigComplex
	if isPow2(twoM) {
		inv = IFFTBig(cloneBigComplexSlice(A, prec), prec)
	} else {
		inv = ifftAny(cloneBigComplexSlice(A, prec), prec)
	}

	P := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for j := 0; j < m; j++ {
		realBF := inv[j].Real
		f64, _ := realBF.Float64()

		// Multiply by 2 to undo the “÷2” that IFFTBig implicitly introduced ★
		rInt := int64(math.Round(f64 * 2.0))

		// reduce mod q into [0..q−1]
		rInt = ((rInt % q) + q) % q
		P.Coeffs[0][j] = uint64(rInt)
	}

	return P
}

// ToEvalNegacyclic converts a CyclotomicFieldElem that is currently
// in COEFF domain into the corresponding negacyclic‐FFT “Eval” form.
//   - e:      input in COEFF domain (BigComplex entries represent integers mod q).
//   - ringQ:  the ring.Ring (defines n and Modulus).
//   - prec:   desired precision (in bits) for BigFloat twiddles.
//
// Returns a fresh *CyclotomicFieldElem in Eval domain.
// Panics if e.Domain != Coeff.
func ToEvalNegacyclic(e *CyclotomicFieldElem, ringQ *ring.Ring, prec uint) *CyclotomicFieldElem {
	if e.Domain != Coeff {
		panic("ToEvalNegacyclic: input must be in Coeff domain")
	}
	n := e.N
	// 1) Build a ring.Poly by rounding each BigComplex coefficient → uint64 mod q.
	P := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i := 0; i < n && i < ringQ.N; i++ {
		// e.Coeffs[i].Real is a *big.Float that should be very close to an integer.
		realBF := e.Coeffs[i].Real
		f64, _ := realBF.Float64()
		rInt := int64(math.Round(f64))
		// reduce mod q
		rInt = ((rInt % q) + q) % q
		P.Coeffs[0][i] = uint64(rInt)
	}
	// 2) Call the negacyclic evaluator (returns an element in Eval domain).
	out := NegacyclicEvaluatePoly(P, ringQ, prec)
	// out.Domain will be Eval already, and out.Coeffs[i] is BigComplex(evaluated at e^{-iπj/n}).
	return out
}

// ToCoeffNegacyclic converts a CyclotomicFieldElem that is currently
// in negacyclic‐Eval domain back into a CyclotomicFieldElem in COEFF domain.
//   - e:      input in Eval domain (BigComplex = values at 2n-roots of −1).
//   - ringQ:  the ring.Ring (defines n and Modulus).
//   - prec:   desired precision (in bits) for the output BigComplex coefficients.
//
// Returns a fresh *CyclotomicFieldElem in Coeff domain.
// Panics if e.Domain != Eval.
func ToCoeffNegacyclic(e *CyclotomicFieldElem, ringQ *ring.Ring, prec uint) *CyclotomicFieldElem {
	if e.Domain != Eval {
		panic("ToCoeffNegacyclic: input must be in Eval domain")
	}
	n := e.N
	// 1) Inverse‐transform via NegacyclicInterpolateElem → a ring.Poly in coefficient form.
	P := NegacyclicInterpolateElem(e, ringQ)
	// 2) Copy P’s uint64 coefficients into a new CyclotomicFieldElem (in Coeff domain).
	out := NewFieldElemBig(n, prec)
	for i := 0; i < n && i < ringQ.N; i++ {
		// lift integer P.Coeffs[0][i] → BigFloat
		reBF := new(big.Float).SetPrec(prec).SetFloat64(float64(P.Coeffs[0][i]))
		imBF := new(big.Float).SetPrec(prec).SetFloat64(0.0)
		out.Coeffs[i] = NewBigComplexFromFloat(reBF, imBF)
	}
	out.Domain = Coeff
	return out
}

// Field operations
func FieldAddBig(a, b *CyclotomicFieldElem) *CyclotomicFieldElem {
	if a.N != b.N {
		panic("FieldAddBig: dimension mismatch")
	}
	res := NewFieldElemBig(a.N, a.Coeffs[0].Real.Prec())
	for i := 0; i < a.N; i++ {
		res.Coeffs[i] = a.Coeffs[i].Add(b.Coeffs[i])
	}
	return res
}

func FieldSubBig(a, b *CyclotomicFieldElem) *CyclotomicFieldElem {
	if a.N != b.N {
		panic("FieldSubBig: dimension mismatch")
	}
	res := NewFieldElemBig(a.N, a.Coeffs[0].Real.Prec())
	for i := 0; i < a.N; i++ {
		res.Coeffs[i] = a.Coeffs[i].Sub(b.Coeffs[i])
	}
	return res
}

func FieldMulBig(a, b *CyclotomicFieldElem) *CyclotomicFieldElem {
	if a.N != b.N {
		panic("FieldMulBig: dimension mismatch")
	}
	res := NewFieldElemBig(a.N, a.Coeffs[0].Real.Prec())
	for i := 0; i < a.N; i++ {
		res.Coeffs[i] = a.Coeffs[i].Mul(b.Coeffs[i])
	}
	return res
}

// Field scalar multiplication and division
type FieldScalar struct{ Val *BigComplex }

func FieldScalarMulBig(a *CyclotomicFieldElem, s *BigComplex) *CyclotomicFieldElem {
	res := NewFieldElemBig(a.N, a.Coeffs[0].Real.Prec())
	for i := 0; i < a.N; i++ {
		res.Coeffs[i] = a.Coeffs[i].Mul(s)
	}
	return res
}

func FieldScalarDiv(a *CyclotomicFieldElem, norm []*big.Float) *CyclotomicFieldElem {
	if len(norm) != a.N {
		panic("FieldScalarDiv: length mismatch")
	}
	res := NewFieldElemBig(a.N, a.Coeffs[0].Real.Prec())
	for i := 0; i < a.N; i++ {
		if norm[i].Cmp(big.NewFloat(0).SetPrec(a.Coeffs[0].Real.Prec())) == 0 {
			panic(fmt.Sprintf("division by zero norm at %d", i))
		}
		res.Coeffs[i] = a.Coeffs[i].DivBy(norm[i])
	}
	return res
}

// HermitianTransposeFieldElem computes the “polynomial transpose” f ↦ fᵗ.
//   - If f.Domain == Coeff:  fᵗ(x) = f₀ − fₙ₋₁·x − fₙ₋₂·x² − … − f₁·xⁿ⁻¹
//   - If f.Domain == Eval:   fᵗ(ζ²ⁿᵏ⁺¹) = f(ζ²ⁿ⁻(²ⁿᵏ⁺¹)) = f(ζ²ⁿ⁻(²ᵏ⁺¹)) = f(ζ²(n−k−1)+1),
//     so out.Eval[k] = in.Eval[n−k−1].
func HermitianTransposeFieldElem(f *CyclotomicFieldElem) *CyclotomicFieldElem {
	n := f.N
	prec := f.Coeffs[0].Real.Prec()
	out := NewFieldElemBig(n, prec)

	switch f.Domain {
	case Coeff:
		// Coefficient‐space transpose:
		//   out[0] = f[0],
		//   out[i] = − f[n−i],   for i = 1..n−1
		for i := 0; i < n; i++ {
			if i == 0 {
				// copy f.Coeffs[0] exactly
				out.Coeffs[0] = f.Coeffs[0].Copy()
			} else {
				// take f.Coeffs[n−i], multiply by −1
				src := f.Coeffs[n-i]
				negReal := new(big.Float).SetPrec(prec).Neg(src.Real)
				negImag := new(big.Float).SetPrec(prec).Neg(src.Imag)
				out.Coeffs[i] = &BigComplex{
					Real: negReal,
					Imag: negImag,
				}
			}
		}
		out.Domain = Coeff

	case Eval:
		// For negacyclic FFT (odd indices), the Hermitian transpose corresponds
		// to coordinate-wise complex conjugation at the same slot.
		for k := 0; k < n; k++ {
			src := f.Coeffs[k]
			out.Coeffs[k] = &BigComplex{
				Real: new(big.Float).SetPrec(prec).Copy(src.Real),
				Imag: new(big.Float).SetPrec(prec).Neg(src.Imag),
			}
		}
		out.Domain = Eval

	default:
		panic("HermitianTransposeFieldElem: unknown domain")
	}
	return out
}

// Field inverse with norms.
func FieldInverseDiagWithNorm(d *CyclotomicFieldElem) (*CyclotomicFieldElem, []*big.Float) {
	n := d.N
	// fmt.Printf("FieldInverseDiagWithNorm: n=%d, prec=%d\n", n, d.Coeffs[0].Real.Prec())
	// for i := 0; i < n; i++ {
	// 	fmt.Printf("  %d: %s + i·%s\n", i, d.Coeffs[i].Real.Text('g', 10), d.Coeffs[i].Imag.Text('g', 10))
	// }
	prec := d.Coeffs[0].Real.Prec()
	inv := NewFieldElemBig(n, prec)
	norms := make([]*big.Float, n)
	zero := new(big.Float).SetPrec(prec).SetFloat64(0)
	for i := 0; i < n; i++ {
		re := d.Coeffs[i].Real
		im := d.Coeffs[i].Imag
		re2 := new(big.Float).Mul(re, re)
		im2 := new(big.Float).Mul(im, im)
		n := new(big.Float).Add(re2, im2)
		if n.Cmp(zero) == 0 {
			panic(fmt.Sprintf("zero norm at %d", i))
		}
		conj := &BigComplex{Real: new(big.Float).Copy(re), Imag: new(big.Float).Neg(im)}
		inv.Coeffs[i] = conj
		norms[i] = n
	}
	return inv, norms
}

// PstrideBig splits even and odd coefficients.
func PstrideBig(c *CyclotomicFieldElem) (*CyclotomicFieldElem, *CyclotomicFieldElem) {
	n := c.N
	h := n / 2
	prec := c.Coeffs[0].Real.Prec()
	c0 := NewFieldElemBig(h, prec)
	c1 := NewFieldElemBig(h, prec)
	for i := 0; i < h; i++ {
		c0.Coeffs[i] = c.Coeffs[2*i]
		c1.Coeffs[i] = c.Coeffs[2*i+1]
	}
	return c0, c1
}

// SubScalar subtracts scalar from all coords.
func (f *CyclotomicFieldElem) SubScalar(c *BigComplex) {
	for i := range f.Coeffs {
		f.Coeffs[i] = f.Coeffs[i].Sub(c)
	}
}

// AddScalar adds scalar to all coords.
func (f *CyclotomicFieldElem) AddScalar(c *BigComplex) {
	for i := range f.Coeffs {
		f.Coeffs[i] = f.Coeffs[i].Add(c)
	}
}

// Copy returns a deep copy of the CyclotomicFieldElem, including all BigComplex entries
func (f *CyclotomicFieldElem) Copy() *CyclotomicFieldElem {
	// Determine precision from an existing coefficient
	prec := f.Coeffs[0].Real.Prec()

	// Allocate a new element with the same length and precision
	out := NewFieldElemBig(f.N, prec)
	out.Domain = f.Domain

	// Deep‐copy each BigComplex
	for i := 0; i < f.N; i++ {
		out.Coeffs[i] = f.Coeffs[i].Copy()
	}

	return out
}

// Conj returns the coordinate‐wise complex conjugate of a CyclotomicFieldElem.
func (f *CyclotomicFieldElem) Conj() *CyclotomicFieldElem {
	prec := f.Coeffs[0].Real.Prec()
	out := NewFieldElemBig(f.N, prec)
	out.Domain = f.Domain
	for i := 0; i < f.N; i++ {
		out.Coeffs[i] = f.Coeffs[i].Conj()
	}
	return out
}

// ToComplex converts BigComplex to built-in complex128 (losing precision).
func (b *BigComplex) ToComplex() complex128 {
	r, _ := b.Real.Float64()
	i, _ := b.Imag.Float64()
	return complex(r, i)
}

// SetCoeffs copies the coefficients from src into e and returns e.
// Panics if dimensions do not match.
func (e *CyclotomicFieldElem) SetCoeffs(src *CyclotomicFieldElem) *CyclotomicFieldElem {
	if e.N != src.N {
		panic("SetCoeffs: dimension mismatch")
	}
	for i := 0; i < e.N; i++ {
		e.Coeffs[i] = src.Coeffs[i]
	}
	return e
}

// ExtractEven returns a new CyclotomicFieldElem containing the even-indexed coefficients of e.
func (e *CyclotomicFieldElem) ExtractEven() *CyclotomicFieldElem {
	m := e.N
	half := m / 2
	out := NewFieldElemBig(half, e.Coeffs[0].Real.Prec())
	for i := 0; i < half; i++ {
		out.Coeffs[i] = e.Coeffs[2*i]
	}
	return out
}

// ExtractOdd returns a new CyclotomicFieldElem containing the odd-indexed coefficients of e.
func (e *CyclotomicFieldElem) ExtractOdd() *CyclotomicFieldElem {
	m := e.N
	half := m / 2
	out := NewFieldElemBig(half, e.Coeffs[0].Real.Prec())
	for i := 0; i < half; i++ {
		out.Coeffs[i] = e.Coeffs[2*i+1]
	}
	return out
}

func InversePermuteFieldElem(x *CyclotomicFieldElem) {
	n := x.N
	if n <= 1 {
		// nothing to permute
		return
	}
	tmp := make([]*BigComplex, n)
	half := n / 2
	e, o := 0, half
	// even positions come from the first half, odd from the second
	for i := 0; e < half; i += 2 {
		tmp[i] = x.Coeffs[e]
		tmp[i+1] = x.Coeffs[o]
		e++
		o++
	}
	copy(x.Coeffs, tmp)
}

// -----------------------------------------------------------------------------
// FloatToEvalNegacyclic
//
// Negacyclic FFT (length = 2n) on an element already in COEFF domain.
// Keeps only the odd-index frequencies so that the output represents
// evaluations at the 2n-th roots of −1:  ω^{2k+1}.
//
// Preconditions
//   - e.Domain == Coeff
//   - e.N == desired ring degree n
//   - FFTBig/IFFTBig work on []*BigComplex with precision = prec.
//
// Post-conditions
//   - returns a fresh CyclotomicFieldElem in Eval domain.
//   - coefficients are *BigComplex with *big.Float components (no rounding).
//
// -----------------------------------------------------------------------------
func FloatToEvalNegacyclic(e *CyclotomicFieldElem, prec uint) *CyclotomicFieldElem {
	if e.Domain != Coeff {
		panic("FloatToEvalNegacyclic: input must be in Coeff domain")
	}

	n := e.N
	twoN := 2 * n

	// 1) Zero-pad the coefficient vector to length 2n.
	A := make([]*BigComplex, twoN)
	for i := 0; i < n; i++ {
		A[i] = e.Coeffs[i].Copy() // deep copy to avoid mutating input
	}
	zeroBF := new(big.Float).SetPrec(prec).SetFloat64(0)
	zeroBC := &BigComplex{Real: zeroBF, Imag: zeroBF}
	for i := n; i < twoN; i++ {
		A[i] = zeroBC
	}

	// 2) Length-2n forward FFT (supports 2/3-smooth sizes).
	var B []*BigComplex
	if isPow2(twoN) {
		B = FFTBig(A, prec)
	} else {
		B = fftAny(A, prec)
	}

	// 3) Keep only the odd indices (negacyclic spectrum).
	out := NewFieldElemBig(n, prec)
	out.Domain = Eval
	for k := 0; k < n; k++ {
		out.Coeffs[k] = B[2*k+1].Copy()
	}
	return out
}

// FloatToEvalNegacyclicDirect performs a direct negacyclic DFT without using FFTs.
// Intended only for debugging to cross-check the FFT-based embedding. It uses
// float64 trig functions and thus should not be relied upon for production
// accuracy, but is sufficient to detect indexing/sign mismatches.
func FloatToEvalNegacyclicDirect(e *CyclotomicFieldElem, prec uint) *CyclotomicFieldElem {
	if e.Domain != Coeff {
		panic("FloatToEvalNegacyclicDirect: input must be in Coeff domain")
	}
	n := e.N
	out := NewFieldElemBig(n, prec)
	out.Domain = Eval
	for k := 0; k < n; k++ {
		theta := -math.Pi * float64(2*k+1) / float64(n)
		wRe, wIm := math.Cos(theta), math.Sin(theta)
		twRe, twIm := 1.0, 0.0
		sumRe, sumIm := 0.0, 0.0
		for j := 0; j < n; j++ {
			cRe, _ := e.Coeffs[j].Real.Float64()
			cIm, _ := e.Coeffs[j].Imag.Float64()
			sumRe += cRe*twRe - cIm*twIm
			sumIm += cRe*twIm + cIm*twRe
			// tw *= w
			tmpRe := twRe*wRe - twIm*wIm
			tmpIm := twRe*wIm + twIm*wRe
			twRe, twIm = tmpRe, tmpIm
		}
		out.Coeffs[k].Real.SetFloat64(sumRe)
		out.Coeffs[k].Imag.SetFloat64(sumIm)
	}
	return out
}

// -----------------------------------------------------------------------------
// FloatToCoeffNegacyclic
//
// Negacyclic inverse FFT that reconstructs the coefficient form from an
// element in Eval domain **without touching modular integers**.
//
// Preconditions
//   - e.Domain == Eval
//   - e.N == ring degree n
//   - IFFTBig scales by 1/(2n) (same as used elsewhere in the code base).
//
// Post-conditions
//   - returns a fresh CyclotomicFieldElem in Coeff domain.
//   - coefficients are *BigComplex with *big.Float components.
//
// -----------------------------------------------------------------------------
func FloatToCoeffNegacyclic(e *CyclotomicFieldElem, prec uint) *CyclotomicFieldElem {
	if e.Domain != Eval {
		panic("FloatToCoeffNegacyclic: input must be in Eval domain")
	}

	n := e.N
	twoN := 2 * n

	// 1) Embed eval values into odd slots of a length-2n buffer.
	A := make([]*BigComplex, twoN)
	zeroBF := new(big.Float).SetPrec(prec).SetFloat64(0)
	zeroBC := &BigComplex{Real: zeroBF, Imag: zeroBF}
	for i := 0; i < twoN; i += 2 {
		A[i] = zeroBC
	}
	for k := 0; k < n; k++ {
		A[2*k+1] = e.Coeffs[k].Copy()
	}

	// 2) Inverse FFT (outputs values scaled by 1/(2n)).
	var inv []*BigComplex
	if isPow2(twoN) {
		inv = IFFTBig(A, prec)
	} else {
		inv = ifftAny(A, prec)
	}

	// 3) Multiply by 2 to undo the extra ½ from the odd-slot embedding.
	two := new(big.Float).SetPrec(prec).SetFloat64(2)

	out := NewFieldElemBig(n, prec)
	out.Domain = Coeff
	for j := 0; j < n; j++ {
		out.Coeffs[j] = &BigComplex{
			Real: new(big.Float).SetPrec(prec).Mul(inv[j].Real, two),
			Imag: new(big.Float).SetPrec(prec).Mul(inv[j].Imag, two),
		}
	}
	return out
}

// FloatToCoeffNegacyclicDirect performs a direct negacyclic inverse DFT.
// Intended only for debugging to cross-check the FFT-based inverse. It uses
// float64 trig functions and should not be relied upon for production
// accuracy.
func FloatToCoeffNegacyclicDirect(e *CyclotomicFieldElem, prec uint) *CyclotomicFieldElem {
	if e.Domain != Eval {
		panic("FloatToCoeffNegacyclicDirect: input must be in Eval domain")
	}
	n := e.N
	out := NewFieldElemBig(n, prec)
	out.Domain = Coeff
	invN := 1.0 / float64(n)
	for j := 0; j < n; j++ {
		var sumRe, sumIm float64
		for k := 0; k < n; k++ {
			theta := math.Pi * float64((2*k+1)*j) / float64(n)
			wRe, wIm := math.Cos(theta), math.Sin(theta)
			yr, _ := e.Coeffs[k].Real.Float64()
			yi, _ := e.Coeffs[k].Imag.Float64()
			sumRe += yr*wRe - yi*wIm
			sumIm += yr*wIm + yi*wRe
		}
		out.Coeffs[j].Real.SetFloat64(sumRe * invN)
		out.Coeffs[j].Imag.SetFloat64(sumIm * invN)
	}
	return out
}
