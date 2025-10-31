// discrete_gaussian.go
// Implements Palisade’s DiscreteGaussianGenerator in Go, with both
// Peikert inversion‐sampling and Karney exact rejection sampling.
// See: “Sampling exactly from the discrete Gaussian” (Karney ’13)
//      and Peikert ’14 DG14 inversion method.

package Preimage_Sampler

import (
	"math"
	"math/rand"
	"sort"
)

const (
	karneyThreshold = 300.0 // σ above which we use Karney’s sampler
	acc             = 5e-32 // tail‐mass accuracy for inversion CDF
)

// ForceZero controls whether DiscreteGaussian.Draw always returns 0.
// It is meant for deterministic testing only.
var ForceZero bool

// SetForceZero toggles deterministic zero sampling for tests.
func SetForceZero(b bool) {
	ForceZero = b
}

// DiscreteGaussian encapsulates a sampler for D_ℤ(mean, σ).
type DiscreteGaussian struct {
	sigma   float64   // stddev
	peikert bool      // true ⇒ do inversion sampling
	a       float64   // mass at zero = 1/∑_{x=-M}^M e^{-x^2/(2σ²)}
	cdf     []float64 // cumulative probabilities for x=1…M (only if peikert)
}

// NewDiscreteGaussian constructs a DGG with stddev σ.
// Panics if σ too large (>2^59), as in Palisade.
func NewDiscreteGaussian(std float64) *DiscreteGaussian {
	if math.Log2(std) > 59 {
		panic("DiscreteGaussian: standard deviation cannot exceed 59 bits")
	}
	dg := &DiscreteGaussian{sigma: std}
	dg.peikert = (std < karneyThreshold)
	if dg.peikert {
		dg.initialize()
	}
	return dg
}

// initialize precomputes the CDF for inversion sampling (Peikert ’14).
func (dg *DiscreteGaussian) initialize() {
	variance := dg.sigma * dg.sigma
	// M ≈ ceil(σ * sqrt(-2 ln(acc)))
	M := int(math.Ceil(dg.sigma * math.Sqrt(-2*math.Log(acc))))
	// compute normalization: sum_{x=-M..M} e^{-x²/(2σ²)}
	sum := 1.0
	for x := 1; x <= M; x++ {
		sum += 2 * math.Exp(-float64(x*x)/(2*variance))
	}
	dg.a = 1 / sum
	// build cdf for x=1…M
	dg.cdf = make([]float64, M)
	for x := 1; x <= M; x++ {
		p := dg.a * math.Exp(-float64(x*x)/(2*variance))
		if x == 1 {
			dg.cdf[x-1] = p
		} else {
			dg.cdf[x-1] = dg.cdf[x-2] + p
		}
	}
}

// Draw samples one integer ∼ D_ℤ(mean, σ).
func (dg *DiscreteGaussian) Draw(mean float64) int64 {
	if ForceZero {
		return 0
	}
	if dg.peikert {
		// inversion sampling
		u := rand.Float64() - 0.5
		if math.Abs(u) <= dg.a/2 {
			return int64(math.Round(mean))
		}
		target := math.Abs(u) - dg.a/2
		idx := sort.SearchFloat64s(dg.cdf, target)
		sample := int64(idx + 1)
		if u < 0 {
			sample = -sample
		}
		return sample + int64(math.Round(mean))
	}
	// Karney’s exact sampler
	return karney(mean, dg.sigma)
}

// karney implements Algorithm 4 (steps D1–D8) from Karney ’13.
func karney(mean, sigma float64) int64 {
	for {
		k := algoG()
		if !algoP(k * (k - 1)) {
			continue
		}
		s := 1
		if rand.Intn(2) == 0 {
			s = -1
		}
		di0 := sigma*float64(k) + float64(s)*mean
		i0 := math.Ceil(di0)
		x0 := (i0 - di0) / sigma
		j := rand.Int63n(int64(math.Ceil(sigma)))
		x := x0 + float64(j)/sigma
		if !(x < 1) || (x == 0 && s < 0 && k == 0) {
			continue
		}
		// D7: must get k+1 true returns from algoB before accepting
		passed := true
		for i := 0; i < k+1; i++ {
			if !algoB(k, float32(x)) {
				passed = false
				break
			}
		}
		if !passed {
			continue
		}
		// D8: accept
		return int64(s) * (int64(i0) + j)
	}
}

// algoH: one Bernoulli trial, uses float32 for speed.
func algoH() bool {
	h_a := rand.Float32()
	if h_a > 0.5 {
		return true
	}
	if h_a < 0.5 {
		for {
			h_b := rand.Float32()
			if h_b > h_a {
				return false
			}
			if h_b < h_a {
				h_a = rand.Float32()
			} else {
				return algoHDouble()
			}
			if h_a > h_b {
				return true
			}
			if h_a == h_b {
				return algoHDouble()
			}
		}
	}
	return algoHDouble()
}

// algoHDouble: high‐precision fallback for H.
func algoHDouble() bool {
	h_a := rand.Float64()
	if !(h_a < 0.5) {
		return true
	}
	for {
		h_b := rand.Float64()
		if !(h_b < h_a) {
			return false
		}
		h_a = rand.Float64()
		if !(h_a < h_b) {
			return true
		}
	}
}

// algoG: count consecutive successes of H.
func algoG() int {
	n := 0
	for algoH() {
		n++
	}
	return n
}

// algoP: accept k(k-1) trials of H.
func algoP(n int) bool {
	for i := 0; i < n; i++ {
		if !algoH() {
			return false
		}
	}
	return true
}

// algoB: inner Bernoulli‐rejection of Karney, using float32.
func algoB(k int, x float32) bool {
	y := x
	m := 2*k + 2
	n := 0
	for {

		z := rand.Float32()
		if z > y {
			break
		}
		if z < y {
			r := rand.Float32()
			rTemp := (2*float32(k) + x) / float32(m)
			if r > rTemp {
				break
			}
			if r < rTemp {
				y = z
				n++
				continue
			}
			return algoBDouble(k, x)
		}
		return algoBDouble(k, x)
	}
	return n%2 == 0
}

// algoBDouble: high‐precision fallback for B.
func algoBDouble(k int, x float32) bool {
	y := x
	m := 2*k + 2
	n := 0
	for {
		// Step D5‐D6 double‐precision version
		z := rand.Float64()
		if !(z < float64(y)) {
			break
		}
		r := rand.Float64()
		// CORRECT: r < (2*k + x)/m
		if !(r < (float64(2*k)+float64(x))/float64(m)) {
			break
		}
		// update y for the next inner‐loop trial
		y = float32(z)
		n++
	}
	return n%2 == 0
}
