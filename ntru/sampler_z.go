package ntru

import (
	"math"
	mrand "math/rand"

	ps "vSIS-Signature/Preimage_Sampler"
)

// CDT table ported from antrag_opt-main/antrag/samplerZ.c (TABLE_SIZE = 13)
var cdtTable = [...]uint64{
	8562458705743934607,
	14988938141546119862,
	17705984313312429518,
	18353082494776078532,
	18439897061947435901,
	18446457975170112665,
	18446737284374178633,
	18446743982533372247,
	18446744073018029834,
	18446744073706592852,
	18446744073709544480,
	18446744073709551607,
	18446744073709551615,
}

// baseSampler draws z0 per CDT thresholds.
func baseSampler() int64 {
	r := mrand.Uint64()
	res := int64(0)
	for i := 0; i < len(cdtTable); i++ {
		if r >= cdtTable[i] {
			res++
		}
	}
	return res
}

// sampleZ implements samplerZ(u) from C using Box-Muller acceptance with parameter R.
// u is the real-valued mean (per coefficient), R is the smoothing parameter.
func sampleZ(u, R float64) int64 {
	uf := math.Floor(u)
	for {
		entropy := uint8(mrand.Intn(256))
		for i := 0; i < 8; i++ {
			z0 := baseSampler()
			b := (entropy >> uint(i)) & 1
			// z = (2*b-1)*z0 + b + uf
			sign := int64(2*int(b) - 1)
			z := float64(sign)*float64(z0) + float64(b) + uf
			x := (float64(z0*z0) - (z-u)*(z-u)) / (2 * R * R)
			p := math.Exp(x)
			// r in [0,1)
			r := (float64(mrand.Uint64()&0x1FFFFFFFFFFFFF) * math.Pow(2, -53))
			if r < p {
				return RoundAwayFromZero(z)
			}
		}
	}
}

// sampleZVec samples an integer vector around coefficient-domain means.
func sampleZVec(xCoeff *ps.CyclotomicFieldElem, R float64) ([]int64, error) {
	if xCoeff.Domain != ps.Coeff {
		return nil, ErrUnsupportedCenterDomain
	}
	n := xCoeff.N
	out := make([]int64, n)
	for i := 0; i < n; i++ {
		mu, _ := xCoeff.Coeffs[i].Real.Float64()
		out[i] = sampleZ(mu, R)
	}
	return out, nil
}

// ErrUnsupportedCenterDomain returned when coefficient centers are not in Coeff domain.
var ErrUnsupportedCenterDomain = fmtError("unsupported center domain for sampleZVec")

type fmtError string

func (e fmtError) Error() string { return string(e) }
