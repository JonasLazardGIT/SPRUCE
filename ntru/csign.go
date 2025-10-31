package ntru

import (
	"math/big"
	ps "vSIS-Signature/Preimage_Sampler"
)

// recenterModQ returns centered int64 coefficients from a ModQPoly.
func recenterModQ(p ModQPoly, par Params) []int64 {
	xs, _ := CenterModQToInt64(p, par)
	return xs
}

// Residual bound computations using big.Float for high precision
func gammaSqBig(par Params, opts SamplerOpts) *big.Float {
	prec := opts.Prec
	if prec == 0 {
		prec = 256
	}
	qBF := new(big.Float).SetPrec(prec).SetInt(par.Q)
	alphaBF := new(big.Float).SetPrec(prec).SetFloat64(opts.Alpha)
	alphaSq := new(big.Float).SetPrec(prec).Mul(alphaBF, alphaBF)
	rBF := new(big.Float).SetPrec(prec).SetFloat64(opts.RSquare)
	sigmaSq := new(big.Float).SetPrec(prec).Mul(rBF, alphaSq)
	sigmaSq.Mul(sigmaSq, qBF)
	slackBF := new(big.Float).SetPrec(prec).SetFloat64(opts.Slack)
	slackSq := new(big.Float).SetPrec(prec).Mul(slackBF, slackBF)
	gammaSq := new(big.Float).SetPrec(prec).Mul(slackSq, sigmaSq)
	two := new(big.Float).SetPrec(prec).SetInt64(2)
	nBF := new(big.Float).SetPrec(prec).SetInt64(int64(par.N))
	twoN := new(big.Float).SetPrec(prec).Mul(two, nBF)
	gammaSq.Mul(gammaSq, twoN)
	return gammaSq
}

func normSumBig(s1, s2 []int64, par Params, opts SamplerOpts) *big.Float {
	prec := opts.Prec
	if prec == 0 {
		prec = 256
	}
	sum := new(big.Float).SetPrec(prec).SetInt64(0)
	tmpA := new(big.Float).SetPrec(prec)
	tmpB := new(big.Float).SetPrec(prec)
	term := new(big.Float).SetPrec(prec)
	for i := 0; i < par.N; i++ {
		tmpA.SetInt64(s1[i])
		term.Mul(tmpA, tmpA)
		sum.Add(sum, term)
		tmpB.SetInt64(s2[i])
		term.Mul(tmpB, tmpB)
		sum.Add(sum, term)
	}
	if opts.UseLog3Cross {
		half := par.N / 2
		for i := 0; i < half; i++ {
			tmpA.SetInt64(s1[i])
			tmpB.SetInt64(s1[i+half])
			term.Mul(tmpA, tmpB)
			sum.Add(sum, term)
			tmpA.SetInt64(s2[i])
			tmpB.SetInt64(s2[i+half])
			term.Mul(tmpA, tmpB)
			sum.Add(sum, term)
		}
	}
	return sum
}

// CoefficientNormSquared returns the coefficient-domain norm sum used by CheckNormC as a float64.
func CoefficientNormSquared(s1, s2 []int64, par Params, opts SamplerOpts) float64 {
	if len(s1) < par.N || len(s2) < par.N {
		return 0
	}
	sum := normSumBig(s1, s2, par, opts)
	f, _ := sum.Float64()
	return f
}

// CheckNormC mimics antrag/sign.c check_norm without cross terms.
// s1, s2 are centered coefficient vectors.
func CheckNormC(s1, s2 []int64, par Params, opts SamplerOpts) bool {
	if len(s1) < par.N || len(s2) < par.N {
		return false
	}
	if opts.RSquare <= 0 || opts.Alpha <= 0 || opts.Slack <= 0 {
		return false
	}
	if opts.Prec == 0 {
		opts.Prec = 256
	}
	sum := normSumBig(s1, s2, par, opts)
	gammaSq := gammaSqBig(par, opts)
	return sum.Cmp(gammaSq) <= 0
}

// ps helper constructors
func psZeroCoeff(n int, prec uint) *ps.CyclotomicFieldElem {
	z := ps.NewFieldElemBig(n, prec)
	z.Domain = ps.Coeff
	return z
}
func psFromInt64Coeff(xs []int64, prec uint) *ps.CyclotomicFieldElem {
	n := len(xs)
	z := ps.NewFieldElemBig(n, prec)
	z.Domain = ps.Coeff
	for i := 0; i < n; i++ {
		z.Coeffs[i].Real.SetFloat64(float64(xs[i]))
		z.Coeffs[i].Imag.SetFloat64(0)
	}
	return z
}

// CentersFromSyndrome returns c0=0 and c1 from a ModQ syndrome (coeff domain).
func (S *Sampler) CentersFromSyndrome(c2 ModQPoly) (*ps.CyclotomicFieldElem, *ps.CyclotomicFieldElem) {
	c0 := psZeroCoeff(S.Par.N, S.Prec)
	c1 := psFromInt64Coeff(recenterModQ(c2, S.Par), S.Prec)
	return c0, c1
}
