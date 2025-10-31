package ntru

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/cmplx"

	ps "vSIS-Signature/Preimage_Sampler"
)

// PairNorm2 computes ||(F,G)||^2 in the embedding.
func PairNorm2(F, G []int64, par Params, prec uint) (float64, error) {
	epar := EmbedParams{Prec: prec}
	Fev, err := ToEvalCFFT(F, par, epar)
	if err != nil {
		return 0, err
	}
	Gev, err := ToEvalCFFT(G, par, epar)
	if err != nil {
		return 0, err
	}
	var sum float64
	for i := 0; i < par.N; i++ {
		sum += cmplx.Abs(Fev.V[i]) * cmplx.Abs(Fev.V[i])
		sum += cmplx.Abs(Gev.V[i]) * cmplx.Abs(Gev.V[i])
	}
	return sum, nil
}

// ifftRndCFFT implements k = RoundAway(2^(exp2-exp1) * IFFT_cfft_detwist(y)).
func ifftRndCFFT(y *ps.CyclotomicFieldElem, exp1, exp2 int, prec uint) []*big.Int {
	c := FloatToCoeffCFFT(y, prec)
	for i := 0; i < c.N; i++ {
		re, _ := c.Coeffs[i].Real.Float64()
		im, _ := c.Coeffs[i].Imag.Float64()
		tol := 1e-7 * math.Max(1, math.Abs(re))
		if math.Abs(im) > tol {
			panic(fmt.Sprintf("ifftRndCFFT: non-zero imag at %d: %g", i, im))
		}
		c.Coeffs[i].Imag.SetFloat64(0)
	}
	shift := exp2 - exp1
	if shift != 0 {
		for i := 0; i < c.N; i++ {
			mant := new(big.Float).SetPrec(prec)
			exp := c.Coeffs[i].Real.MantExp(mant)
			c.Coeffs[i].Real = new(big.Float).SetPrec(prec).SetMantExp(mant, exp+shift)
		}
	}
	k := make([]*big.Int, c.N)
	for i := 0; i < c.N; i++ {
		r := c.Coeffs[i].Real
		if r.Sign() >= 0 {
			t := new(big.Float).SetPrec(prec).SetFloat64(0.5)
			s := new(big.Float).SetPrec(prec).Add(r, t)
			k[i] = new(big.Int)
			s.Int(k[i])
		} else {
			ab := new(big.Float).SetPrec(prec).Neg(r)
			t := new(big.Float).SetPrec(prec).SetFloat64(0.5)
			s := new(big.Float).SetPrec(prec).Add(ab, t)
			bi := new(big.Int)
			s.Int(bi)
			bi.Neg(bi)
			k[i] = bi
		}
	}
	return k
}

// ReduceOnce performs a single Babai reduction step on (F,G).
// Returns updated (F2,G2), whether norm decreased, and error.
func ReduceOnce(F, G, f, g []int64, par Params, prec uint) (F2, G2 []int64, decreased bool, err error) {
	if len(F) != par.N || len(G) != par.N || len(f) != par.N || len(g) != par.N {
		return nil, nil, false, errors.New("dimension mismatch")
	}
	N := par.N
	if prec < 256 {
		prec = 256
	}
	exp1 := extraBitsInt64(f, g, 500)
	exp2 := extraBitsInt64(F, G, 500)
	loadScaled := func(a []int64, sh int) *ps.CyclotomicFieldElem {
		e := ps.NewFieldElemBig(N, prec)
		e.Domain = ps.Coeff
		for i := 0; i < N; i++ {
			v := a[i]
			if sh > 0 {
				if v >= 0 {
					v >>= sh
				} else {
					v = -((-v) >> sh)
				}
			}
			e.Coeffs[i].Real.SetInt64(v)
			e.Coeffs[i].Imag.SetInt64(0)
		}
		return e
	}
	fC := loadScaled(f, exp1)
	gC := loadScaled(g, exp1)
	FC := loadScaled(F, exp2)
	GC := loadScaled(G, exp2)
	fE := FloatToEvalCFFT(fC, prec)
	gE := FloatToEvalCFFT(gC, prec)
	FE := FloatToEvalCFFT(FC, prec)
	GE := FloatToEvalCFFT(GC, prec)
	fConj := fE.Conj()
	gConj := gE.Conj()
	den := ps.FieldAddBig(ps.FieldMulBig(fE, fConj), ps.FieldMulBig(gE, gConj))
	num := ps.FieldAddBig(ps.FieldMulBig(FE, fConj), ps.FieldMulBig(GE, gConj))
	y := ps.NewFieldElemBig(N, prec)
	y.Domain = ps.Eval
	for i := 0; i < N; i++ {
		d := den.Coeffs[i].Real
		if d.Sign() == 0 {
			return nil, nil, false, errors.New("ReduceOnce: zero denom")
		}
		y.Coeffs[i].Real.Quo(num.Coeffs[i].Real, d)
		y.Coeffs[i].Imag.Quo(num.Coeffs[i].Imag, d)
	}
	kBig := ifftRndCFFT(y, exp1, exp2, prec)
	k := make([]int64, N)
	allZero := true
	for i := 0; i < N; i++ {
		if !kBig[i].IsInt64() {
			return nil, nil, false, errors.New("ReduceOnce: k overflow")
		}
		k[i] = kBig[i].Int64()
		if k[i] != 0 {
			allZero = false
		}
	}
	if allZero {
		return append([]int64(nil), F...), append([]int64(nil), G...), false, nil
	}
	Kf, err := MulNegacyclicZZParam(k, f, par.LOG3_D)
	if err != nil {
		return nil, nil, false, err
	}
	Kg, err := MulNegacyclicZZParam(k, g, par.LOG3_D)
	if err != nil {
		return nil, nil, false, err
	}
	F2 = make([]int64, N)
	G2 = make([]int64, N)
	for i := 0; i < N; i++ {
		F2[i] = F[i] - Kf[i]
		G2[i] = G[i] - Kg[i]
	}
	n0, err := PairNorm2(F, G, par, prec)
	if err != nil {
		return nil, nil, false, err
	}
	n1, err := PairNorm2(F2, G2, par, prec)
	if err != nil {
		return nil, nil, false, err
	}
	return F2, G2, n1 < n0, nil
}

// RoundAwayFromZero is defined in rounding.go; declare here to satisfy linter.
// func RoundAwayFromZero(x float64) int64
