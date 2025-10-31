package ntru

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"sync"

	ps "vSIS-Signature/Preimage_Sampler"
)

// EmbedParams controls precision and optional symmetry enforcement for the embedding.
type EmbedParams struct {
	Prec uint
	Real bool
}

// EvalVec holds evaluation-domain values.
type EvalVec struct {
	V []complex128
}

// CoeffVec holds integer coefficients in coefficient domain.
type CoeffVec struct {
	Int []int64
}

// Debug-only embedding flavor tagging ("cfft"). Helps catch mixed embeddings early.
var flavorMu sync.Mutex
var flavorTag = map[*ps.CyclotomicFieldElem]string{}

func markFlavorCFFT(e *ps.CyclotomicFieldElem) {
	if !debugOn || e == nil {
		return
	}
	flavorMu.Lock()
	flavorTag[e] = "cfft"
	flavorMu.Unlock()
}

func flavorOf(e *ps.CyclotomicFieldElem) string {
	if !debugOn || e == nil {
		return ""
	}
	flavorMu.Lock()
	f := flavorTag[e]
	flavorMu.Unlock()
	return f
}

func assertSameFlavor(where string, es ...*ps.CyclotomicFieldElem) {
	if !debugOn {
		return
	}
	if len(es) == 0 {
		return
	}
	f0 := flavorOf(es[0])
	for _, e := range es[1:] {
		if flavorOf(e) != f0 {
			panic(fmt.Sprintf("embedding flavor mismatch at %s: got %q and %q", where, f0, flavorOf(e)))
		}
	}
}

func ensurePrec(e EmbedParams) uint {
	if e.Prec == 0 {
		return 128
	}
	return e.Prec
}

// psiTwiddlesBig precomputes psi^j and psi^{-j} for j=0..N-1 with psi = exp(-i*pi/N).
func psiTwiddlesBig(N int, prec uint) (psiPow, psiInvPow []*ps.BigComplex) {
	theta := -math.Pi / float64(N)
	c := math.Cos(theta)
	s := math.Sin(theta)
	psi := ps.NewBigComplexFromFloat(
		new(big.Float).SetPrec(prec).SetFloat64(c),
		new(big.Float).SetPrec(prec).SetFloat64(s),
	)
	psiInv := ps.NewBigComplexFromFloat(
		new(big.Float).SetPrec(prec).SetFloat64(c),
		new(big.Float).SetPrec(prec).Neg(new(big.Float).SetPrec(prec).SetFloat64(s)),
	)
	psiPow = make([]*ps.BigComplex, N)
	psiInvPow = make([]*ps.BigComplex, N)
	one := ps.NewBigComplexFromFloat(new(big.Float).SetPrec(prec).SetFloat64(1), new(big.Float).SetPrec(prec).SetFloat64(0))
	psiPow[0] = one.Copy()
	psiInvPow[0] = one.Copy()
	for j := 1; j < N; j++ {
		psiPow[j] = psiPow[j-1].Mul(psi)
		psiInvPow[j] = psiInvPow[j-1].Mul(psiInv)
	}
	return
}

// FloatToEvalCFFT twists coefficients by psi^j and applies a length-N FFT.
func FloatToEvalCFFT(e *ps.CyclotomicFieldElem, prec uint) *ps.CyclotomicFieldElem {
	if e.Domain != ps.Coeff {
		panic("FloatToEvalCFFT: need Coeff domain")
	}
	N := e.N
	psiPow, _ := psiTwiddlesBig(N, prec)
	tmp := make([]*ps.BigComplex, N)
	for j := 0; j < N; j++ {
		tmp[j] = e.Coeffs[j].Mul(psiPow[j])
	}
	vals := ps.FFTAnyBig(tmp, prec)
	out := ps.NewFieldElemBig(N, prec)
	out.Domain = ps.Eval
	for i := 0; i < N; i++ {
		out.Coeffs[i] = vals[i].Copy()
	}
	markFlavorCFFT(out)
	return out
}

// FloatToCoeffCFFT applies an inverse FFT and detwists by psi^{-j}.
func FloatToCoeffCFFT(e *ps.CyclotomicFieldElem, prec uint) *ps.CyclotomicFieldElem {
	if e.Domain != ps.Eval {
		panic("FloatToCoeffCFFT: need Eval domain")
	}
	N := e.N
	_, psiInvPow := psiTwiddlesBig(N, prec)
	vals := make([]*ps.BigComplex, N)
	for i := 0; i < N; i++ {
		vals[i] = e.Coeffs[i].Copy()
	}
	coeffTw := ps.IFFTAnyBig(vals, prec)
	out := ps.NewFieldElemBig(N, prec)
	out.Domain = ps.Coeff
	for j := 0; j < N; j++ {
		out.Coeffs[j] = coeffTw[j].Mul(psiInvPow[j])
	}
	return out
}

// ToEvalCFFT maps integer coefficients to their twisted cFFT evaluations.
func ToEvalCFFT(coeffs []int64, par Params, epar EmbedParams) (EvalVec, error) {
	if len(coeffs) != par.N {
		return EvalVec{}, errors.New("dimension mismatch")
	}
	prec := ensurePrec(epar)
	cf := ps.NewFieldElemBig(par.N, prec)
	cf.Domain = ps.Coeff
	for i, c := range coeffs {
		cf.Coeffs[i].Real.SetInt64(c)
		cf.Coeffs[i].Imag.SetInt64(0)
	}
	ev := FloatToEvalCFFT(cf, prec)
	out := make([]complex128, par.N)
	for i := 0; i < par.N; i++ {
		re, _ := ev.Coeffs[i].Real.Float64()
		im, _ := ev.Coeffs[i].Imag.Float64()
		out[i] = complex(re, im)
	}
	return EvalVec{V: out}, nil
}

// ToCoeffIntCFFT maps twisted cFFT evaluations back to integer coefficients.
func ToCoeffIntCFFT(ev EvalVec, par Params, epar EmbedParams) (CoeffVec, error) {
	if len(ev.V) != par.N {
		return CoeffVec{}, errors.New("dimension mismatch")
	}
	prec := ensurePrec(epar)
	ef := ps.NewFieldElemBig(par.N, prec)
	ef.Domain = ps.Eval
	for i, z := range ev.V {
		ef.Coeffs[i].Real.SetFloat64(real(z))
		ef.Coeffs[i].Imag.SetFloat64(imag(z))
	}
	cf := FloatToCoeffCFFT(ef, prec)
	out := make([]int64, par.N)
	for i := 0; i < par.N; i++ {
		r, _ := cf.Coeffs[i].Real.Float64()
		out[i] = RoundAwayFromZero(r)
	}
	return CoeffVec{Int: out}, nil
}

// ToEval maps integer coefficients to their canonical embedding.
func ToEval(coeffs []int64, par Params, epar EmbedParams) (EvalVec, error) {
	dbg(os.Stderr, "[Embed] ToEval begin N=%d\n", par.N)
	if len(coeffs) != par.N {
		return EvalVec{}, errors.New("dimension mismatch")
	}
	N := par.N
	prec := ensurePrec(epar)
	cf := ps.NewFieldElemBig(N, prec)
	// Explicitly mark coefficient domain to mirror the C reference helpers.
	cf.Domain = ps.Coeff
	for i, c := range coeffs {
		cf.Coeffs[i].Real.SetInt64(c)
		cf.Coeffs[i].Imag.SetInt64(0)
	}
	ev := FloatToEvalCFFT(cf, prec)
	out := make([]complex128, N)
	for i := 0; i < N; i++ {
		re, _ := ev.Coeffs[i].Real.Float64()
		im, _ := ev.Coeffs[i].Imag.Float64()
		out[i] = complex(re, im)
	}
	dbg(os.Stderr, "[Embed] ToEval done\n")
	return EvalVec{V: out}, nil
}

// ToCoeffInt maps evaluation-domain values to integer coefficients using ties-away-from-zero rounding.
func ToCoeffInt(ev EvalVec, par Params, epar EmbedParams) (CoeffVec, error) {
	if len(ev.V) != par.N {
		return CoeffVec{}, errors.New("dimension mismatch")
	}
	prec := ensurePrec(epar)
	N := par.N
	ef := ps.NewFieldElemBig(N, prec)
	ef.Domain = ps.Eval
	for i, z := range ev.V {
		ef.Coeffs[i].Real.SetFloat64(real(z))
		ef.Coeffs[i].Imag.SetFloat64(imag(z))
	}
	cf := FloatToCoeffCFFT(ef, prec)
	out := make([]int64, N)
	for i := 0; i < N; i++ {
		re, _ := cf.Coeffs[i].Real.Float64()
		out[i] = RoundAwayFromZero(re)
	}
	return CoeffVec{Int: out}, nil
}

// ToEvalFloat maps centered float coefficients to Eval domain.
func ToEvalFloat(coeffs []float64, par Params, epar EmbedParams) (EvalVec, error) {
	if len(coeffs) != par.N {
		return EvalVec{}, errors.New("dimension mismatch")
	}
	prec := ensurePrec(epar)
	cf := ps.NewFieldElemBig(par.N, prec)
	cf.Domain = ps.Coeff
	for i, c := range coeffs {
		cf.Coeffs[i].Real.SetFloat64(c)
		cf.Coeffs[i].Imag.SetInt64(0)
	}
	ev := FloatToEvalCFFT(cf, prec)
	out := make([]complex128, par.N)
	for i := 0; i < par.N; i++ {
		re, _ := ev.Coeffs[i].Real.Float64()
		im, _ := ev.Coeffs[i].Imag.Float64()
		out[i] = complex(re, im)
	}
	return EvalVec{V: out}, nil
}

// ToCoeffFloat maps Eval domain values to floats without rounding.
func ToCoeffFloat(ev EvalVec, par Params, epar EmbedParams) ([]float64, error) {
	if len(ev.V) != par.N {
		return nil, errors.New("dimension mismatch")
	}
	prec := ensurePrec(epar)
	ef := ps.NewFieldElemBig(par.N, prec)
	ef.Domain = ps.Eval
	for i, z := range ev.V {
		ef.Coeffs[i].Real.SetFloat64(real(z))
		ef.Coeffs[i].Imag.SetFloat64(imag(z))
	}
	cf := FloatToCoeffCFFT(ef, prec)
	out := make([]float64, par.N)
	for i := 0; i < par.N; i++ {
		out[i], _ = cf.Coeffs[i].Real.Float64()
	}
	return out, nil
}

// EmbeddingNorms returns per-embedding squared magnitudes for f and optionally f+g.
func EmbeddingNorms(f []int64, g []int64, par Params, epar EmbedParams) (f2 []float64, fg2 []float64, err error) {
	fev, err := ToEval(f, par, epar)
	if err != nil {
		return nil, nil, err
	}
	f2 = make([]float64, par.N)
	for i, z := range fev.V {
		f2[i] = real(z)*real(z) + imag(z)*imag(z)
	}
	if g != nil {
		gev, err := ToEval(g, par, epar)
		if err != nil {
			return nil, nil, err
		}
		fg2 = make([]float64, par.N)
		for i := 0; i < par.N; i++ {
			z := gev.V[i]
			fg2[i] = f2[i] + real(z)*real(z) + imag(z)*imag(z)
		}
	}
	return f2, fg2, nil
}

// SlotSumsSquared computes per-slot |phi_i(f)|^2 + |phi_i(g)|^2 along with min/max.
func SlotSumsSquared(f, g []int64, par Params, epar EmbedParams) (S []float64, Smin, Smax float64, err error) {
	if len(f) != par.N || len(g) != par.N {
		return nil, 0, 0, errors.New("dimension mismatch")
	}
	fev, err := ToEval(f, par, epar)
	if err != nil {
		return nil, 0, 0, err
	}
	gev, err := ToEval(g, par, epar)
	if err != nil {
		return nil, 0, 0, err
	}
	S = make([]float64, par.N)
	for i := 0; i < par.N; i++ {
		fr, fi := real(fev.V[i]), imag(fev.V[i])
		gr, gi := real(gev.V[i]), imag(gev.V[i])
		val := fr*fr + fi*fi + gr*gr + gi*gi
		S[i] = val
		if i == 0 || val < Smin {
			Smin = val
		}
		if i == 0 || val > Smax {
			Smax = val
		}
	}
	return S, Smin, Smax, nil
}

// AlphaWindowOK checks that all S_i lie within [q/alpha^2, alpha^2 * q].
func AlphaWindowOK(S []float64, q uint64, alpha float64) bool {
	up := alpha * alpha * float64(q)
	low := float64(q) / (alpha * alpha)
	for _, s := range S {
		if s < low || s > up {
			return false
		}
	}
	return true
}
