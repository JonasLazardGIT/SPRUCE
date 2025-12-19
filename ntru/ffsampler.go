package ntru

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"math/cmplx"
	mrand "math/rand"
	"os"

	ps "vSIS-Signature/Preimage_Sampler"
)

// Sampler implements an ff-style lattice sampler for the NTRU trapdoor.
type Sampler struct {
	Par  Params
	EPar EmbedParams

	f, g, F, G []int64 // trapdoor polynomials (coeff domain)

	lastS2 []int64 // cached centered residual from latest SamplePreimageTargetOptionB

	// cached Eval-domain representations of f,g,F,G
	fev, gev EvalVec
	Fev, Gev EvalVec

	// precomputed Gram matrix entries in Eval domain
	a, d *ps.CyclotomicFieldElem
	b    *ps.CyclotomicFieldElem

	// per-slot Schur complement
	lam2 []float64

	// Eval-domain basis components and GSO/Beta caches (C-style orientation)
	// We follow the reference: b1 = (g, -f), b2 = (G, -F).
	b10, b11       *ps.CyclotomicFieldElem // b1 = (g,-f)
	b20, b21       *ps.CyclotomicFieldElem // b2 = (G,-F)
	gb20, gb21     *ps.CyclotomicFieldElem // ~b2 components
	beta10, beta11 *ps.CyclotomicFieldElem // betahat_1 components
	beta20, beta21 *ps.CyclotomicFieldElem // betahat_2 components

	// per-slot norms of ~b1 and ~b2
	norm1 []float64
	norm2 []float64

	// per-slot sigmas for C-style sampler
	sigma1 []float64
	sigma2 []float64

	// options
	Opts SamplerOpts

	Prec uint
}

// LastS2 returns a copy of the most recent centered residual s2 captured during
// SamplePreimageTargetOptionB. The slice is nil if no OptionB preimage was
// produced since sampler construction or the last error.
func (S *Sampler) LastS2() []int64 {
	if len(S.lastS2) == 0 {
		return nil
	}
	return append([]int64(nil), S.lastS2...)
}

// NewSampler constructs a Sampler from a valid NTRU trapdoor (f,g,F,G).
func NewSampler(f, g, F, G []int64, par Params, prec uint) (*Sampler, error) {
	if len(f) != par.N || len(g) != par.N || len(F) != par.N || len(G) != par.N {
		return nil, errors.New("dimension mismatch")
	}
	// Enforce stable numerics: floor embedding precision to at least 256 bits
	if prec < 256 {
		prec = 256
	}
	s := &Sampler{
		Par:  par,
		EPar: EmbedParams{Prec: prec},
		f:    append([]int64(nil), f...),
		g:    append([]int64(nil), g...),
		F:    append([]int64(nil), F...),
		G:    append([]int64(nil), G...),
		Prec: prec,
	}
	dbg(os.Stderr, "[Sampler] NewSampler N=%d Q=%s Prec=%d\n", par.N, par.Q.String(), prec)
	s.Opts.Prec = prec
	if s.Opts.SigmaScale == 0 {
		s.Opts.SigmaScale = 1.0
	}
	if s.Opts.RSquare <= 0 {
		s.Opts.RSquare = CReferenceRSquare()
	}
	// Default to the C-style Box–Muller complex sampler unless callers override it.
	if !s.Opts.UseCNormalDist {
		s.Opts.UseCNormalDist = true
	}
	dbg(os.Stderr, "[Sampler] precomputeEval begin\n")
	if err := s.precomputeEval(); err != nil {
		return nil, err
	}
	dbg(os.Stderr, "[Sampler] precomputeEval done\n")
	return s, nil
}

// ReduceTrapdoor applies repeated Babai reductions on (F,G) to decrease the
// embedding norm, updating cached Eval-domain views. Returns at first non-decrease
// or after maxIters.
func (S *Sampler) ReduceTrapdoor(maxIters int) error {
	if maxIters <= 0 {
		return nil
	}
	F := append([]int64(nil), S.F...)
	G := append([]int64(nil), S.G...)
	for i := 0; i < maxIters; i++ {
		F2, G2, dec, err := ReduceOnce(F, G, S.f, S.g, S.Par, S.Prec)
		if err != nil {
			return err
		}
		F, G = F2, G2
		if !dec {
			break
		}
	}
	S.F, S.G = F, G
	// Refresh cached Eval-domain polys
	return S.precomputeEval()
}

// precomputeEval caches evaluation-domain views of f,g,F,G.
func (S *Sampler) precomputeEval() error {
	var err error
	if S.fev, err = ToEvalCFFT(S.f, S.Par, S.EPar); err != nil {
		return err
	}
	if S.gev, err = ToEvalCFFT(S.g, S.Par, S.EPar); err != nil {
		return err
	}
	if S.Fev, err = ToEvalCFFT(S.F, S.Par, S.EPar); err != nil {
		return err
	}
	if S.Gev, err = ToEvalCFFT(S.G, S.Par, S.EPar); err != nil {
		return err
	}
	return nil
}

// BuildGram precomputes the Gram matrix entries (a,b,d) in Eval domain.
func (S *Sampler) BuildGram() error {
	dbg(os.Stderr, "[Sampler] BuildGram begin\n")
	par := S.Par
	N := par.N
	prec := S.Prec

	fev, gev, Fev, Gev := S.fev, S.gev, S.Fev, S.Gev

	fB := ps.NewFieldElemBig(N, prec)
	gB := ps.NewFieldElemBig(N, prec)
	FB := ps.NewFieldElemBig(N, prec)
	GB := ps.NewFieldElemBig(N, prec)
	fB.Domain, gB.Domain, FB.Domain, GB.Domain = ps.Eval, ps.Eval, ps.Eval, ps.Eval

	for i := 0; i < N; i++ {
		fB.Coeffs[i].Real.SetFloat64(real(fev.V[i]))
		fB.Coeffs[i].Imag.SetFloat64(imag(fev.V[i]))
		gB.Coeffs[i].Real.SetFloat64(real(gev.V[i]))
		gB.Coeffs[i].Imag.SetFloat64(imag(gev.V[i]))
		FB.Coeffs[i].Real.SetFloat64(real(Fev.V[i]))
		FB.Coeffs[i].Imag.SetFloat64(imag(Fev.V[i]))
		GB.Coeffs[i].Real.SetFloat64(real(Gev.V[i]))
		GB.Coeffs[i].Imag.SetFloat64(imag(Gev.V[i]))
	}

	// Coordinate-wise complex conjugates in Eval domain
	gConj := gB.Conj()
	fConj := fB.Conj()
	GConj := GB.Conj()
	FConj := FB.Conj()

	// Per-slot Gram entries for b1=(g,-f), b2=(G,-F):
	// d = <b1,b1> = ||g||^2 + ||f||^2
	// a = <b2,b2> = ||G||^2 + ||F||^2
	// b = <b1,b2> = g*conj(G) + f*conj(F)
	gg := ps.FieldMulBig(gB, gConj)
	ff := ps.FieldMulBig(fB, fConj)
	GG := ps.FieldMulBig(GB, GConj)
	FF := ps.FieldMulBig(FB, FConj)
	S.d = ps.FieldAddBig(gg, ff)
	S.d.Domain = ps.Eval
	S.a = ps.FieldAddBig(GG, FF)
	S.a.Domain = ps.Eval
	gGc := ps.FieldMulBig(gB, GConj)
	fFc := ps.FieldMulBig(fB, FConj)
	S.b = ps.FieldAddBig(gGc, fFc)
	S.b.Domain = ps.Eval

	S.lam2 = make([]float64, N)
	const tol = 1e-7
	for i := 0; i < N; i++ {
		aiBF := S.a.Coeffs[i].Real // a = ||(G,-F)||^2 = ||G||^2 + ||F||^2
		diBF := S.d.Coeffs[i].Real // d = ||(g,-f)||^2 = ||g||^2 + ||f||^2
		brBF := S.b.Coeffs[i].Real // b (real)
		biBF := S.b.Coeffs[i].Imag // b (imag)
		if aiBF.Sign() <= 0 || diBF.Sign() <= 0 {
			return fmt.Errorf("non-positive Gram diag at slot %d", i)
		}
		// lam2 for two-step ffSampling with Beta2 = conj(b)/d: lam2 = a - |b|^2/d
		br2 := new(big.Float).Mul(brBF, brBF)
		bi2 := new(big.Float).Mul(biBF, biBF)
		num := new(big.Float).Add(br2, bi2)
		quot := new(big.Float).Quo(num, diBF)
		lam2BF := new(big.Float).Sub(aiBF, quot)
		lam2Abs := new(big.Float).Abs(lam2BF)
		aiAbs := new(big.Float).Abs(aiBF)
		scale := new(big.Float).SetFloat64(1)
		if aiAbs.Cmp(scale) > 0 {
			scale = aiAbs
		}
		scale.Mul(scale, big.NewFloat(tol))
		if lam2BF.Sign() < 0 {
			if lam2Abs.Cmp(scale) > 0 {
				lam2, _ := lam2BF.Float64()
				return fmt.Errorf("non-positive lam2 at slot %d (%.3e)", i, lam2)
			}
			lam2BF = lam2Abs
		}
		detBF := new(big.Float).Mul(diBF, lam2BF) // det = d * lam2 (consistent ordering)
		detAbs := new(big.Float).Abs(detBF)
		diAbs := new(big.Float).Abs(diBF)
		detScale := new(big.Float).Mul(aiAbs, diAbs)
		detScale.Mul(detScale, big.NewFloat(tol))
		if detBF.Sign() < 0 && detAbs.Cmp(detScale) > 0 {
			det, _ := detBF.Float64()
			return fmt.Errorf("non-positive det at slot %d (%.3e)", i, det)
		}
		ai, _ := aiBF.Float64()
		di, _ := diBF.Float64()
		br, _ := brBF.Float64()
		bi, _ := biBF.Float64()
		lam2f, _ := lam2BF.Float64()
		if lam2f < 0 {
			lam2f = math.Abs(lam2f)
		}
		S.lam2[i] = lam2f
		gi, Gi := S.gev.V[i], S.Gev.V[i]
		fi, Fi := S.fev.V[i], S.Fev.V[i]
		wantA := cmplx.Abs(Gi)*cmplx.Abs(Gi) + cmplx.Abs(Fi)*cmplx.Abs(Fi)
		wantD := cmplx.Abs(gi)*cmplx.Abs(gi) + cmplx.Abs(fi)*cmplx.Abs(fi)
		wantB := gi*cmplx.Conj(Gi) + fi*cmplx.Conj(Fi)
		if math.Abs(ai-wantA) > tol*math.Max(1, math.Abs(wantA)) ||
			math.Abs(di-wantD) > tol*math.Max(1, math.Abs(wantD)) ||
			math.Abs(br-real(wantB)) > tol*math.Max(1, math.Abs(real(wantB))) ||
			math.Abs(bi-imag(wantB)) > tol*math.Max(1, math.Abs(imag(wantB))) {
			if debugOn {
				fmt.Printf("slot %d mismatch: a %.8f want %.8f d %.8f want %.8f b %.8f%+.8fi want %.8f%+.8fi\n",
					i, ai, wantA, di, wantD, br, bi, real(wantB), imag(wantB))
			}
			return fmt.Errorf("gram mismatch at slot %d", i)
		}
	}
	if debugOn {
		limit := 8
		lam2Slice := make([]float64, limit)
		for i := 0; i < limit && i < len(S.lam2); i++ {
			lam2Slice[i] = S.lam2[i]
		}
		dbg(os.Stderr, "[Sampler] lam2[0:%d]=%v\n", limit, lam2Slice[:limit])
	}

	// Cache Eval-domain basis: b1=(f,g), b2=(F,G)
	S.b10 = fB.Copy()
	S.b11 = gB.Copy()
	S.b20 = FB.Copy()
	S.b21 = GB.Copy()
	S.b10.Domain, S.b11.Domain, S.b20.Domain, S.b21.Domain = ps.Eval, ps.Eval, ps.Eval, ps.Eval
	// Tag cFFT flavor for debug-time embedding checks
	markFlavorCFFT(S.b10)
	markFlavorCFFT(S.b11)
	markFlavorCFFT(S.b20)
	markFlavorCFFT(S.b21)

	// Compute GSO(~b2) = b2 - mu*b1, mu = <b1,b2>/<b1,b1> (generic in terms of b's)
	ip12 := ps.FieldAddBig(ps.FieldMulBig(S.b10.Conj(), S.b20), ps.FieldMulBig(S.b11.Conj(), S.b21))
	ip12.Domain = ps.Eval
	ip11 := ps.FieldAddBig(ps.FieldMulBig(S.b10, S.b10.Conj()), ps.FieldMulBig(S.b11, S.b11.Conj()))
	ip11.Domain = ps.Eval
	mu := ps.NewFieldElemBig(N, prec)
	mu.Domain = ps.Eval
	for i := 0; i < N; i++ {
		den := new(big.Float).Copy(ip11.Coeffs[i].Real) // real per slot
		mu.Coeffs[i].Real.Quo(ip12.Coeffs[i].Real, den)
		mu.Coeffs[i].Imag.Quo(ip12.Coeffs[i].Imag, den)
	}
	mu_b10 := ps.FieldMulBig(mu, S.b10)
	mu_b11 := ps.FieldMulBig(mu, S.b11)
	S.gb20 = ps.FieldSubBig(S.b20, mu_b10)
	S.gb21 = ps.FieldSubBig(S.b21, mu_b11)
	S.gb20.Domain, S.gb21.Domain = ps.Eval, ps.Eval
	if debugOn {
		limit := 8
		dbg(os.Stderr, "[Sampler] mu[0:%d]=%v\n", limit, fieldSlice(mu, limit))
	}

	// Norms for ~b1 and ~b2
	n1 := ps.FieldAddBig(ps.FieldMulBig(S.b10, S.b10.Conj()), ps.FieldMulBig(S.b11, S.b11.Conj()))
	n1.Domain = ps.Eval
	n2 := ps.FieldAddBig(ps.FieldMulBig(S.gb20, S.gb20.Conj()), ps.FieldMulBig(S.gb21, S.gb21.Conj()))
	n2.Domain = ps.Eval
	S.norm1 = make([]float64, N)
	S.norm2 = make([]float64, N)
	for i := 0; i < N; i++ {
		S.norm1[i], _ = n1.Coeffs[i].Real.Float64()
		S.norm2[i], _ = n2.Coeffs[i].Real.Float64()
		if S.norm1[i] < 0 {
			S.norm1[i] = math.Abs(S.norm1[i])
		}
		if S.norm2[i] < 0 {
			S.norm2[i] = math.Abs(S.norm2[i])
		}
	}

	// Betas: conj(~b)/<~b,~b>
	S.beta10 = ps.NewFieldElemBig(N, prec)
	S.beta11 = ps.NewFieldElemBig(N, prec)
	S.beta20 = ps.NewFieldElemBig(N, prec)
	S.beta21 = ps.NewFieldElemBig(N, prec)
	b10Conj := S.b10.Conj()
	b11Conj := S.b11.Conj()
	gb20Conj := S.gb20.Conj()
	gb21Conj := S.gb21.Conj()
	for i := 0; i < N; i++ {
		den1 := new(big.Float).SetFloat64(S.norm1[i])
		den2 := new(big.Float).SetFloat64(S.norm2[i])
		S.beta10.Coeffs[i].Real.Quo(b10Conj.Coeffs[i].Real, den1)
		S.beta10.Coeffs[i].Imag.Quo(b10Conj.Coeffs[i].Imag, den1)
		S.beta11.Coeffs[i].Real.Quo(b11Conj.Coeffs[i].Real, den1)
		S.beta11.Coeffs[i].Imag.Quo(b11Conj.Coeffs[i].Imag, den1)
		S.beta20.Coeffs[i].Real.Quo(gb20Conj.Coeffs[i].Real, den2)
		S.beta20.Coeffs[i].Imag.Quo(gb20Conj.Coeffs[i].Imag, den2)
		S.beta21.Coeffs[i].Real.Quo(gb21Conj.Coeffs[i].Real, den2)
		S.beta21.Coeffs[i].Imag.Quo(gb21Conj.Coeffs[i].Imag, den2)
	}
	S.beta10.Domain, S.beta11.Domain, S.beta20.Domain, S.beta21.Domain = ps.Eval, ps.Eval, ps.Eval, ps.Eval
	// Tag betas as cFFT-derived
	markFlavorCFFT(S.beta10)
	markFlavorCFFT(S.beta11)
	markFlavorCFFT(S.beta20)
	markFlavorCFFT(S.beta21)

	dbg(os.Stderr, "[Sampler] BuildGram done\n")
	return nil
}

// (removed legacy Beta2 helper used only by development sampler)

// sampleEvalGaussian builds an Eval-domain element with per-slot complex Gaussian N(0, σ_i^2).
func (S *Sampler) sampleEvalGaussian(sigmas []float64) *ps.CyclotomicFieldElem {
	if S.Opts.UseCNormalDist {
		return S.sampleEvalGaussianC(sigmas)
	}
	n := S.Par.N
	y := ps.NewFieldElemBig(n, S.Prec)
	y.Domain = ps.Eval
	for i := 0; i < n; i++ {
		s := sigmas[i]
		y.Coeffs[i].Real.SetFloat64(mrand.NormFloat64() * s)
		y.Coeffs[i].Imag.SetFloat64(mrand.NormFloat64() * s)
	}
	return y
}

// sampleEvalGaussianC draws per-slot complex Gaussian using Box–Muller, akin to the
// C normaldist approach (angle uniform, radius per slot). This is statistically
// equivalent to independent NormFloat64 on real and imaginary parts.
func (S *Sampler) sampleEvalGaussianC(sigmas []float64) *ps.CyclotomicFieldElem {
	n := S.Par.N
	y := ps.NewFieldElemBig(n, S.Prec)
	y.Domain = ps.Eval
	// For each slot, generate angle θ ~ Unif[0,2π), radius r = σ*sqrt(-2 ln U1)
	for i := 0; i < n; i++ {
		s := sigmas[i]
		u1 := mrand.Float64()
		for u1 <= 0 {
			u1 = mrand.Float64()
		}
		u2 := mrand.Float64()
		r := s * math.Sqrt(-2.0*math.Log(u1))
		theta := 2.0 * math.Pi * u2
		re := r * math.Cos(theta)
		im := r * math.Sin(theta)
		y.Coeffs[i].Real.SetFloat64(re)
		y.Coeffs[i].Imag.SetFloat64(im)
	}
	return y
}

// computeSigmasFromNorms computes σ1, σ2 from provided per-slot norms using big.Float math:
//
//	SIGMA_SQUARE = RSquare * Alpha^2 * Q
//	sigma_k[i] = sqrt(SIGMA_SQUARE / norm_k[i] - RSquare) for i < N/2; 0 otherwise.
func computeSigmasFromNorms(norm1, norm2 []float64, par Params, opts SamplerOpts, prec uint) (sigma1, sigma2 []float64, err error) {
	if len(norm1) == 0 || len(norm2) == 0 || len(norm1) != len(norm2) {
		return nil, nil, errors.New("computeSigmasFromNorms: invalid norms")
	}
	if opts.RSquare <= 0 || opts.Alpha <= 0 {
		return nil, nil, fmt.Errorf("ComputeSigmasC: Alpha and RSquare must be > 0")
	}
	n := len(norm1)
	sigma1 = make([]float64, n)
	sigma2 = make([]float64, n)
	// big.Float computation of SIGMA_SQUARE
	qBF := new(big.Float).SetPrec(prec).SetInt(par.Q)
	alphaBF := new(big.Float).SetPrec(prec).SetFloat64(opts.Alpha)
	r2BF := new(big.Float).SetPrec(prec).SetFloat64(opts.RSquare)
	sigmaSqBF := new(big.Float).Mul(r2BF, new(big.Float).Mul(alphaBF, alphaBF))
	sigmaSqBF.Mul(sigmaSqBF, qBF)
	for i := 0; i < n; i++ {
		if i < n/2 {
			// v = sigma^2 / norm − R^2
			v1 := new(big.Float).Quo(new(big.Float).Copy(sigmaSqBF), new(big.Float).SetFloat64(norm1[i]))
			v1.Sub(v1, r2BF)
			v2 := new(big.Float).Quo(new(big.Float).Copy(sigmaSqBF), new(big.Float).SetFloat64(norm2[i]))
			v2.Sub(v2, r2BF)
			v1f, _ := v1.Float64()
			if v1f < 0 {
				v1f = 0
			}
			v2f, _ := v2.Float64()
			if v2f < 0 {
				v2f = 0
			}
			sigma1[i] = math.Sqrt(v1f)
			sigma2[i] = math.Sqrt(v2f)
		} else {
			sigma1[i] = 0
			sigma2[i] = 0
		}
	}
	return sigma1, sigma2, nil
}

// ComputeSigmasC computes σ1, σ2 exactly as in antrag/keygen.c compute_sigma using big.Float
// and stores them in S.sigma1, S.sigma2. Requires BuildGram() to populate norm1/norm2.
func (S *Sampler) ComputeSigmasC() (sigma1, sigma2 []float64, err error) {
	dbg(os.Stderr, "[Sampler] ComputeSigmasC begin\n")
	if len(S.norm1) == 0 || len(S.norm2) == 0 {
		return nil, nil, errors.New("ComputeSigmasC: norms not initialized (call BuildGram)")
	}
	s1, s2, err := computeSigmasFromNorms(S.norm1, S.norm2, S.Par, S.Opts, S.Prec)
	if err != nil {
		return nil, nil, err
	}
	S.sigma1, S.sigma2 = s1, s2
	if debugOn {
		limit := 8
		if len(s1) < limit {
			limit = len(s1)
		}
		dbg(os.Stderr, "[Sampler] sigma1[0:%d]=%v\n", limit, s1[:limit])
		dbg(os.Stderr, "[Sampler] sigma2[0:%d]=%v\n", limit, s2[:limit])
		dbg(os.Stderr, "[Sampler] norm1[0:%d]=%v\n", limit, S.norm1[:limit])
		dbg(os.Stderr, "[Sampler] norm2[0:%d]=%v\n", limit, S.norm2[:limit])
	}
	dbg(os.Stderr, "[Sampler] ComputeSigmasC done\n")
	return s1, s2, nil
}

// NormsGSO returns copies of <~b1,~b1> and <~b2,~b2> per slot for tests.
func (S *Sampler) NormsGSO() (norm1, norm2 []float64, err error) {
	if len(S.norm1) == 0 || len(S.norm2) == 0 {
		return nil, nil, errors.New("NormsGSO: norms not initialized (call BuildGram)")
	}
	n := S.Par.N
	norm1 = make([]float64, n)
	norm2 = make([]float64, n)
	copy(norm1, S.norm1)
	copy(norm2, S.norm2)
	return norm1, norm2, nil
}

// AEntry returns the a[i] diagonal entry as float64.
func (S *Sampler) AEntry(i int) (float64, bool) {
	if i < 0 || i >= S.Par.N {
		return 0, false
	}
	ai, _ := S.a.Coeffs[i].Real.Float64()
	return ai, true
}

// Lam2Entry returns the lambda^2[i] value as float64.
func (S *Sampler) Lam2Entry(i int) (float64, bool) {
	if i < 0 || i >= S.Par.N {
		return 0, false
	}
	if len(S.lam2) == 0 {
		return 0, false
	}
	return S.lam2[i], true
}

// A returns the Eval-domain Gram entry a.
func (S *Sampler) A() *ps.CyclotomicFieldElem { return S.a }

// B returns the Eval-domain Gram entry b.
func (S *Sampler) B() *ps.CyclotomicFieldElem { return S.b }

// D returns the Eval-domain Gram entry d.
func (S *Sampler) D() *ps.CyclotomicFieldElem { return S.d }

// (removed) Trapdoor-center builders for strict preimage mode

// SamplePair draws (z0,z1) given coset centers c0,c1.
func (S *Sampler) SamplePair(c0, c1 *ps.CyclotomicFieldElem) (z0, z1 []int64, err error) {
	if S.a == nil || S.b == nil || S.d == nil {
		return nil, nil, errors.New("gram matrix not built")
	}
	if ps.ForceZero {
		z0 = make([]int64, S.Par.N)
		z1 = make([]int64, S.Par.N)
		for i := 0; i < S.Par.N; i++ {
			r0, _ := c0.Coeffs[i].Real.Float64()
			r1, _ := c1.Coeffs[i].Real.Float64()
			z0[i] = RoundAwayFromZero(r0)
			z1[i] = RoundAwayFromZero(r1)
		}
		return
	}

	// Preimage sampler expects centers in Coeff domain.
	switch c0.Domain {
	case ps.Eval:
		c0 = FloatToCoeffCFFT(c0, S.Prec)
		c1 = FloatToCoeffCFFT(c1, S.Prec)
	case ps.Coeff:
		// ok
	default:
		return nil, nil, fmt.Errorf("unsupported center domain: %v", c0.Domain)
	}

	// Always use the C-style two-step Eval-domain sampler
	return S.samplePairCExact(c0, c1)
}

// samplePairFF2x2 implements a two-step nearest-plane sampler:
// 1) q1 = round(c1 + y2) with per-slot σ2 = sqrt(d)
// 2) c0' = c0 + Beta2 * (q1 - c1), Beta2 = conj(b)/d in Eval
// 3) q0 = round(c0' + y1) with per-slot σ1 = sqrt(lam2)
// (removed: unused development-only two-step sampler)

// sampleDiscreteZVec draws integers around per-coefficient means in Coeff domain.
// (removed: unused discrete-Gaussian helper)

// sampleZVecCCompatible enforces the C sampler contract (real coeff means, stddev parameter).
func sampleZVecCCompatible(xCoeff *ps.CyclotomicFieldElem, R float64) ([]int64, error) {
	if xCoeff.Domain != ps.Coeff {
		return nil, ErrUnsupportedCenterDomain
	}
	for i := 0; i < xCoeff.N; i++ {
		_, _ = xCoeff.Coeffs[i].Real.Float64()
		_, _ = xCoeff.Coeffs[i].Imag.Float64()
		xCoeff.Coeffs[i].Imag.SetFloat64(0)
	}
	return sampleZVec(xCoeff, R)
}

// samplePairCExact mirrors the two-step ffSampling from C (sign.c).
func (S *Sampler) samplePairCExact(c0, c1 *ps.CyclotomicFieldElem) (z0, z1 []int64, err error) {
	z0, z1, _, err = S.samplePairCExactTrace(c0, c1)
	return
}

type SampleTrace struct {
	NormInitial    float64
	NormAfterStep1 float64
	NormAfterStep2 float64
}

func evalPairNorm(c0, c1 *ps.CyclotomicFieldElem) float64 {
	if c0 == nil || c1 == nil {
		return 0
	}
	var sum float64
	for i := 0; i < c0.N; i++ {
		r0, _ := c0.Coeffs[i].Real.Float64()
		i0, _ := c0.Coeffs[i].Imag.Float64()
		r1, _ := c1.Coeffs[i].Real.Float64()
		i1, _ := c1.Coeffs[i].Imag.Float64()
		sum += r0*r0 + i0*i0 + r1*r1 + i1*i1
	}
	return sum
}

func fieldSlice(e *ps.CyclotomicFieldElem, limit int) []complex128 {
	if e == nil || limit <= 0 {
		return nil
	}
	if limit > e.N {
		limit = e.N
	}
	out := make([]complex128, limit)
	for i := 0; i < limit; i++ {
		re, _ := e.Coeffs[i].Real.Float64()
		im, _ := e.Coeffs[i].Imag.Float64()
		out[i] = complex(re, im)
	}
	return out
}

// samplePairCExactTrace mirrors the two-step sampler and returns norms before/after each Babai step.
func (S *Sampler) samplePairCExactTrace(c0, c1 *ps.CyclotomicFieldElem) (z0, z1 []int64, trace SampleTrace, err error) {
	if S.beta10 == nil || S.beta11 == nil || S.beta21 == nil || S.b20 == nil || S.b21 == nil || len(S.norm1) == 0 || len(S.norm2) == 0 {
		err = errors.New("c-style sampler not initialized: call BuildGram first")
		return
	}
	N := S.Par.N
	if S.Opts.RSquare <= 0 || S.Opts.Alpha <= 0 {
		err = errors.New("sampler: RSquare and Alpha must be set (no fallback)")
		return
	}
	sig1, sig2, errSig := S.ComputeSigmasC()
	if errSig != nil {
		err = errSig
		return
	}
	if S.Opts.SigmaScale > 0 && S.Opts.SigmaScale != 1.0 {
		for i := 0; i < N; i++ {
			sig1[i] *= S.Opts.SigmaScale
			sig2[i] *= S.Opts.SigmaScale
		}
	}

	var c0Eval, c1Eval *ps.CyclotomicFieldElem
	if c0.Domain == ps.Eval {
		c0Eval = c0.Copy()
	} else if c0.Domain == ps.Coeff {
		c0Eval = FloatToEvalCFFT(c0, S.Prec)
	} else {
		err = fmt.Errorf("unsupported c0 domain: %v", c0.Domain)
		return
	}
	if c1.Domain == ps.Eval {
		c1Eval = c1.Copy()
	} else if c1.Domain == ps.Coeff {
		c1Eval = FloatToEvalCFFT(c1, S.Prec)
	} else {
		err = fmt.Errorf("unsupported c1 domain: %v", c1.Domain)
		return
	}
	assertSameFlavor("samplePairCExact:centers", c0Eval, c1Eval)
	trace.NormInitial = evalPairNorm(c0Eval, c1Eval)

	// Step 1: d2 = beta20 * c0 + beta21 * c1; x2 = d2 - y2
	assertSameFlavor("samplePairCExact:beta2·c", c0Eval, c1Eval)
	assertSameFlavor("samplePairCExact:beta2", S.beta20, S.beta21)
	t20 := ps.FieldMulBig(S.beta20, c0Eval)
	t21 := ps.FieldMulBig(S.beta21, c1Eval)
	d2 := ps.FieldAddBig(t20, t21)
	d2.Domain = ps.Eval
	y2 := S.sampleEvalGaussian(sig2)
	x2 := ps.FieldSubBig(d2, y2)
	x2.Domain = ps.Eval
	x2Coeff := FloatToCoeffCFFT(x2, S.Prec)
	R := math.Sqrt(S.Opts.RSquare)
	z1Ints, errZ1 := sampleZVecCCompatible(x2Coeff, R)
	if errZ1 != nil {
		err = errZ1
		return
	}
	z1 = z1Ints

	// Update centers: c ← c − B2*z1
	z1Coeff := ps.NewFieldElemBig(N, S.Prec)
	z1Coeff.Domain = ps.Coeff
	for i := 0; i < N; i++ {
		z1Coeff.Coeffs[i].Real.SetFloat64(float64(z1[i]))
		z1Coeff.Coeffs[i].Imag.SetFloat64(0)
	}
	z1Eval := FloatToEvalCFFT(z1Coeff, S.Prec)
	assertSameFlavor("samplePairCExact:update", S.b20, z1Eval)
	v1Eval := ps.FieldMulBig(S.b20, z1Eval)
	v2Eval := ps.FieldMulBig(S.b21, z1Eval)
	v1Eval.Domain, v2Eval.Domain = ps.Eval, ps.Eval
	c0Eval = ps.FieldSubBig(c0Eval, v1Eval)
	c1Eval = ps.FieldSubBig(c1Eval, v2Eval)
	c0Eval.Domain, c1Eval.Domain = ps.Eval, ps.Eval
	trace.NormAfterStep1 = evalPairNorm(c0Eval, c1Eval)

	// Step 2: d1 = beta10*c0 + beta11*c1; x1 = d1 - y1
	t0 := ps.FieldMulBig(S.beta10, c0Eval)
	t1 := ps.FieldMulBig(S.beta11, c1Eval)
	d1 := ps.FieldAddBig(t0, t1)
	d1.Domain = ps.Eval
	y1 := S.sampleEvalGaussian(sig1)
	x1 := ps.FieldSubBig(d1, y1)
	x1.Domain = ps.Eval
	x1Coeff := FloatToCoeffCFFT(x1, S.Prec)
	z0Ints, errZ0 := sampleZVecCCompatible(x1Coeff, R)
	if errZ0 != nil {
		err = errZ0
		return
	}
	z0 = z0Ints

	z0Coeff := ps.NewFieldElemBig(N, S.Prec)
	z0Coeff.Domain = ps.Coeff
	for i := 0; i < N; i++ {
		z0Coeff.Coeffs[i].Real.SetFloat64(float64(z0[i]))
		z0Coeff.Coeffs[i].Imag.SetFloat64(0)
	}
	z0Eval := FloatToEvalCFFT(z0Coeff, S.Prec)
	b10z0 := ps.FieldMulBig(S.b10, z0Eval)
	b11z0 := ps.FieldMulBig(S.b11, z0Eval)
	c0Final := ps.FieldSubBig(c0Eval, b10z0)
	c1Final := ps.FieldSubBig(c1Eval, b11z0)
	trace.NormAfterStep2 = evalPairNorm(c0Final, c1Final)
	return
}
