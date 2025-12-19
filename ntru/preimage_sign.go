package ntru

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	ps "vSIS-Signature/Preimage_Sampler"
)

// CoeffPoly is an alias for IntPoly to make intent explicit.
type CoeffPoly = IntPoly

//
// (removed) SamplePreimageTarget (strict/conditional wrapper)

// WriteTargetSignature persists a JSON bundle for the target signature under ./NTRU_Signature/.
// Returns the path written.
func (S *Sampler) WriteTargetSignature(msg []byte, t *ModQPoly, s0, s1 *CoeffPoly, trials int) (string, error) {
	outdir := filepath.Clean("./NTRU_Signature")
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		return "", err
	}

	// Public key h
	fQ := Int64ToModQPoly(S.f, S.Par)
	gQ := Int64ToModQPoly(S.g, S.Par)
	h, err := PublicKeyH(fQ, gQ, S.Par)
	if err != nil {
		return "", err
	}

	// coefficient-domain copies of (s0, s1)
	s0i := make([]int64, S.Par.N)
	s1i := make([]int64, S.Par.N)
	for i := 0; i < S.Par.N; i++ {
		s0i[i] = s0.Coeffs[i].Int64()
		s1i[i] = s1.Coeffs[i].Int64()
	}

	// s2c := center(h*s1 + c1) using exact RNS convolution (no pre-centering of c1)
	s1poly := Int64ToModQPoly(s1i, S.Par)
	hs1, err := ConvolveRNS(s1poly, h, S.Par)
	if err != nil {
		return "", err
	}
	s2 := hs1.Add(*t)
	for i := 0; i < S.Par.N; i++ {
		s2.Coeffs[i].Mod(s2.Coeffs[i], S.Par.Q)
	}
	s2c := recenterModQ(s2, S.Par)
	passed := CheckNormC(s1i, s2c, S.Par, S.Opts)
	nrm := CoefficientNormSquared(s1i, s2c, S.Par, S.Opts)

	var linf int64
	for _, v := range s2c {
		if v < 0 {
			v = -v
		}
		if v > linf {
			linf = v
		}
	}

	// Hex helpers
	qHex := S.Par.Q.Text(16)
	hHex := polyHex(h)
	tHex := polyHex(*t)

	payload := map[string]interface{}{
		"version":   "ntru-preimage-v1",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"params": map[string]interface{}{
			"N":                S.Par.N,
			"Q":                qHex,
			"Alpha":            S.Opts.Alpha,
			"RSquare":          S.Opts.RSquare,
			"Slack":            S.Opts.Slack,
			"UseLog3Cross":     S.Opts.UseLog3Cross,
			"UseExactResidual": S.Opts.UseExactResidual,
			"BoundShape":       S.Opts.BoundShape,
			"Prec":             S.Prec,
		},
		"public_key": map[string]interface{}{
			"h_hex": hHex,
		},
		"target": map[string]interface{}{
			"t_hex":  tHex,
			"source": "provided",
		},
		"signature": map[string]interface{}{
			"s0_coeffs": s0i,
			"s1_coeffs": s1i,
			"s2_coeffs": s2c,
			"norm": map[string]interface{}{
				"l2_est": nrm,
				// record the same predicate used during sampling
				"passed":        passed,
				"residual_linf": linf,
			},
			"trials_used": trials,
		},
		"sampler": map[string]interface{}{
			"centers": "target",
			"mode":    "two-step-eval+CDT",
			"rng":     "CSPRNG",
		},
	}

	fname := fmt.Sprintf("%s_N%d_trial%d.json", time.Now().UTC().Format("20060102T150405Z"), S.Par.N, trials)
	path := filepath.Join(outdir, fname)
	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return "", err
	}
	return path, nil
}

func polyHex(p ModQPoly) string {
	// Serialize as concatenation of big-endian hex coefficients (fixed-width not enforced here).
	// For auditability, tests can parse back by reading per-coefficient lengths from context if needed.
	// Simpler variant: join with ':' delimiters.
	hexparts := make([]byte, 0)
	for i := 0; i < len(p.Coeffs); i++ {
		hb := []byte(p.Coeffs[i].Text(16))
		hexparts = append(hexparts, hb...)
		if i+1 < len(p.Coeffs) {
			hexparts = append(hexparts, ':')
		}
	}
	return string(hexparts)
}

// fieldSign returns a copy of e multiplied by sign (+1 or -1) in its current domain.
// (removed) fieldSign/fieldConj

//
//

// rebuildV1V2From reconstructs v1, v2 (coeff-domain floats) from sampled z0,z1.
// It mirrors the post-sampling reconstruction used by SignC.
func (S *Sampler) rebuildV1V2From(z0, z1 []int64) (v1r, v2r []float64, err error) {
	N := S.Par.N
	z1Coeff := psFromInt64Coeff(z1, S.Prec)
	z0Coeff := psFromInt64Coeff(z0, S.Prec)
	z1Eval := FloatToEvalCFFT(z1Coeff, S.Prec)
	z0Eval := FloatToEvalCFFT(z0Coeff, S.Prec)
	assertSameFlavor("rebuildV1V2:z1", S.b20, z1Eval)
	// With b1=(f,g), b2=(F,G), v = z0*b1 + z1*b2:
	// v1 = f*z0 + F*z1 ; v2 = g*z0 + G*z1
	v1Eval := ps.FieldAddBig(ps.FieldMulBig(S.b10, z0Eval), ps.FieldMulBig(S.b20, z1Eval))
	v2Eval := ps.FieldAddBig(ps.FieldMulBig(S.b11, z0Eval), ps.FieldMulBig(S.b21, z1Eval))
	v1Eval.Domain, v2Eval.Domain = ps.Eval, ps.Eval
	v1Coeff := FloatToCoeffCFFT(v1Eval, S.Prec)
	v2Coeff := FloatToCoeffCFFT(v2Eval, S.Prec)
	v1r = make([]float64, N)
	v2r = make([]float64, N)
	for i := 0; i < N; i++ {
		r1, _ := v1Coeff.Coeffs[i].Real.Float64()
		r2, _ := v2Coeff.Coeffs[i].Real.Float64()
		v1r[i] = r1
		v2r[i] = r2
	}
	return v1r, v2r, nil
}

// SamplePreimageTargetOptionB implements the hybrid signature-mode preimage sampler:
// - Accepts on CheckNormC(s1, c2 - v2) only (C-style), no congruence in-loop.
// - After acceptance, computes s0 := t - h*s1 (mod Q), then recenters and returns (s0,s1).
func (S *Sampler) SamplePreimageTargetOptionB(t ModQPoly, maxTrials int) (s0, s1 *CoeffPoly, trials int, err error) {
	if S.Opts.ReduceIters <= 0 {
		S.Opts.ReduceIters = 64
	}
	S.Opts.UseCNormalDist = true
	S.Opts.UseExactResidual = true
	S.Opts.BoundShape = "cstyle"
	S.Opts.ApplyDefaults(S.Par)
	if err := S.ReduceTrapdoor(S.Opts.ReduceIters); err != nil {
		return nil, nil, 0, err
	}
	if S.a == nil {
		if err := S.BuildGram(); err != nil {
			return nil, nil, 0, err
		}
	}
	if S.Opts.RSquare <= 0 || S.Opts.Alpha <= 0 {
		return nil, nil, 0, errors.New("OptionB: RSquare and Alpha must be positive")
	}
	if S.Opts.Slack <= 0 {
		return nil, nil, 0, errors.New("OptionB: Slack must be positive")
	}
	if _, _, err := S.ComputeSigmasC(); err != nil {
		return nil, nil, 0, err
	}
	if maxTrials <= 0 {
		maxTrials = 1 << 16
	}
	S.lastS2 = nil
	// c0=0, c1=centered(t) in Coeff domain
	c0, c1 := S.CentersFromSyndrome(t)
	c1rec := recenterModQ(t, S.Par)
	if debugOn {
		var maxC1 int64
		for _, v := range c1rec {
			if v < 0 {
				v = -v
			}
			if v > maxC1 {
				maxC1 = v
			}
		}
		dbg(os.Stderr, "[OptionB] max|target|=%d\n", maxC1)
	}
	c1Mod := Int64ToModQPoly(c1rec, S.Par)
	h, err := PublicKeyH(Int64ToModQPoly(S.f, S.Par), Int64ToModQPoly(S.g, S.Par), S.Par)
	if err != nil {
		return nil, nil, 0, err
	}
	for trials = 1; trials <= maxTrials; trials++ {
		if trials == 1 || trials%16 == 0 {
			dbg(os.Stderr, "[OptionB] trial=%d\n", trials)
		}
		// Sample integers via C-style two-step sampler
		var z0, z1 []int64
		if debugOn {
			var trace SampleTrace
			var sErr error
			z0, z1, trace, sErr = S.samplePairCExactTrace(c0, c1)
			if sErr != nil {
				continue
			}
			dbg(os.Stderr, "[OptionB] norms: initial=%.4e after1=%.4e after2=%.4e\n", trace.NormInitial, trace.NormAfterStep1, trace.NormAfterStep2)
		} else {
			var sErr error
			z0, z1, sErr = S.samplePairCExact(c0, c1)
			if sErr != nil {
				continue
			}
		}
		// Rebuild v1,v2 and round
		v1r, v2r, rErr := S.rebuildV1V2From(z0, z1)
		if rErr != nil {
			continue
		}
		n := S.Par.N
		v1Round := make([]int64, n)
		v2Round := make([]int64, n)
		s1i := make([]int64, n)
		for i := 0; i < n; i++ {
			r1 := RoundAwayFromZero(v1r[i])
			r2 := RoundAwayFromZero(v2r[i])
			v1Round[i] = r1
			v2Round[i] = r2
			s1i[i] = -r1
		}
		if debugOn {
			limit := 8
			if n < limit {
				limit = n
			}
			dbg(os.Stderr, "[OptionB] v1Round[0:%d]=%v\n", limit, v1Round[:limit])
			dbg(os.Stderr, "[OptionB] v2Round[0:%d]=%v\n", limit, v2Round[:limit])
		}
		v2Poly := Int64ToModQPoly(v2Round, S.Par)
		residual := c1Mod.Sub(v2Poly)
		s2c := recenterModQ(residual, S.Par)
		S.lastS2 = append(S.lastS2[:0], s2c...)
		if debugOn {
			limit := 8
			if len(s2c) < limit {
				limit = len(s2c)
			}
			dbg(os.Stderr, "[OptionB] s2c[0:%d]=%v\n", limit, s2c[:limit])
		}
		var linf int64
		for _, v := range s2c {
			if v < 0 {
				v = -v
			}
			if v > linf {
				linf = v
			}
		}
		if S.Opts.ResidualLInf > 0 && float64(linf) > S.Opts.ResidualLInf {
			if debugOn {
				dbg(os.Stderr, "[OptionB] reject residual Linf=%d (limit=%.2f)\n", linf, S.Opts.ResidualLInf)
			}
			continue
		}
		sum := normSumBig(v1Round, s2c, S.Par, S.Opts)
		gamma := gammaSqBig(S.Par, S.Opts)
		if ok := sum.Cmp(gamma) <= 0; !ok {
			if debugOn {
				sumF, _ := sum.Float64()
				gammaF, _ := gamma.Float64()
				fmt.Fprintf(os.Stderr, "[OptionB] reject residual (cstyle): sum=%.4g bound=%.4g ratio=%.4f\n", sumF, gammaF, sumF/gammaF)
			}
			continue
		}
		if debugOn {
			sumF, _ := sum.Float64()
			gammaF, _ := gamma.Float64()
			dbg(os.Stderr, "[OptionB] accept residual: sum=%.4g bound=%.4g ratio=%.4f\n", sumF, gammaF, sumF/gammaF)
		}
		s1poly := Int64ToModQPoly(s1i, S.Par)
		hs1, convErr := ConvolveRNS(s1poly, h, S.Par)
		if convErr != nil {
			continue
		}
		s0Q := t.Sub(hs1)
		s0c := recenterModQ(s0Q, S.Par)
		p0 := NewIntPoly(n)
		p1 := NewIntPoly(n)
		for i := 0; i < n; i++ {
			p0.Coeffs[i].SetInt64(s0c[i])
			p1.Coeffs[i].SetInt64(s1i[i])
		}
		if debugOn {
			S.debugHS1Residual(s1i, &t)
		}
		return &p0, &p1, trials, nil
	}
	return nil, nil, maxTrials, errors.New("OptionB: too many rejections")
}

// debugHS1Residual prints Linf of center(h⊛s1 + c1) where c1 is the centered target.
func (S *Sampler) debugHS1Residual(s1 []int64, t *ModQPoly) {
	if !debugOn {
		return
	}
	h, err := PublicKeyH(Int64ToModQPoly(S.f, S.Par), Int64ToModQPoly(S.g, S.Par), S.Par)
	if err != nil {
		return
	}
	hs1, err := ConvolveRNS(Int64ToModQPoly(s1, S.Par), h, S.Par)
	if err != nil {
		return
	}
	c1Rec := recenterModQ(*t, S.Par)
	c1Mod := Int64ToModQPoly(c1Rec, S.Par)
	sum := hs1.Add(c1Mod)
	centered := recenterModQ(sum, S.Par)
	var linf int64
	for _, v := range centered {
		if v < 0 {
			v = -v
		}
		if v > linf {
			linf = v
		}
	}
	dbg(os.Stderr, "[Preimage] residual Linf=%d\n", linf)
}

//
//
