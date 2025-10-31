package ntru

import (
	"fmt"
	"io"
	"math"

	ps "vSIS-Signature/Preimage_Sampler"
)

func (S *Sampler) DebugDumpGram(w io.Writer) {
	if !debugOn {
		return
	}
	N := S.Par.N
	minA, minD := math.MaxFloat64, math.MaxFloat64
	minLam2, minDet := math.MaxFloat64, math.MaxFloat64
	maxMu := 0.0
	for i := 0; i < N; i++ {
		ai, _ := S.a.Coeffs[i].Real.Float64()
		di, _ := S.d.Coeffs[i].Real.Float64()
		br, _ := S.b.Coeffs[i].Real.Float64()
		bi, _ := S.b.Coeffs[i].Imag.Float64()
		mu2 := (br*br + bi*bi) / ai / ai
		lam2 := di - (br*br+bi*bi)/ai
		det := ai * lam2
		if ai < minA {
			minA = ai
		}
		if di < minD {
			minD = di
		}
		if lam2 < minLam2 {
			minLam2 = lam2
		}
		if det < minDet {
			minDet = det
		}
		if mu2 > maxMu {
			maxMu = mu2
		}
		if i < 8 {
			fmt.Fprintf(w, "slot %d: a=%+.6e, d=%+.6e, b=(%+.6e%+.6ei), lam2=%+.6e, det=%+.6e\n", i, ai, di, br, bi, lam2, det)
		}
	}
	fmt.Fprintf(w, "GRAM: min(a)=%.6e  min(d)=%.6e  min(lam2)=%.6e  min(det)=%.6e  max(|b/a|^2)=%.6e\n", minA, minD, minLam2, minDet, maxMu)
}

// SamplePairTrace exposes the two-step sampler along with residual norms for testing/debugging.
func (S *Sampler) SamplePairTrace(c0, c1 *ps.CyclotomicFieldElem) (z0, z1 []int64, trace SampleTrace, err error) {
	return S.samplePairCExactTrace(c0, c1)
}

// DebugEvalBasis returns copies of the Eval-domain basis vectors (b1,b2).
func (S *Sampler) DebugEvalBasis() (b10, b11, b20, b21 *ps.CyclotomicFieldElem) {
	return S.b10.Copy(), S.b11.Copy(), S.b20.Copy(), S.b21.Copy()
}

// DebugEvalBetas returns copies of the Eval-domain beta projectors.
func (S *Sampler) DebugEvalBetas() (beta10, beta11, beta20, beta21 *ps.CyclotomicFieldElem) {
	return S.beta10.Copy(), S.beta11.Copy(), S.beta20.Copy(), S.beta21.Copy()
}

func (S *Sampler) DebugDumpCenters(w io.Writer, t ModQPoly, c0, c1 *ps.CyclotomicFieldElem) {
	if !debugOn {
		return
	}
	fmt.Fprintf(w, "Centers for target: domain(c0)=%v domain(c1)=%v\n", c0.Domain, c1.Domain)
	for i := 0; i < S.Par.N && i < 8; i++ {
		r0, _ := c0.Coeffs[i].Real.Float64()
		i0, _ := c0.Coeffs[i].Imag.Float64()
		r1, _ := c1.Coeffs[i].Real.Float64()
		i1, _ := c1.Coeffs[i].Imag.Float64()
		fmt.Fprintf(w, "slot %d: c0=(%+.6e%+.6ei)  c1=(%+.6e%+.6ei)\n", i, r0, i0, r1, i1)
	}
}

func (S *Sampler) DebugDumpResidual(w io.Writer, z0, z1 []int64, t ModQPoly) {
	if !debugOn {
		return
	}
	y, _ := NewMatOpFG(Int64ToModQPoly(S.f, S.Par), Int64ToModQPoly(S.g, S.Par), S.Par)
	r, _ := y.ApplyPair(Int64ToModQPoly(z0, S.Par), Int64ToModQPoly(z1, S.Par))
	fmt.Fprintln(w, "Residual (first 8 coeffs): y - t mod q")
	for i := 0; i < S.Par.N && i < 8; i++ {
		fmt.Fprintf(w, "  i=%d: got=%s  want=%s\n", i, r.Coeffs[i].String(), t.Coeffs[i].String())
	}
}
