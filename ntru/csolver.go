package ntru

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"

	ps "vSIS-Signature/Preimage_Sampler"
)

// ntruCSolveTowerBabai computes F,G in Z[x]/(x^N+1) with f*G - g*F = Q using
// the C-style tower solver (ext=2 only) and a Babai reduction loop.
// It assumes N is a power of two (i.e., no ext=3 branch).
func ntruCSolveTowerBabai(f, g []int64, par Params, opts SolveOpts) (F, G []int64, err error) {
	dbg(os.Stderr, "[csolver] start N=%d Q=%s LOG3_D=%v M=%d Prec=%d Reduce=%v MaxIters=%d\n", par.N, par.Q.String(), par.LOG3_D, par.M, opts.Prec, opts.Reduce, opts.MaxIters)
	if len(f) != par.N || len(g) != par.N {
		return nil, nil, errors.New("dimension mismatch")
	}
	if (par.N & (par.N - 1)) != 0 {
		return nil, nil, fmt.Errorf("n must be power of two for tower solver, got %d", par.N)
	}
	// Convert to big.Int slices
	fb := make([]*big.Int, par.N)
	gb := make([]*big.Int, par.N)
	for i := 0; i < par.N; i++ {
		fb[i] = big.NewInt(f[i])
		gb[i] = big.NewInt(g[i])
	}
	// Set precision and run tower solver with per-level Babai
	prec := opts.Prec
	if prec < 256 {
		prec = 256
	}
	// Optional precision override for debugging via env
	if env := os.Getenv("NTRU_BABAI_PREC"); env != "" {
		if v, err := strconv.Atoi(env); err == nil && v > 0 {
			if uint(v) > prec {
				prec = uint(v)
			}
			dbg(os.Stderr, "[csolver] override Prec via NTRU_BABAI_PREC=%d\n", v)
		}
	}
	if prec == 0 {
		prec = 128
	}
	dbg(os.Stderr, "[csolver] towerSolve enter deg=%d\n", par.N)
	Fbig, Gbig, ok := towerSolveTower(fb, gb, par, prec)
	if !ok {
		return nil, nil, errors.New("tower solver failed")
	}
	dbg(os.Stderr, "[csolver] towerSolve done; global Babai\n")
	// Global Babai with dynamic scaling (same numerics as C)
	// Build big-int views for f,g once
	fBig := make([]*big.Int, par.N)
	gBig := make([]*big.Int, par.N)
	for i := 0; i < par.N; i++ {
		fBig[i] = big.NewInt(f[i])
		gBig[i] = big.NewInt(g[i])
	}
	blBefore := bitlenMaxAbsBig(Fbig)
	dbg(os.Stderr, "[csolver] Global Babai pre bitlen=%d\n", blBefore)
	Fbig, Gbig, ok = reduceBabaiBig(fBig, gBig, Fbig, Gbig, par, prec)
	if !ok {
		return nil, nil, errors.New("global babai failed")
	}
	blAfter := bitlenMaxAbsBig(Fbig)
	dbg(os.Stderr, "[csolver] Global Babai post bitlen=%d (Δ=%d)\n", blAfter, blBefore-blAfter)
	// Attempt to cast after BigInt Babai
	Fi, ok1 := bigSliceToInt64(Fbig)
	Gi, ok2 := bigSliceToInt64(Gbig)
	if !ok1 || !ok2 {
		return nil, nil, errors.New("int64 overflow after BigInt Babai")
	}
	if opts.Reduce {
		// Iteration cap aligned with C heuristic: 2 * size metric (bitlen of max |F|)
		maxIters := opts.MaxIters
		if maxIters <= 0 {
			sz := bitlenMaxAbs(Fi)
			if sz <= 0 {
				sz = 1
			}
			maxIters = 2 * sz
		}
		dbg(os.Stderr, "[csolver] ReduceOnce loop start maxIters=%d\n", maxIters)
		for iter := 0; iter < maxIters; iter++ {
			F2, G2, dec, rerr := ReduceOnce(Fi, Gi, f, g, par, opts.Prec)
			if rerr != nil {
				return nil, nil, rerr
			}
			Fi, Gi = F2, G2
			if !dec {
				dbg(os.Stderr, "[csolver] ReduceOnce no decrease at iter=%d; stop\n", iter)
				break
			}
		}
	}
	// Final identity check
	if !CheckNTRUIdentity(f, g, Fi, Gi, par) {
		return nil, nil, errors.New("NTRUSolveC: identity check failed after reduction")
	}
	dbg(os.Stderr, "[csolver] done\n")
	return Fi, Gi, nil
}

// towerSolveTower recursively solves f*G - g*F = Q for D with prime factors 2 and/or 3.
// Chooses ext=3 if divisible by 3; otherwise ext=2.
// reduceBabaiBig performs a Babai reduction on big.Int polynomials F,G with
// respect to basis (f,g) at precision prec. Returns updated copies.
func reduceBabaiBig(f, g, F, G []*big.Int, par Params, prec uint) (Fout, Gout []*big.Int, ok bool) {
	N := len(f)
	if prec < 256 {
		prec = 256
	}
	if env := os.Getenv("NTRU_BABAI_PREC"); env != "" {
		if v, err := strconv.Atoi(env); err == nil && v > 0 {
			if uint(v) > prec {
				prec = uint(v)
			}
		}
	}
	exp1 := extraBitsBig(f, g, 500)
	loadScaled := func(dst *ps.CyclotomicFieldElem, src []*big.Int, sh int) {
		for i := 0; i < dst.N; i++ {
			t := new(big.Int).Set(src[i])
			if sh > 0 {
				if t.Sign() >= 0 {
					t.Rsh(t, uint(sh))
				} else {
					t.Neg(t)
					t.Rsh(t, uint(sh))
					t.Neg(t)
				}
			}
			dst.Coeffs[i].Real.SetInt(t)
			dst.Coeffs[i].Imag.SetInt64(0)
		}
	}
	fC := ps.NewFieldElemBig(N, prec)
	fC.Domain = ps.Coeff
	gC := ps.NewFieldElemBig(N, prec)
	gC.Domain = ps.Coeff
	loadScaled(fC, f, exp1)
	loadScaled(gC, g, exp1)
	fE := FloatToEvalCFFT(fC, prec)
	gE := FloatToEvalCFFT(gC, prec)
	fConj := fE.Conj()
	gConj := gE.Conj()
	den := ps.FieldAddBig(ps.FieldMulBig(fE, fConj), ps.FieldMulBig(gE, gConj))
	maxIters := 2 * bitlenMaxAbsBig(F)
	if maxIters <= 0 {
		maxIters = 2
	}
	Fb := make([]*big.Int, N)
	Gb := make([]*big.Int, N)
	for i := 0; i < N; i++ {
		Fb[i] = new(big.Int).Set(F[i])
		Gb[i] = new(big.Int).Set(G[i])
	}
	for iter := 0; iter < maxIters; iter++ {
		exp2 := extraBitsBig(Fb, Gb, 500)
		FC := ps.NewFieldElemBig(N, prec)
		FC.Domain = ps.Coeff
		GC := ps.NewFieldElemBig(N, prec)
		GC.Domain = ps.Coeff
		loadScaled(FC, Fb, exp2)
		loadScaled(GC, Gb, exp2)
		FE := FloatToEvalCFFT(FC, prec)
		GE := FloatToEvalCFFT(GC, prec)
		num := ps.FieldAddBig(ps.FieldMulBig(FE, fConj), ps.FieldMulBig(GE, gConj))
		y := ps.NewFieldElemBig(N, prec)
		y.Domain = ps.Eval
		for i := 0; i < N; i++ {
			d := den.Coeffs[i].Real
			if d.Sign() == 0 {
				return nil, nil, false
			}
			y.Coeffs[i].Real.Quo(num.Coeffs[i].Real, d)
			y.Coeffs[i].Imag.Quo(num.Coeffs[i].Imag, d)
		}
		k := ifftRndCFFT(y, exp1, exp2, prec)
		allZero := true
		Kf := mulNegacyclicBigParam(k, f, par.LOG3_D)
		Kg := mulNegacyclicBigParam(k, g, par.LOG3_D)
		for i := 0; i < N; i++ {
			if k[i].Sign() != 0 {
				allZero = false
			}
			Fb[i].Sub(Fb[i], Kf[i])
			Gb[i].Sub(Gb[i], Kg[i])
		}
		if allZero {
			break
		}
	}
	return Fb, Gb, true
}

// towerSolveTowerBabai recursively solves and applies Babai at each level.
func towerSolveTower(f, g []*big.Int, par Params, prec uint) (F, G []*big.Int, ok bool) {
	dbg(os.Stderr, "[tower] enter deg=%d M=%d LOG3_D=%v\n", len(f), par.M, par.LOG3_D)
	d := len(f)
	if d == 0 {
		return nil, nil, false
	}
	if d == 1 {
		// Base case: a = f0, b = -g0, find u,v with a*u + b*v = gcd(a,b)
		dbg(os.Stderr, "[tower] basecase deg=1\n")
		a := new(big.Int).Set(f[0])
		b := new(big.Int).Neg(g[0])
		u, v, gcd := extGCDCanon(a, b)
		// C requires gcd == 1 at base case
		if gcd.Cmp(big.NewInt(1)) != 0 {
			return nil, nil, false
		}
		k := new(big.Int).Set(par.Q)
		F0 := new(big.Int).Mul(v, k) // v * Q
		G0 := new(big.Int).Mul(u, k) // u * Q
		if os.Getenv("NTRU_DEBUG") == "1" {
			dbg(os.Stderr, "[basecase] a=%s b=%s u=%s v=%s F0=%s G0=%s\n", a.String(), b.String(), u.String(), v.String(), F0.String(), G0.String())
		}
		return []*big.Int{F0}, []*big.Int{G0}, true
	}
	// Choose extension per C: if m==6 force ext=2 (special LOG3 path),
	// otherwise ext=3 when divisible by 3, else 2.
	m := par.M
	ext := 2
	if m == 6 {
		ext = 2
	} else if d%3 == 0 {
		ext = 3
	}
	// Optional mapping trace for tiny instances
	if os.Getenv("NTRU_TOWER_TRACE") == "1" && d <= 8 {
		if ext == 2 {
			kept := make([]int, 0, d/2)
			for i := 0; i < d; i += 2 {
				kept = append(kept, i)
			}
			dbg(os.Stderr, "[tower-map] deg=%d ext=2: reduce keeps even indices %v; expand maps back to even positions\n", d, kept)
		} else {
			kept := make([]int, 0, d/3)
			for i := 0; i < d; i += 3 {
				kept = append(kept, i)
			}
			dbg(os.Stderr, "[tower-map] deg=%d ext=3: reduce keeps indices %v (mod 3 == 0); expand maps back to those positions\n", d, kept)
		}
	}
	if ext == 3 {
		dbg(os.Stderr, "[tower] split ext=3 deg=%d m=%d\n", d, m)
		// ext = 3 branch
		fc := conj3BigParam(f, par.LOG3_D)
		gc := conj3BigParam(g, par.LOG3_D)
		fn := mulNegacyclicBigParam(f, fc, par.LOG3_D)
		gn := mulNegacyclicBigParam(g, gc, par.LOG3_D)
		fnRed := reduce3Big(fn)
		gnRed := reduce3Big(gn)
		// Recurse with updated params: d -> d/3, m -> m/3 (if provided)
		subPar := par
		if subPar.M != 0 {
			subPar.M = subPar.M / 3
		}
		Fsmall, Gsmall, ok := towerSolveTower(fnRed, gnRed, subPar, prec)
		if !ok {
			return nil, nil, false
		}
		Fexp := expand3Big(Fsmall)
		Gexp := expand3Big(Gsmall)
		F = mulNegacyclicBigParam(Fexp, gc, par.LOG3_D)
		G = mulNegacyclicBigParam(Gexp, fc, par.LOG3_D)
		// Babai at this level
		F, G, ok = reduceBabaiBig(f, g, F, G, par, prec)
		if !ok {
			return nil, nil, false
		}
		return F, G, true
	} else {
		dbg(os.Stderr, "[tower] split ext=2 deg=%d m=%d\n", d, m)
		// ext = 2 branch
		fc := conj2BigWithLog3(f, par.LOG3_D)
		gc := conj2BigWithLog3(g, par.LOG3_D)
		fn := mulNegacyclicBigParam(f, fc, par.LOG3_D)
		gn := mulNegacyclicBigParam(g, gc, par.LOG3_D)
		fnRed := reduce2Big(fn)
		gnRed := reduce2Big(gn)
		subPar := par
		if subPar.M != 0 {
			// C: when m==6, still ext=2 but m reduces by /3
			if subPar.M == 6 {
				subPar.M = subPar.M / 3
			} else {
				subPar.M = subPar.M / 2
			}
		}
		Fsmall, Gsmall, ok := towerSolveTower(fnRed, gnRed, subPar, prec)
		if !ok {
			return nil, nil, false
		}
		Fexp := expand2Big(Fsmall)
		Gexp := expand2Big(Gsmall)
		F = mulNegacyclicBigParam(Fexp, gc, par.LOG3_D)
		G = mulNegacyclicBigParam(Gexp, fc, par.LOG3_D)
		// Babai at this level
		F, G, ok = reduceBabaiBig(f, g, F, G, par, prec)
		if !ok {
			return nil, nil, false
		}
		return F, G, true
	}
}

// mulNegacyclicBigParam multiplies polynomials in Z[x]/(x^n+1) with an optional
// LOG3 tweak mirroring C ipoly_mul_naive when ANTRAG_LOG3_D is set:
// for i from 2n-2 down to n: h[i-n] -= h[i]; if LOG3_D then h[i-n/2] += h[i].
func mulNegacyclicBigParam(f, g []*big.Int, log3 bool) []*big.Int {
	n := len(f)
	deg := 2*n - 1
	h := make([]*big.Int, deg)
	for i := range h {
		h[i] = new(big.Int)
	}
	tmp := new(big.Int)
	for i := 0; i < n; i++ {
		if f[i].Sign() == 0 {
			continue
		}
		for j := 0; j < n; j++ {
			if g[j].Sign() == 0 {
				continue
			}
			tmp.Mul(f[i], g[j])
			h[i+j].Add(h[i+j], tmp)
		}
	}
	for i := deg - 1; i >= n; i-- {
		h[i-n].Sub(h[i-n], h[i])
		if log3 {
			h[i-n/2].Add(h[i-n/2], h[i])
		}
	}
	out := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		out[i] = new(big.Int).Set(h[i])
	}
	return out
}

func conj2Big(p []*big.Int) []*big.Int {
	n := len(p)
	out := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		out[i] = new(big.Int).Set(p[i])
		if i&1 == 1 {
			out[i].Neg(out[i])
		}
	}
	return out
}

// conj2 with special-case for degree==2 when LOG3_D is enabled (m==6 path in C).
// Mirrors ipoly_conj2: negate odd indices; if degree==2 and LOG3_D, then for i even:
//
//	pc[i] += p[i+1].
func conj2BigWithLog3(p []*big.Int, log3 bool) []*big.Int {
	out := conj2Big(p)
	if len(p) == 2 && log3 {
		// i=0 only
		out[0].Add(out[0], p[1])
	}
	return out
}

func conj3BigParam(p []*big.Int, log3 bool) []*big.Int {
	n := len(p)
	half := n / 2
	// pc1 and pc2 as in C ipoly_conj3
	pc1 := make([]*big.Int, n)
	pc2 := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		pc1[i] = new(big.Int)
		pc2[i] = new(big.Int)
	}
	// pc1
	for i := 0; i < n; i += 3 {
		pc1[i].Set(p[i])
	}
	for i := 1; i < half; i += 3 {
		pc1[i].Add(p[i], p[i+half])
		pc1[i].Neg(pc1[i])
	}
	for i := half + 1; i < n; i += 3 {
		pc1[i].Set(p[i-half])
	}
	for i := 2; i < half; i += 3 {
		pc1[i].Set(p[i+half])
	}
	for i := half + 2; i < n; i += 3 {
		pc1[i].Add(p[i-half], p[i])
		pc1[i].Neg(pc1[i])
	}
	// pc2
	for i := 0; i < n; i += 3 {
		pc2[i].Set(p[i])
	}
	for i := 2; i < half; i += 3 {
		pc2[i].Add(p[i], p[i+half])
		pc2[i].Neg(pc2[i])
	}
	for i := half + 2; i < n; i += 3 {
		pc2[i].Set(p[i-half])
	}
	for i := 1; i < half; i += 3 {
		pc2[i].Set(p[i+half])
	}
	for i := half + 1; i < n; i += 3 {
		pc2[i].Add(p[i-half], p[i])
		pc2[i].Neg(pc2[i])
	}
	return mulNegacyclicBigParam(pc1, pc2, log3)
}

func reduce2Big(p []*big.Int) []*big.Int {
	n := len(p)
	out := make([]*big.Int, n/2)
	for i := 0; i < n/2; i++ {
		out[i] = new(big.Int).Set(p[2*i])
	}
	return out
}

func reduce3Big(p []*big.Int) []*big.Int {
	n := len(p)
	out := make([]*big.Int, n/3)
	for i := 0; i < n/3; i++ {
		out[i] = new(big.Int).Set(p[3*i])
	}
	return out
}

func expand2Big(p []*big.Int) []*big.Int {
	n := len(p)
	out := make([]*big.Int, 2*n)
	for i := 0; i < 2*n; i++ {
		out[i] = new(big.Int)
	}
	for i := 0; i < n; i++ {
		out[2*i].Set(p[i])
		// out[2*i+1] already zero
	}
	return out
}

func expand3Big(p []*big.Int) []*big.Int {
	n := len(p)
	out := make([]*big.Int, 3*n)
	for i := 0; i < 3*n; i++ {
		out[i] = new(big.Int)
	}
	for i := 0; i < n; i++ {
		out[3*i].Set(p[i])
	}
	return out
}

func bigSliceToInt64(p []*big.Int) ([]int64, bool) {
	out := make([]int64, len(p))
	for i := range p {
		if !p[i].IsInt64() {
			return nil, false
		}
		out[i] = p[i].Int64()
	}
	return out, true
}

func bitlenMaxAbs(s []int64) int {
	var m int64
	for _, v := range s {
		if v < 0 {
			v = -v
		}
		if v > m {
			m = v
		}
	}
	// bitlen(0) = 0; else floor(log2) + 1
	bl := 0
	for m > 0 {
		bl++
		m >>= 1
	}
	return bl
}
