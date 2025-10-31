package ntru

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
)

// KeygenFFT implements the Antrag key generation pipeline:
// Eval-domain radial sampling (annulus midline), inverse embed, Conway–Sloane decode_odd,
// α-window on first N/2 slots, invertibility mod Q, NTRU tower+Babai solve, identity check.
// On success returns (f,g,F,G) and is the default keygen path.
func KeygenFFT(par Params, opts KeygenOpts) (f, g, F, G []int64, err error) {
	// Feature remains opt-in; if Alpha not set, choose a conservative default.
	if opts.MaxTrials <= 0 {
		opts.MaxTrials = 10000
	}
	if opts.Alpha <= 0 {
		opts.Alpha = 1.20
	}
	if opts.Prec == 0 {
		opts.Prec = 128
	}

	// Guards: alpha≥1 unless fixed C-radius is used; radius positive when used.
	if !opts.UseCRadius && opts.Alpha < 1.0 {
		return nil, nil, nil, nil, fmtError("KeygenFFT: alpha must be ≥ 1")
	}
	if opts.UseCRadius && opts.Radius <= 0 {
		return nil, nil, nil, nil, fmtError("KeygenFFT: Radius must be > 0 when UseCRadius is set")
	}
	// Require power-of-two N for the solver/embedding path.
	if par.N <= 0 || (par.N&(par.N-1)) != 0 {
		return nil, nil, nil, nil, fmtError("KeygenFFT: N must be a power of two")
	}

	epar := EmbedParams{Prec: opts.Prec}
	// Mirror the C flow: always use the tower+Babai solver with local Babai reductions enabled.
	solve := SolveOpts{Prec: opts.Prec, UseCTower: true, Reduce: true}

	envDebug := os.Getenv("NTRU_DEBUG") == "1"
	verbose := opts.Verbose || envDebug
	var tried, failWindow, failInvert, failSolve, failIdent int
	if verbose {
		q := float64(par.Q.Uint64())
		var rad float64
		if opts.UseCRadius {
			rad = math.Sqrt(q) * opts.Radius
		} else {
			rad = math.Sqrt(q) * 0.5 * (opts.Alpha + 1.0/opts.Alpha)
		}
		fmt.Printf("KeygenFFT: start N=%d Q=%s alpha=%.4f useCRadius=%v radius=%.6g rad=%.6g Prec=%d MaxTrials=%d\n",
			par.N, par.Q.String(), opts.Alpha, opts.UseCRadius, opts.Radius, rad, opts.Prec, opts.MaxTrials)
	}

	for trial := 0; trial < opts.MaxTrials; trial++ {
		if verbose && (trial < 5 || (trial+1)%100 == 0) {
			fmt.Printf("KeygenFFT: trial=%d sampling radial (useCRadius=%v)\n", trial+1, opts.UseCRadius)
		}
		// Draw Eval-domain samples using either annulus midline (alpha) or fixed C-radius.
		fEval, gEval, err := KeygenRadialFGOpts(par, opts.Alpha, opts.UseCRadius, opts.Radius)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if verbose && (trial < 5 || (trial+1)%100 == 0) {
			fmt.Printf("KeygenFFT: trial=%d sampled radial OK\n", trial+1)
		}

		// Inverse-embed to coefficient domain as floats
		fFloat, err := ToCoeffFloat(fEval, par, epar)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		gFloat, err := ToCoeffFloat(gEval, par, epar)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if verbose && (trial < 5 || (trial+1)%100 == 0) {
			fmt.Printf("KeygenFFT: trial=%d tocoeff float OK\n", trial+1)
		}

		// Conway–Sloane decode_odd to integers
		fi, err := DecodeOdd(fFloat)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		gi, err := DecodeOdd(gFloat)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if verbose && (trial < 5 || (trial+1)%100 == 0) {
			fmt.Printf("KeygenFFT: trial=%d decode_odd OK\n", trial+1)
		}

		// α-window check in Eval domain on first N/2 slots (C semantics)
		S, _, _, err := SlotSumsSquared(fi, gi, par, epar)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		half := par.N / 2
		if verbose && (trial < 5 || (trial+1)%100 == 0) {
			fmt.Printf("KeygenFFT: trial=%d computed slot sums\n", trial+1)
		}
		if !AlphaWindowOK(S[:half], par.Q.Uint64(), opts.Alpha) {
			failWindow++
			tried++
			if verbose && (tried <= 10 || tried%100 == 0) {
				fmt.Printf("KeygenFFT: trial=%d stage=window counts window=%d invert=%d solve=%d ident=%d\n", tried, failWindow, failInvert, failSolve, failIdent)
			}
			continue
		}

		// Invertibility prefilter AFTER α-window (C staging: compute_public)
		if !IsUnitModQ(Int64ToModQPoly(fi, par), par) {
			failInvert++
			tried++
			if verbose && (tried <= 10 || tried%100 == 0) {
				fmt.Printf("KeygenFFT: trial=%d stage=invert counts window=%d invert=%d solve=%d ident=%d\n", tried, failWindow, failInvert, failSolve, failIdent)
			}
			continue
		}

		// Solve NTRU and verify identity
		F, G, err = NTRUSolve(fi, gi, par, solve)
		if err != nil {
			failSolve++
			tried++
			if verbose && (tried <= 10 || tried%100 == 0) {
				fmt.Printf("KeygenFFT: trial=%d stage=solve counts window=%d invert=%d solve=%d ident=%d\n", tried, failWindow, failInvert, failSolve, failIdent)
			}
			continue
		}
		if !CheckNTRUIdentity(fi, gi, F, G, par) {
			failIdent++
			tried++
			if verbose && (tried <= 10 || tried%100 == 0) {
				fmt.Printf("KeygenFFT: trial=%d stage=ident counts window=%d invert=%d solve=%d ident=%d\n", tried, failWindow, failInvert, failSolve, failIdent)
			}
			continue
		}
		if verbose {
			fmt.Printf("KeygenFFT: success at trial=%d (window=%d invert=%d solve=%d ident=%d)\n", tried+1, failWindow, failInvert, failSolve, failIdent)
		}
		return fi, gi, F, G, nil
	}
	if verbose {
		fmt.Printf("KeygenFFT: FINAL trials=%d window=%d invert=%d solve=%d ident=%d\n", tried, failWindow, failInvert, failSolve, failIdent)
	}
	return nil, nil, nil, nil, fmtError("KeygenFFT: no key within MaxTrials and alpha window")
}

// KeygenRadialFG generates Eval-domain (f,g) following the C keygen_fg() sampler.
// It draws three arrays of uniform random values in [0,1), then sets, for i < N/2:
//
//	af = rad * cos(pi/2 * r[i])
//	ag = rad * sin(pi/2 * r[i])
//	f[i] = af * cos(2*pi * r[i + N/2]);   Im(f[i]) = af * sin(2*pi * r[i + N/2])
//	g[i] = ag * cos(2*pi * r[i + N/2*2]); Im(g[i]) = ag * sin(2*pi * r[i + N/2*2])
//
// where rad = sqrt(Q) * 0.5 * (alpha + 1/alpha).
// Returns two Eval vectors of length N (complex128 per slot).
func KeygenRadialFG(par Params, alpha float64) (fEval, gEval EvalVec, err error) {
	if par.N%2 != 0 || par.N <= 0 {
		return EvalVec{}, EvalVec{}, errors.New("KeygenRadialFG: N must be positive even")
	}
	if alpha < 1.0 {
		return EvalVec{}, EvalVec{}, errors.New("KeygenRadialFG: alpha must be ≥ 1")
	}

	N := par.N
	half := N / 2
	q := float64(par.Q.Uint64())
	rad := math.Sqrt(q) * 0.5 * (alpha + 1.0/alpha)

	// r array of length 3*N/2 with uniform [0,1) from crypto/rand
	r, err := cryptoRandFloat64s(3 * half)
	if err != nil {
		return EvalVec{}, EvalVec{}, err
	}

	f := make([]complex128, N)
	g := make([]complex128, N)

	// Fill independent slots 0..N/2-1 and enforce conjugate symmetry:
	// for k in [0..N/2-1], set slot k, and slot N-1-k = conj(slot k).
	for i := 0; i < half; i++ {
		af := rad * math.Cos((math.Pi/2.0)*r[i])
		ag := rad * math.Sin((math.Pi/2.0)*r[i])

		thetaF := 2.0 * math.Pi * r[i+half]
		thetaG := 2.0 * math.Pi * r[i+2*half]

		fRe := af * math.Cos(thetaF)
		fIm := af * math.Sin(thetaF)
		gRe := ag * math.Cos(thetaG)
		gIm := ag * math.Sin(thetaG)

		zf := complex(fRe, fIm)
		zg := complex(gRe, gIm)
		f[i] = zf
		g[i] = zg
		// conjugate slot index for negacyclic embedding: N-1-i
		j := N - 1 - i
		f[j] = complex(fRe, -fIm)
		g[j] = complex(gRe, -gIm)
	}

	return EvalVec{V: f}, EvalVec{V: g}, nil
}

// KeygenRadialFGOpts is an extended version of KeygenRadialFG which allows the
// fixed C-style radius mode. When useCRadius is true, the radius is set to
// sqrt(Q) * cRadius; otherwise it uses the annulus midline sqrt(Q)*0.5*(alpha+1/alpha).
func KeygenRadialFGOpts(par Params, alpha float64, useCRadius bool, cRadius float64) (fEval, gEval EvalVec, err error) {
	if par.N%2 != 0 || par.N <= 0 {
		return EvalVec{}, EvalVec{}, errors.New("KeygenRadialFG: N must be positive even")
	}
	if !useCRadius && alpha < 1.0 {
		return EvalVec{}, EvalVec{}, errors.New("KeygenRadialFG: alpha must be ≥ 1 (when not using fixed C-radius)")
	}
	if useCRadius && cRadius <= 0 {
		return EvalVec{}, EvalVec{}, errors.New("KeygenRadialFG: Radius must be > 0 when UseCRadius is set")
	}

	N := par.N
	half := N / 2
	q := float64(par.Q.Uint64())
	var rad float64
	if useCRadius {
		rad = math.Sqrt(q) * cRadius
	} else {
		rad = math.Sqrt(q) * 0.5 * (alpha + 1.0/alpha)
	}

	// r array of length 3*N/2 with uniform [0,1) from crypto/rand
	r, err := cryptoRandFloat64s(3 * half)
	if err != nil {
		return EvalVec{}, EvalVec{}, err
	}

	f := make([]complex128, N)
	g := make([]complex128, N)

	for i := 0; i < half; i++ {
		af := rad * math.Cos((math.Pi/2.0)*r[i])
		ag := rad * math.Sin((math.Pi/2.0)*r[i])

		thetaF := 2.0 * math.Pi * r[i+half]
		thetaG := 2.0 * math.Pi * r[i+2*half]

		fRe := af * math.Cos(thetaF)
		fIm := af * math.Sin(thetaF)
		gRe := ag * math.Cos(thetaG)
		gIm := ag * math.Sin(thetaG)

		zf := complex(fRe, fIm)
		zg := complex(gRe, gIm)
		f[i] = zf
		g[i] = zg
		j := N - 1 - i
		f[j] = complex(fRe, -fIm)
		g[j] = complex(gRe, -gIm)
	}

	return EvalVec{V: f}, EvalVec{V: g}, nil
}

// cryptoRandFloat64s returns n independent floats U in [0,1) using crypto/rand.
// Mirrors C's simple_frand: U = uint64 / 2^64.
func cryptoRandFloat64s(n int) ([]float64, error) {
	if n <= 0 {
		return nil, nil
	}
	out := make([]float64, n)
	buf := make([]byte, 8*n)
	if _, err := crand.Read(buf); err != nil {
		return nil, err
	}
	const inv2p64 = 5.421010862427522e-20 // 2^-64
	for i := 0; i < n; i++ {
		u := binary.LittleEndian.Uint64(buf[8*i:])
		out[i] = float64(u) * inv2p64
	}
	return out, nil
}

// KeygenWindowSample finds integer (f,g) by the C-faithful Eval radial sampling +
// inverse-embedding + decode_odd, enforcing only the α-window. It does not run
// the NTRU solver. Useful for testing the α-window condition independently.
func KeygenWindowSample(par Params, alpha float64, prec uint, maxTrials int) (f, g []int64, err error) {
	if maxTrials <= 0 {
		maxTrials = 10000
	}
	if alpha < 1.0 {
		return nil, nil, errors.New("KeygenWindowSample: alpha must be ≥ 1")
	}
	epar := EmbedParams{Prec: prec}
	for trial := 0; trial < maxTrials; trial++ {
		fEval, gEval, err := KeygenRadialFG(par, alpha)
		if err != nil {
			return nil, nil, err
		}
		fFloat, err := ToCoeffFloat(fEval, par, epar)
		if err != nil {
			return nil, nil, err
		}
		gFloat, err := ToCoeffFloat(gEval, par, epar)
		if err != nil {
			return nil, nil, err
		}
		fi, err := DecodeOdd(fFloat)
		if err != nil {
			return nil, nil, err
		}
		gi, err := DecodeOdd(gFloat)
		if err != nil {
			return nil, nil, err
		}
		S, _, _, err := SlotSumsSquared(fi, gi, par, epar)
		if err != nil {
			return nil, nil, err
		}
		half := par.N / 2
		if AlphaWindowOK(S[:half], par.Q.Uint64(), alpha) {
			return fi, gi, nil
		}
	}
	return nil, nil, fmtError("KeygenWindowSample: no (f,g) within MaxTrials for alpha window")
}
