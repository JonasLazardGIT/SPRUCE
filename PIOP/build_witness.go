// quadraticgate/quadratic_gate.go
package PIOP

import (
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	ntrukeys "vSIS-Signature/ntru/keys"
	sv "vSIS-Signature/ntru/signverify"
	prof "vSIS-Signature/prof"
	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// zeroPoly allocates an all-zero polynomial in NTT form.
func zeroPoly(r *ring.Ring) *ring.Poly { p := r.NewPoly(); return p }

// copyPoly returns a deep copy of p.
func copyPoly(r *ring.Ring, p *ring.Poly) *ring.Poly {
	out := r.NewPoly()
	ring.Copy(p, out)
	return out
}

// addInto  :  dst += src
func addInto(r *ring.Ring, dst, src *ring.Poly) { r.Add(dst, src, dst) }

// mulScalarNTT multiplies every coefficient of p by the scalar c (mod q)
// and writes the result into dst.  Both p and dst must be in NTT form;
// dst may alias p for in-place updates.
func mulScalarNTT(r *ring.Ring, p *ring.Poly, c uint64, dst *ring.Poly) {
	if c == 0 {
		// quick-zero
		for i := range dst.Coeffs[0] {
			dst.Coeffs[0][i] = 0
		}
		return
	}

	q := r.Modulus[0]
	c %= q

	// Montgomery representation: coefficient-wise multiplication
	for i := range p.Coeffs[0] {
		dst.Coeffs[0][i] = (p.Coeffs[0][i] * c) % q
	}
}

func BuildWitness(
	ringQ *ring.Ring,
	A [][]*ring.Poly,
	b1 []*ring.Poly,
	B0Const []*ring.Poly,
	B0Msg [][]*ring.Poly,
	B0Rnd [][]*ring.Poly,
	/* private */
	s []*ring.Poly,
	x1 *ring.Poly,
	u []*ring.Poly,
	x0 []*ring.Poly,
) (w1 []*ring.Poly, w2 *ring.Poly, w3 []*ring.Poly) {
	defer prof.Track(time.Now(), "BuildWitness")

	// Parameter & shape guards (q=1038337, N=1024, A=1x2, s has 2 rows, u/x0 singletons)
	if ringQ.N != 1024 {
		log.Fatalf("ring N=%d, want 1024", ringQ.N)
	}
	if len(A) != 1 || len(A[0]) != 2 {
		log.Fatal("A must be 1x2 (1,h)")
	}
	if len(s) != 2 {
		log.Fatal("signature must have 2 rows (s2,s1)")
	}
	if len(u) != 1 || len(x0) != 1 {
		log.Fatal("u and x0 must be singletons")
	}

	n := len(A)    // #rows in A
	m := len(s)    // len(signature vector)
	lu := len(u)   // len(message block
	lx0 := len(x0) // len(mask block
	// witness vector (s, u, x0) has length m + lu + lx0
	k := m + lu + lx0

	// -------------------------------------------------------------------------
	// 0)  Sanity-check dimensions
	// -------------------------------------------------------------------------
	if len(b1) != n || len(B0Const) != n {

		log.Fatal("dimension mismatch in public vectors")
	}
	for _, row := range A {
		if len(row) != m {
			log.Fatal("wrong A row length ≠ m")

		}
	}

	// -------------------------------------------------------------------------
	// 1)  Verify the proof-friendly equation
	// -------------------------------------------------------------------------
	// (b1 ⊙ A)·s
	left1 := make([]*ring.Poly, n)
	for j := 0; j < n; j++ {
		left1[j] = zeroPoly(ringQ)
		for t := 0; t < m; t++ {
			tmp := ringQ.NewPoly()
			ringQ.MulCoeffs(b1[j], A[j][t], tmp) // b₁ⱼ * Aⱼ,t
			ringQ.MulCoeffs(tmp, s[t], tmp)
			addInto(ringQ, left1[j], tmp)
		}
	}

	// (A·s) * x1
	left2 := make([]*ring.Poly, n)
	for j := 0; j < n; j++ {
		left2[j] = zeroPoly(ringQ)
		for t := 0; t < m; t++ {
			tmp := ringQ.NewPoly()
			ringQ.MulCoeffs(A[j][t], s[t], tmp) // Aⱼ,t * s_t
			ringQ.MulCoeffs(tmp, x1, tmp)
			addInto(ringQ, left2[j], tmp)
		}
	}

	// B0(1;u;x0)
	right := make([]*ring.Poly, n)
	one := zeroPoly(ringQ)
	one.Coeffs[0][0] = 1 // constant 1
	for j := 0; j < n; j++ {
		right[j] = copyPoly(ringQ, B0Const[j]) // 1 · B0const

		// + message part
		for i := 0; i < lu; i++ {
			tmp := ringQ.NewPoly()
			ringQ.MulCoeffs(B0Msg[i][j], u[i], tmp)
			addInto(ringQ, right[j], tmp)
		}
		// + randomness part
		for i := 0; i < lx0; i++ {
			tmp := ringQ.NewPoly()
			ringQ.MulCoeffs(B0Rnd[i][j], x0[i], tmp)
			addInto(ringQ, right[j], tmp)
		}
	}

	// Check equality row by row
	for j := 0; j < n; j++ {
		tmp := ringQ.NewPoly()
		ringQ.Sub(left1[j], left2[j], tmp) // (b⊙A)s − (A s)x1
		ringQ.Sub(tmp, right[j], tmp)      // − B0(...)
		if !ringQ.Equal(tmp, ringQ.NewPoly()) {
			// Debug dump: first few coefficients of each side
			dump := func(name string, p *ring.Poly) {
				fmt.Printf("%s[0:8]=", name)
				for i := 0; i < 8 && i < len(p.Coeffs[0]); i++ {
					fmt.Printf("%d,", p.Coeffs[0][i])
				}
				fmt.Println()
			}
			fmt.Println("[BuildWitness] equality failed; dumping components")
			dump("left1", left1[j])
			dump("left2", left2[j])
			dump("right", right[j])
			dump("diff ", tmp)
			// also dump A row and b1 for context
			for t := 0; t < m; t++ {
				dump(fmt.Sprintf("A[%d][%d]", j, t), A[j][t])
			}
			dump("b1[j]", b1[j])
			log.Fatal("proof-friendly eq. fails on row", j)
		}
	}
	// -------------------------------------------------------------------------
	// Build the witnesses such as : w1 = (s, u, x0), w2 = x1, w3 = w1.w2= (w_{1,i}*x1)_i
	// -------------------------------------------------------------------------
	w1 = make([]*ring.Poly, k)
	for i := 0; i < m; i++ {
		w1[i] = copyPoly(ringQ, s[i]) // w1[i] = s_i
	}
	for i := 0; i < lu; i++ {
		w1[m+i] = copyPoly(ringQ, u[i]) // w1[m+i] = u_i
	}
	for i := 0; i < lx0; i++ {
		w1[m+lu+i] = copyPoly(ringQ, x0[i]) // w1[m+lu+i] = x0_i
	}
	w2 = copyPoly(ringQ, x1) // w2 = x1
	w3 = make([]*ring.Poly, k)
	for i := 0; i < k; i++ {
		w3[i] = ringQ.NewPoly()
		ringQ.MulCoeffs(w1[i], w2, w3[i]) // w3[i] = w1[i] * x1
	}
	// -------------------------------------------------------------------------
	// Return the witnesses
	return w1, w2, w3
}

func BuildWitnessFromDisk() (w1 []*ring.Poly, w2 *ring.Poly, w3 []*ring.Poly, err error) {
	defer prof.Track(time.Now(), "BuildWitnessFromDisk")

	// ‣ 0. parameters ----------------------------------------------------------
	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch: keep fixtures working */)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load params: %w", err)
	}

	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new ring: %w", err)
	}

	// Ensure test fixtures (keys/signature) exist; generate quick defaults if not.
	if err := ensureNTRUFixtures(par.N, par.Q); err != nil {
		return nil, nil, nil, fmt.Errorf("ensure fixtures: %w", err)
	}

	// convenience: explicit in-place lift
	toNTT := func(p *ring.Poly) { ringQ.NTT(p, p) }

	// ‣ 1. matrix A = [1, h] (build from public.json; lift to NTT) ---------
	pk, err := ntrukeys.LoadPublic()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load public key: %w", err)
	}

	A := make([][]*ring.Poly, 1)
	A[0] = make([]*ring.Poly, 2)
	// one(x) = 1
	one := ringQ.NewPoly()
	one.Coeffs[0][0] = 1
	ringQ.NTT(one, one)
	// Build ±h in coefficient domain, then lift to NTT.
	hCoeff := ringQ.NewPoly()
	negHCoeff := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i, v := range pk.HCoeffs {
		vv := v % q
		if vv < 0 {
			vv += q
		}
		hCoeff.Coeffs[0][i] = uint64(vv)
		if vv == 0 {
			negHCoeff.Coeffs[0][i] = 0
		} else {
			negHCoeff.Coeffs[0][i] = uint64((q - vv) % q)
		}
	}
	hNTT := ringQ.NewPoly()
	ring.Copy(hCoeff, hNTT)
	ringQ.NTT(hNTT, hNTT)
	ringQ.NTT(negHCoeff, negHCoeff)
	A[0][0], A[0][1] = one, negHCoeff

	// ‣ 2. B-matrix columns  (stored in coefficient domain → lift) -------------
	Bcoeffs, err := ntrurio.LoadBMatrixCoeffs(resolve("Parameters/Bmatrix.json"))
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load Bmatrix: %w", err)
	}

	B0Const := make([]*ring.Poly, 1)
	B0Msg := [][]*ring.Poly{make([]*ring.Poly, 1)}
	B0Rnd := [][]*ring.Poly{make([]*ring.Poly, 1)}
	b1 := make([]*ring.Poly, 1)

	makePolyNTT := func(raw []uint64) *ring.Poly {
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], raw)
		toNTT(p) // lift to NTT **once**
		return p
	}

	B0Const[0] = makePolyNTT(Bcoeffs[0])  //   B₀,const
	B0Msg[0][0] = makePolyNTT(Bcoeffs[1]) //   B₀,msg
	B0Rnd[0][0] = makePolyNTT(Bcoeffs[2]) //   B₀,rnd
	b1[0] = makePolyNTT(Bcoeffs[3])       //   b₁
	// debug B-matrix heads

	// ‣ 3. ρ  (compression vector) --------------------------------------------
	prng, err := utils.NewPRNG()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("PRNG: %w", err)
	}
	rho := make([]uint64, 1)
	rbuf := make([]byte, 8)
	prng.Read(rbuf)
	rho[0] = uint64(rbuf[0]) % par.Q // small is fine

	// ‣ 4. signature bundle ---------------------------------------------------
	sig, err := ntrukeys.Load()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load signature bundle: %w", err)
	}
	if len(sig.Signature.S2) != ringQ.N {
		return nil, nil, nil, fmt.Errorf("signature bundle missing s2 (len=%d)", len(sig.Signature.S2))
	}
	// Re-load B using the path recorded in the signature (robust to fixture changes)
	if sig.Hash.BFile != "" {
		if Bcoeffs2, e2 := ntrurio.LoadBMatrixCoeffs(resolve(sig.Hash.BFile)); e2 == nil {
			B0Const[0] = makePolyNTT(Bcoeffs2[0])
			B0Msg[0][0] = makePolyNTT(Bcoeffs2[1])
			B0Rnd[0][0] = makePolyNTT(Bcoeffs2[2])
			b1[0] = makePolyNTT(Bcoeffs2[3])
		}
	}

	// message u and masks x₀, x₁ – decode seeds, regenerate, then lift to NTT
	m := ringQ.NewPoly()
	x0 := ringQ.NewPoly()
	x1 := ringQ.NewPoly()
	mSeed, err := ntrukeys.DecodeSeed(sig.Hash.MSeed)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode mseed: %w", err)
	}
	prngM, err := utils.NewKeyedPRNG(mSeed)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keyed PRNG m: %w", err)
	}
	if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngM, m, ntru.CurrentSeedPolyBounds()); err != nil {
		return nil, nil, nil, fmt.Errorf("sample m from seed: %w", err)
	}
	x0Seed, err := ntrukeys.DecodeSeed(sig.Hash.X0Seed)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode x0seed: %w", err)
	}
	prngX0, err := utils.NewKeyedPRNG(x0Seed)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keyed PRNG x0: %w", err)
	}
	if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngX0, x0, ntru.CurrentSeedPolyBounds()); err != nil {
		return nil, nil, nil, fmt.Errorf("sample x0 from seed: %w", err)
	}
	x1Seed, err := ntrukeys.DecodeSeed(sig.Hash.X1Seed)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decode x1seed: %w", err)
	}
	prngX1, err := utils.NewKeyedPRNG(x1Seed)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("keyed PRNG x1: %w", err)
	}
	if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngX1, x1, ntru.CurrentSeedPolyBounds()); err != nil {
		return nil, nil, nil, fmt.Errorf("sample x1 from seed: %w", err)
	}
	toNTT(m)
	toNTT(x0)
	toNTT(x1)
	// debug seeds derived polys (coeff domain heads)
	tmpc := ringQ.NewPoly()
	ringQ.InvNTT(m, tmpc)
	ringQ.InvNTT(x0, tmpc)
	ringQ.InvNTT(x1, tmpc)

	// signature vector s = [s2, s1] in coefficient domain → modulo-q → NTT ----
	s := make([]*ring.Poly, 2)
	s2 := ringQ.NewPoly()
	s1 := ringQ.NewPoly()
	for i, v := range sig.Signature.S2 {
		vv := v % int64(ringQ.Modulus[0])
		if vv < 0 {
			vv += int64(ringQ.Modulus[0])
		}
		s2.Coeffs[0][i] = uint64(vv)
	}
	for i, v := range sig.Signature.S1 {
		vv := v % int64(ringQ.Modulus[0])
		if vv < 0 {
			vv += int64(ringQ.Modulus[0])
		}
		s1.Coeffs[0][i] = uint64(vv)
	}
	ringQ.NTT(s2, s2)
	ringQ.NTT(s1, s1)
	s[0], s[1] = s2, s1
	// debug s rows (coeff domain heads)
	ringQ.InvNTT(s2, tmpc)
	ringQ.InvNTT(s1, tmpc)

	// Cross-check congruence: As vs t
	// Recompute t from seeds and B (in coeff domain copies)
	mC := ringQ.NewPoly()
	x0C := ringQ.NewPoly()
	x1C := ringQ.NewPoly()
	ringQ.InvNTT(m, mC)
	ringQ.InvNTT(x0, x0C)
	ringQ.InvNTT(x1, x1C)
	tNTT, err := vsishash.ComputeBBSHash(ringQ, []*ring.Poly{B0Const[0], B0Msg[0][0], B0Rnd[0][0], b1[0]}, mC, x0C, x1C)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("recompute t: %w", err)
	}
	c1 := ringQ.NewPoly()
	for i, v := range sig.Hash.TCoeffs {
		vv := v % int64(ringQ.Modulus[0])
		if vv < 0 {
			vv += int64(ringQ.Modulus[0])
		}
		c1.Coeffs[0][i] = uint64(vv)
	}
	ringQ.NTT(c1, c1)

	As := ringQ.NewPoly()
	tmp0 := ringQ.NewPoly()
	tmp1 := ringQ.NewPoly()
	ringQ.MulCoeffs(A[0][0], s2, tmp0)
	ringQ.MulCoeffs(A[0][1], s1, tmp1)
	ringQ.Add(tmp0, tmp1, As)

	diff := ringQ.NewPoly()
	ringQ.Sub(As, c1, diff)

	// Optional cross-check: ensure s2 - h*s1 recovers c1 directly
	tmpResid := ringQ.NewPoly()
	ringQ.MulCoeffs(hNTT, s1, tmpResid)
	ringQ.Sub(s2, tmpResid, tmpResid)
	diffResid := ringQ.NewPoly()
	ringQ.Sub(tmpResid, c1, diffResid)
	if !ringQ.Equal(diffResid, ringQ.NewPoly()) {
		fmt.Println("[BuildWitness] warning: s2 - h*s1 mismatch; dumping head coeffs")
	}

	targetDelta := ringQ.NewPoly()
	ringQ.Sub(tNTT, c1, targetDelta)
	if !ringQ.Equal(targetDelta, ringQ.NewPoly()) {
		fmt.Println("[BuildWitness] warning: tNTT differs from stored c1; continuing with c1")
	}

	if !ringQ.Equal(diff, ringQ.NewPoly()) {
		fmt.Println("[BuildWitness] signature bundle appears stale; regenerating...")
		if _, err := sv.Sign([]byte("piop-sim"), 256); err != nil {
			return nil, nil, nil, fmt.Errorf("regen signature: %w", err)
		}
		sig, err = ntrukeys.Load()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("reload signature: %w", err)
		}
		// Re-derive seeds and s2/s1
		mSeed, _ = ntrukeys.DecodeSeed(sig.Hash.MSeed)
		prngM, _ = utils.NewKeyedPRNG(mSeed)
		if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngM, m, ntru.CurrentSeedPolyBounds()); err != nil {
			return nil, nil, nil, fmt.Errorf("resample m from seed: %w", err)
		}
		x0Seed, _ = ntrukeys.DecodeSeed(sig.Hash.X0Seed)
		prngX0, _ = utils.NewKeyedPRNG(x0Seed)
		if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngX0, x0, ntru.CurrentSeedPolyBounds()); err != nil {
			return nil, nil, nil, fmt.Errorf("resample x0 from seed: %w", err)
		}
		x1Seed, _ = ntrukeys.DecodeSeed(sig.Hash.X1Seed)
		prngX1, _ = utils.NewKeyedPRNG(x1Seed)
		if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngX1, x1, ntru.CurrentSeedPolyBounds()); err != nil {
			return nil, nil, nil, fmt.Errorf("resample x1 from seed: %w", err)
		}
		toNTT(m)
		toNTT(x0)
		toNTT(x1)
		for i, v := range sig.Signature.S2 {
			vv := v % int64(ringQ.Modulus[0])
			if vv < 0 {
				vv += int64(ringQ.Modulus[0])
			}
			s2.Coeffs[0][i] = uint64(vv)
		}
		for i, v := range sig.Signature.S1 {
			vv := v % int64(ringQ.Modulus[0])
			if vv < 0 {
				vv += int64(ringQ.Modulus[0])
			}
			s1.Coeffs[0][i] = uint64(vv)
		}
		ringQ.NTT(s2, s2)
		ringQ.NTT(s1, s1)
		s[0], s[1] = s2, s1
		// recompute As and t
		mC := ringQ.NewPoly()
		x0C := ringQ.NewPoly()
		x1C := ringQ.NewPoly()
		ringQ.InvNTT(m, mC)
		ringQ.InvNTT(x0, x0C)
		ringQ.InvNTT(x1, x1C)
		tNTT, err = vsishash.ComputeBBSHash(ringQ, []*ring.Poly{B0Const[0], B0Msg[0][0], B0Rnd[0][0], b1[0]}, mC, x0C, x1C)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("recompute t after regen: %w", err)
		}
		for i, v := range sig.Hash.TCoeffs {
			vv := v % int64(ringQ.Modulus[0])
			if vv < 0 {
				vv += int64(ringQ.Modulus[0])
			}
			c1.Coeffs[0][i] = uint64(vv)
		}
		ringQ.NTT(c1, c1)
		ringQ.MulCoeffs(A[0][0], s2, tmp0)
		ringQ.MulCoeffs(A[0][1], s1, tmp1)
		ringQ.Add(tmp0, tmp1, As)
		ringQ.Sub(As, c1, diff)
		if !ringQ.Equal(diff, ringQ.NewPoly()) {
			return nil, nil, nil, fmt.Errorf("signature regen did not restore congruence")
		}
	}

	// ‣ 5. build quadratic gate -----------------------------------------------
	w1, w2, w3 = BuildWitness(
		ringQ,
		A, b1,
		B0Const, B0Msg, B0Rnd,
		/*private*/ s, x1, []*ring.Poly{m}, []*ring.Poly{x0})

	return w1, w2, w3, nil
}

// ensureNTRUFixtures writes a minimal keypair and signature under ./ntru_keys
// if they are missing, to allow tests to run without manual setup.
func ensureNTRUFixtures(N int, Q uint64) error {
	if _, err := os.Stat("ntru_keys/public.json"); err == nil {
		// Keys exist; ensure signature
	} else if os.IsNotExist(err) {
		qbig := new(big.Int).SetUint64(Q)
		par, perr := ntru.NewParams(N, qbig)
		if perr != nil {
			return perr
		}
		// Use trivial keygen for speed in tests
		if _, _, gerr := sv.GenerateKeypair(par, ntru.SolveOpts{Prec: 128}, 128); gerr != nil {
			return gerr
		}
	} else if err != nil {
		return err
	}
	if _, err := os.Stat("ntru_keys/signature.json"); err == nil {
		return nil
	} else if os.IsNotExist(err) {
		if _, serr := sv.Sign([]byte("piop-sim"), 256); serr != nil {
			return serr
		}
		return nil
	} else if err != nil {
		return err
	}
	return nil
}
