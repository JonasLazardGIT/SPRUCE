// quadratic_gate_pacs.go
package PIOP

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
	measure "vSIS-Signature/measure"
	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	ntrukeys "vSIS-Signature/ntru/keys"
	sv "vSIS-Signature/ntru/signverify"
	prof "vSIS-Signature/prof"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// -----------------------------------------------------------------------------
//  Small utility – evaluate a coefficient-domain polynomial  mod q
// -----------------------------------------------------------------------------

// evalPoly returns   P(x)  where  P(X)=Σ_i coeffs[i]·X^i  and all arithmetic
// is modulo q.  The slice is in ascending degree order (coeffs[0] = a₀).
func EvalPoly(coeffs []uint64, x, q uint64) uint64 {
	if len(coeffs) == 0 {
		return 0
	}
	// Horner scheme: (((a_d)·x + a_{d-1})·x + … + a₀)
	res := coeffs[len(coeffs)-1] % q
	for i := len(coeffs) - 2; i >= 0; i-- {
		res = modMul(res, x, q)
		res = modAdd(res, coeffs[i]%q, q)
	}
	return res
}

// -----------------------------------------------------------------------------
// Θ′ – interpolating polys for public coefficients in f′
// -----------------------------------------------------------------------------

// BuildThetaPrime constructs a polynomial for every public coefficient that
// depends on the column index k:  A_{j,k},  b1_j,  B0msg_{i,k},  B0rnd_{i,k}.
//
//	values[k] must be the table of that coefficient for k=0..s-1.
//	omega     is the evaluation set Ω of size s.
//
// The result is an NTT poly whose degree ≤ s-1 and which satisfies
//
//	P(omega[k]) = values[k]  for all k.
func BuildThetaPrime(ringQ *ring.Ring, values, omega []uint64) *ring.Poly {
	if len(values) != len(omega) {
		panic("BuildThetaPrime: length mismatch")
	}
	q := ringQ.Modulus[0]
	coeffs := Interpolate(omega, values, q)
	p := ringQ.NewPoly()
	copy(p.Coeffs[0], coeffs)
	ringQ.NTT(p, p)
	return p
}

// (All-zeros Θ for f is implicit; we do not keep a separate helper.)

// -----------------------------------------------------------------------------
// Θ′  – interpolating polys for every public coefficient appearing in f′
// -----------------------------------------------------------------------------

type ThetaPrime struct {
	ARows   [][]*ring.Poly // [row][col]
	B1Rows  []*ring.Poly   // one polynomial per row  j (|Ω| evaluations)
	B0Const []*ring.Poly   // idem
	B0Msg   [][]*ring.Poly // [msgIdx][row]
	B0Rnd   [][]*ring.Poly // [rndIdx][row]
}

// BuildThetaPrimeSet builds Θ′ for *all* public tables.  omega is the
// evaluation set Ω = {ω₁,…,ω_s} (length s) used when you interpolated witness
// rows into P_i(X).
func BuildThetaPrimeSet(
	ringQ *ring.Ring,
	A [][]*ring.Poly, // [row][col]
	b1 []*ring.Poly, // [row]
	B0Const []*ring.Poly, // [row]
	B0Msg, B0Rnd [][]*ring.Poly, // [msgIdx][row]  /  [rndIdx][row]
	omega []uint64, // |Ω| = s
) *ThetaPrime {

	q := ringQ.Modulus[0]
	s := len(omega)

	// -- A rows/cols ----------------------------------------------------------
	aRows := make([][]*ring.Poly, len(A))
	for i := range A {
		aRows[i] = make([]*ring.Poly, len(A[i]))
		for k := range A[i] {
			coeff := ringQ.NewPoly()
			ringQ.InvNTT(A[i][k], coeff)
			vals := make([]uint64, s)
			for j := 0; j < s; j++ {
				vals[j] = EvalPoly(coeff.Coeffs[0], omega[j]%q, q)
			}
			aRows[i][k] = BuildThetaPrime(ringQ, vals, omega)
		}
	}

	// -- helper for row-wise constants ----------------------------------------
	buildRowPolys := func(src []*ring.Poly) []*ring.Poly {
		out := make([]*ring.Poly, len(src))
		for j, pj := range src {
			coeff := ringQ.NewPoly()
			ringQ.InvNTT(pj, coeff)
			vals := make([]uint64, s)
			for t := 0; t < s; t++ {
				vals[t] = EvalPoly(coeff.Coeffs[0], omega[t]%q, q)
			}
			out[j] = BuildThetaPrime(ringQ, vals, omega)
		}
		return out
	}

	b1Rows := buildRowPolys(b1)
	b0cRows := buildRowPolys(B0Const)

	build2D := func(src [][]*ring.Poly) [][]*ring.Poly {
		out := make([][]*ring.Poly, len(src))
		for idx := range src {
			out[idx] = buildRowPolys(src[idx])
		}
		return out
	}

	return &ThetaPrime{
		ARows:   aRows,
		B1Rows:  b1Rows,
		B0Const: b0cRows,
		B0Msg:   build2D(B0Msg),
		B0Rnd:   build2D(B0Rnd),
	}
}

// BuildThetaPrimeSetCoeff builds Θ′ using coefficient packing: each Θ′ row
// stores the raw coefficient vector (first |Ω| entries) of the source poly.
// This matches the CoeffPacking witness layout where row values equal coeffs.
func BuildThetaPrimeSetCoeff(
	ringQ *ring.Ring,
	A [][]*ring.Poly, // [row][col]
	b1 []*ring.Poly, // [row]
	B0Const []*ring.Poly, // [row]
	B0Msg, B0Rnd [][]*ring.Poly, // [msgIdx][row]  /  [rndIdx][row]
	omega []uint64, // |Ω| = s
) *ThetaPrime {
	q := ringQ.Modulus[0]
	s := len(omega)

	coeffVals := func(p *ring.Poly) []uint64 {
		coeff := ringQ.NewPoly()
		ringQ.InvNTT(p, coeff)
		if s > len(coeff.Coeffs[0]) {
			panic("BuildThetaPrimeSetCoeff: |Ω| exceeds ring degree")
		}
		vals := make([]uint64, s)
		for j := 0; j < s; j++ {
			vals[j] = coeff.Coeffs[0][j] % q
		}
		return vals
	}

	aRows := make([][]*ring.Poly, len(A))
	for i := range A {
		aRows[i] = make([]*ring.Poly, len(A[i]))
		for k := range A[i] {
			aRows[i][k] = BuildThetaPrime(ringQ, coeffVals(A[i][k]), omega)
		}
	}

	buildRowPolys := func(src []*ring.Poly) []*ring.Poly {
		out := make([]*ring.Poly, len(src))
		for j, pj := range src {
			out[j] = BuildThetaPrime(ringQ, coeffVals(pj), omega)
		}
		return out
	}

	build2D := func(src [][]*ring.Poly) [][]*ring.Poly {
		out := make([][]*ring.Poly, len(src))
		for idx := range src {
			out[idx] = buildRowPolys(src[idx])
		}
		return out
	}

	return &ThetaPrime{
		ARows:   aRows,
		B1Rows:  buildRowPolys(b1),
		B0Const: buildRowPolys(B0Const),
		B0Msg:   build2D(B0Msg),
		B0Rnd:   build2D(B0Rnd),
	}
}

// q_polys.go  (same PIOP package)

type BuildQLayout struct {
	WitnessPolys []*ring.Poly
	MaskPolys    []*ring.Poly
}

// BuildQ constructs the vector of polynomials Q_i(X) as in Eq.(4).
//
// inputs:
//
//	Fpar       – slice of *ring.Poly for every parallel constraint F_j(X)
//	Fagg       – slice of *ring.Poly for every aggregated constraint F'_j(X)
//	GammaPrime – [][]*ring.Poly   len(rho) × m1    (random deg≤s-1)
//	gammaPrime – [][]uint64       len(rho) × m2    (random scalars)
//
// output:  []*ring.Poly   len = rho
func BuildQ(
	ringQ *ring.Ring,
	layout BuildQLayout,
	FparInt []*ring.Poly,
	FparNorm []*ring.Poly,
	FaggInt []*ring.Poly,
	FaggNorm []*ring.Poly,
	GammaPrime [][]uint64,
	gammaPrime [][]uint64,
) []*ring.Poly {
	defer prof.Track(time.Now(), "BuildQ")

	maskPolys := layout.MaskPolys
	if len(maskPolys) == 0 {
		panic("BuildQ: missing mask polynomials in layout")
	}

	Fpar := append(append([]*ring.Poly{}, FparInt...), FparNorm...)
	Fagg := append(append([]*ring.Poly{}, FaggInt...), FaggNorm...)

	rho := len(maskPolys)
	m1 := len(Fpar)
	m2 := len(Fagg)

	Q := make([]*ring.Poly, rho)
	tmp := ringQ.NewPoly()
	for i := 0; i < rho; i++ {
		if i >= len(maskPolys) || maskPolys[i] == nil {
			panic(fmt.Sprintf("BuildQ: missing mask polynomial for row %d", i))
		}
		Qi := maskPolys[i].CopyNew() // start with M_i(X)

		// Σ_j Γ'_{i,j} * F_j(X)
		for j := 0; j < m1; j++ {
			mulScalarNTT(ringQ, Fpar[j], GammaPrime[i][j], tmp)
			addInto(ringQ, Qi, tmp)
		}
		// Σ_j γ'_{i,j} * F'_j(X)
		for j := 0; j < m2; j++ {
			mulScalarNTT(ringQ, Fagg[j], gammaPrime[i][j], tmp)
			addInto(ringQ, Qi, tmp)
		}
		Q[i] = Qi
	}
	if measure.Enabled {
		qb := new(big.Int).SetUint64(ringQ.Modulus[0])
		bytesR := measure.BytesRing(ringQ.N, qb)
		measure.Global.Add("piop/Q", int64(len(maskPolys))*int64(bytesR))
	}
	return Q
}

// verify_q.go

// VerifyQ checks, for every i∈[ρ], that
//
//	Σ_{ω∈Ω} Q_i(ω) = 0   (Eq.(7))
//
// The caller has already performed the Merkle-consistency check.
func VerifyQ(
	ringQ *ring.Ring,
	Q []*ring.Poly,
	omega []uint64,
) bool {
	defer prof.Track(time.Now(), "VerifyQ")
	coeff := ringQ.NewPoly()
	q := ringQ.Modulus[0]

	seen := make(map[uint64]struct{}, len(omega))
	for _, w := range omega {
		wm := w % q
		if _, ok := seen[wm]; ok {
			log.Fatalf("VerifyQ: Ω has duplicate element %d", wm)
		}
		seen[wm] = struct{}{}
	}
	if len(omega) == 0 {
		log.Fatalf("VerifyQ: |Ω| must be > 0")
	}
	if uint64(len(omega)) >= q {
		log.Fatalf("VerifyQ: |Ω| (= %d) must be < q (= %d) for S0 invertibility", len(omega), q)
	}

	for _, Qi := range Q {
		ringQ.InvNTT(Qi, coeff)
		sum := uint64(0)
		for _, w := range omega {
			sum = modAdd(sum, EvalPoly(coeff.Coeffs[0], w, q), q)
		}
		if sum != 0 {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------------
//  Full PACS verification  (f and f′ exactly as in the paper)
// -----------------------------------------------------------------------------

// VerifyFullPACS checks the two sets of constraints verbatim:
//
//   - ∀k :  f ( w1_k , w2 , w3_k ) = 0                    (parallel)
//   - ∀j :  Σ_k f′( column_k , θ′_j,k ) = 0              (aggregated)
//
// It returns true iff both families hold.
func VerifyFullPACS(
	ringQ *ring.Ring,
	w1 []*ring.Poly, w2 *ring.Poly, w3 []*ring.Poly,
	A [][]*ring.Poly, b1 []*ring.Poly,
	B0Const []*ring.Poly, B0Msg, B0Rnd [][]*ring.Poly,
) bool {

	s := len(w1) // number of columns

	// ------------------------------------------------------------------ f ----
	tmp := ringQ.NewPoly()
	zero := ringQ.NewPoly()
	for k := 0; k < s; k++ {
		ringQ.MulCoeffs(w1[k], w2, tmp)
		ringQ.Sub(w3[k], tmp, tmp)
		if !ringQ.Equal(tmp, zero) {
			return false // f constraint breaks for this k
		}
	}

	// -------------------------------------------------------------- f′ summed
	mSig := len(w1) - len(B0Msg) - len(B0Rnd) // length of signature vector s
	if mSig < 0 {
		log.Fatalf("VerifyFullPACS: negative mSig (len(w1)=%d)", len(w1))
	}
	nRows := len(A)

	left1 := ringQ.NewPoly()
	left2 := ringQ.NewPoly()
	right := ringQ.NewPoly()

	for j := 0; j < nRows; j++ {
		// reset accumulators
		for _, p := range []*ring.Poly{left1, left2, right} {
			resetPoly(p)
		}

		// Σ_k (b1⊙A)_j·s
		for t := 0; t < mSig; t++ {
			ringQ.MulCoeffs(b1[j], A[j][t], tmp)
			ringQ.MulCoeffs(tmp, w1[t], tmp)
			addInto(ringQ, left1, tmp)
		}
		// Σ_k (A s) * x1
		for t := 0; t < mSig; t++ {
			ringQ.MulCoeffs(A[j][t], w1[t], tmp)
			ringQ.MulCoeffs(tmp, w2, tmp)
			addInto(ringQ, left2, tmp)
		}
		// Σ_k B0(1;u;x0)
		addInto(ringQ, right, B0Const[j])
		for i := range B0Msg {
			ringQ.MulCoeffs(B0Msg[i][j], w1[mSig+i], tmp)
			addInto(ringQ, right, tmp)
		}
		offset := mSig + len(B0Msg)
		for i := range B0Rnd {
			ringQ.MulCoeffs(B0Rnd[i][j], w1[offset+i], tmp)
			addInto(ringQ, right, tmp)
		}

		// f′_sum = left1 - left2 - right  must be zero
		ringQ.Sub(left1, left2, tmp)
		ringQ.Sub(tmp, right, tmp)
		if !ringQ.Equal(tmp, zero) {
			return false // some aggregated constraint failed
		}
	}
	return true
}

// BuildQFromDisk loads the same JSON fixtures used by VerifyGHFromDisk,
// samples fresh Fiat-Shamir randomness Γ' and γ', computes
//
//	Q = (Q₁,…,Q_ρ)
//
// as in Eq.(4) of the SmallWood paper, and returns it.
//
// The function is **self-contained**: you can call it from a unit-test and
// check the Ω-sum condition with VerifyQ (see q_polys.go).
func BuildQFromDisk() (Q []*ring.Poly, omega []uint64, ringQ *ring.Ring) {

	//-------------------------------------------------------------------[0] ring
	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
	if err != nil {
		log.Fatalf("Parameters.json: %v", err)
	}
	ringQ, _ = ring.NewRing(par.N, []uint64{par.Q})
	toNTT := func(p *ring.Poly) { ringQ.NTT(p, p) }

	// Ensure fixtures are present so this helper is self-contained.
	if _, err := os.Stat("ntru_keys/public.json"); os.IsNotExist(err) {
		qbig := new(big.Int).SetUint64(par.Q)
		np, _ := ntru.NewParams(par.N, qbig)
		if _, _, err := sv.GenerateKeypair(np, ntru.SolveOpts{Prec: 128}, 128); err != nil {
			log.Fatalf("ensure keys: %v", err)
		}
	}
	if _, err := os.Stat("ntru_keys/signature.json"); os.IsNotExist(err) {
		if _, err := sv.Sign([]byte("piop-statement"), 256); err != nil {
			log.Fatalf("ensure signature: %v", err)
		}
	}

	//-------------------------------------------------------------------[1] A,pk
	pk, err := ntrukeys.LoadPublic()
	if err != nil {
		log.Fatalf("ntru_keys/public.json: %v", err)
	}
	A := [][]*ring.Poly{make([]*ring.Poly, 2)}
	one := ringQ.NewPoly()
	one.Coeffs[0][0] = 1
	ringQ.NTT(one, one)
	negH := ringQ.NewPoly()
	qmod := int64(ringQ.Modulus[0])
	for i, v := range pk.HCoeffs {
		vv := v % qmod
		if vv < 0 {
			vv += qmod
		}
		if vv == 0 {
			negH.Coeffs[0][i] = 0
		} else {
			negH.Coeffs[0][i] = uint64((qmod - vv) % qmod)
		}
	}
	ringQ.NTT(negH, negH)
	A[0][0], A[0][1] = one, negH

	//-------------------------------------------------------------------[2] B-mat
	Bcoeffs, _ := ntrurio.LoadBMatrixCoeffs(resolve("Parameters/Bmatrix.json"))
	B0Const := []*ring.Poly{toNTTwrap(ringQ, Bcoeffs[0], toNTT)}
	B0Msg := [][]*ring.Poly{{toNTTwrap(ringQ, Bcoeffs[1], toNTT)}}
	B0Rnd := [][]*ring.Poly{{toNTTwrap(ringQ, Bcoeffs[2], toNTT)}}
	b1 := []*ring.Poly{toNTTwrap(ringQ, Bcoeffs[3], toNTT)}

	//-------------------------------------------------------------------[3] sign
	sig, err := ntrukeys.Load()
	if err != nil {
		log.Fatalf("load signature bundle: %v", err)
	}
	if len(sig.Signature.S2) != ringQ.N {
		log.Fatalf("signature bundle missing s2 (len=%d)", len(sig.Signature.S2))
	}
	m := ringQ.NewPoly()
	x0 := ringQ.NewPoly()
	x1 := ringQ.NewPoly()
	mSeed, _ := ntrukeys.DecodeSeed(sig.Hash.MSeed)
	prngM, _ := utils.NewKeyedPRNG(mSeed)
	if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngM, m, ntru.CurrentSeedPolyBounds()); err != nil {
		log.Fatalf("sample m from seed: %v", err)
	}
	x0Seed, _ := ntrukeys.DecodeSeed(sig.Hash.X0Seed)
	prngX0, _ := utils.NewKeyedPRNG(x0Seed)
	if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngX0, x0, ntru.CurrentSeedPolyBounds()); err != nil {
		log.Fatalf("sample x0 from seed: %v", err)
	}
	x1Seed, _ := ntrukeys.DecodeSeed(sig.Hash.X1Seed)
	prngX1, _ := utils.NewKeyedPRNG(x1Seed)
	if err := ntru.FillPolyBoundedFromPRNG(ringQ, prngX1, x1, ntru.CurrentSeedPolyBounds()); err != nil {
		log.Fatalf("sample x1 from seed: %v", err)
	}
	toNTT(m)
	toNTT(x0)
	toNTT(x1)
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

	//-------------------------------------------------------------------[4] witness
	w1, w2, w3 := BuildWitness(ringQ,
		A, b1, B0Const, B0Msg, B0Rnd,
		/*private*/ s, x1, []*ring.Poly{m}, []*ring.Poly{x0})

	//-------------------------------------------------------------------[5] Ω  = first s points of the NTT evaluation grid
	sCols := len(w1)
	px := ringQ.NewPoly() // P(X)=X
	px.Coeffs[0][1] = 1
	pts := ringQ.NewPoly()
	ringQ.NTT(px, pts) // NTT(X) enumerates the grid (order consistent with ringQ)
	omega = make([]uint64, sCols)
	copy(omega, pts.Coeffs[0][:sCols])

	//-------------------------------------------------------------------[6] build F_j(X) & F'_j(X)
	mSig := len(s)
	FparProd := buildFpar(ringQ, w1, w2, w3)
	thetaPrime := BuildThetaPrimeSet(ringQ, A, b1, B0Const, B0Msg, B0Rnd, omega)
	integerRows := buildFparInteger(ringQ, w1, w2, thetaPrime, mSig)
	FparInt := append([]*ring.Poly{}, integerRows...)
	FparInt = append(FparInt, FparProd...)
	FparNorm := []*ring.Poly{}
	FaggInt := append([]*ring.Poly{}, integerRows...)
	FaggNorm := []*ring.Poly{}
	FparAll := append([]*ring.Poly{}, FparInt...)
	FaggAll := append([]*ring.Poly{}, FaggInt...)

	//-------------------------------------------------------------------[7] sample Γ' , γ'
	rho := 1 // one masking row is enough here
	ell := 1 // expose 1 random point per row
	dQ := sCols + ell - 1

	// Bind to public inputs via FS: include Ω and public tables
	q := ringQ.Modulus[0]
	concatPolys := func(pp []*ring.Poly) []byte {
		var out []byte
		for _, p := range pp {
			for _, c := range p.Coeffs[0] {
				var b [8]byte
				binary.LittleEndian.PutUint64(b[:], c)
				out = append(out, b[:]...)
			}
		}
		return out
	}
	fsOmg := bytesU64Vec(omega)
	fsA := concatPolys(A[0])
	fsB1 := concatPolys(b1)
	fsGamma := newFSRNG("GammaPrime:offline", fsOmg, fsA, fsB1)
	fsGammaSc := newFSRNG("gammaPrime:offline", fsOmg, fsA, fsB1)
	GammaPrime := sampleFSMatrix(rho, len(FparAll), q, fsGamma)
	gammaPrime := sampleFSMatrix(rho, len(FaggAll), q, fsGammaSc)

	// precompute Ω-sums of Fpar and Fagg
	sumFpar := sumPolyList(ringQ, FparAll, omega)
	sumFagg := sumPolyList(ringQ, FaggAll, omega)

	M := BuildMaskPolynomials(ringQ, rho, dQ, omega, GammaPrime, gammaPrime, sumFpar, sumFagg)

	//-------------------------------------------------------------------[8] build Q
	layout := BuildQLayout{MaskPolys: M}
	Q = BuildQ(ringQ, layout, FparInt, FparNorm, FaggInt, FaggNorm, GammaPrime, gammaPrime)

	fmt.Println("[BuildQFromDisk]  built", len(Q), "polys  (deg ≤", dQ, ")")
	return Q, omega, ringQ
}

// ---------- tiny helpers -----------------------------------------------------

func toNTTwrap(r *ring.Ring, coeffs []uint64, lift func(*ring.Poly)) *ring.Poly {
	p := r.NewPoly()
	copy(p.Coeffs[0], coeffs)
	lift(p)
	return p
}

// Fpar_k(X)  = w3_k - w1_k·w2
func buildFpar(r *ring.Ring, w1 []*ring.Poly, w2 *ring.Poly, w3 []*ring.Poly) []*ring.Poly {
	defer prof.Track(time.Now(), "buildFpar")
	out := make([]*ring.Poly, len(w1))
	for k := range w1 {
		out[k] = makeProductConstraint(r, w1[k], w2, w3[k])
	}
	if measure.Enabled {
		qb := new(big.Int).SetUint64(r.Modulus[0])
		bytesR := measure.BytesRing(r.N, qb)
		measure.Global.Add("piop/Fpar/core", int64(len(out))*int64(bytesR))
	}
	return out
}

// buildIntegerRowsOnOmega returns the proof-friendly rows F_j(X) = 0 that encode
// the equality (b1⊙A)s − (A·s)x1 − B0(1;u;x0) evaluated on Ω.
func buildIntegerRowsOnOmega(
	r *ring.Ring,
	w1 []*ring.Poly, w2 *ring.Poly,
	theta *ThetaPrime, // built with BuildThetaPrimeSet(..., omega)
	mSig int,
) []*ring.Poly {
	defer prof.Track(time.Now(), "buildIntegerRowsOnOmega")

	out := make([]*ring.Poly, len(theta.ARows))
	tmp := r.NewPoly()
	left1 := r.NewPoly()
	left2 := r.NewPoly()
	right := r.NewPoly()

	for j := range theta.ARows {
		// clear accumulators
		resetPoly(left1)
		resetPoly(left2)
		resetPoly(right)

		// Σ_t  (b1⊙A)_j,t  *  s_t
		for t := 0; t < mSig; t++ {
			r.MulCoeffs(theta.B1Rows[j], theta.ARows[j][t], tmp) // b1_j * A_j,t
			r.MulCoeffs(tmp, w1[t], tmp)
			addInto(r, left1, tmp)
		}
		// Σ_t  (A_j,t * s_t) * x1
		for t := 0; t < mSig; t++ {
			r.MulCoeffs(theta.ARows[j][t], w1[t], tmp)
			r.MulCoeffs(tmp, w2, tmp)
			addInto(r, left2, tmp)
		}
		// B0 · (1; u; x0)  : constant + message + randomness blocks
		addInto(r, right, theta.B0Const[j])
		// message block
		for i := range theta.B0Msg {
			r.MulCoeffs(theta.B0Msg[i][j], w1[mSig+i], tmp)
			addInto(r, right, tmp)
		}
		// randomness block
		off := mSig + len(theta.B0Msg)
		for i := range theta.B0Rnd {
			r.MulCoeffs(theta.B0Rnd[i][j], w1[off+i], tmp)
			addInto(r, right, tmp)
		}

		// F'_j(X) = left1 - left2 - right
		r.Sub(left1, left2, tmp)
		r.Sub(tmp, right, tmp)
		out[j] = tmp.CopyNew()
	}
	if measure.Enabled {
		qb := new(big.Int).SetUint64(r.Modulus[0])
		bytesR := measure.BytesRing(r.N, qb)
		measure.Global.Add("piop/Fagg/omega", int64(len(out))*int64(bytesR))
	}
	return out
}

// buildFparInteger exposes the per-row proof-friendly constraints to callers.
func buildFparInteger(r *ring.Ring, w1 []*ring.Poly, w2 *ring.Poly, theta *ThetaPrime, mSig int) []*ring.Poly {
	return buildIntegerRowsOnOmega(r, w1, w2, theta, mSig)
}
