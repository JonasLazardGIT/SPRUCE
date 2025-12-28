// Package PIOP – prover‑side helpers for Section 6 PACS construction.
//
// This file contains utilities that turn a *row* of the witness matrix
// (w_{i,1},…,w_{i,s}) into the blinding polynomial P_i ∈ F_q[X] described in
// Protocol 6 of the SmallWood paper.  Each polynomial is defined by
//   - its s anchor points Ω = {ω₁,…,ω_s},
//   - ℓ extra random points r₁,…,r_ℓ (r_j ∉ Ω),
//   - uniformly random evaluations P_i(r_j) ∈ F_q.
//
// Degree ≤ s+ℓ−1 and perfect zero‑knowledge follow immediately.
//
// The code is written for tiny s,ℓ (≤64) as is common in practice;  O(n³)
// barycentric Lagrange interpolation is therefore acceptable.
package PIOP

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	kf "vSIS-Signature/internal/kfield"
	measure "vSIS-Signature/measure"
	prof "vSIS-Signature/prof"

	"github.com/tuneinsight/lattigo/v4/ring"
)

var (
	bigA, bigB, bigQ, bigAB big.Int
)

// -----------------------------------------------------------------------------
//  field helpers (mod q)
// -----------------------------------------------------------------------------

func randUint64Mod(q uint64) uint64 {
	var bound uint64 = ^uint64(0) - (^uint64(0) % q)
	for {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			panic("randUint64Mod: entropy read failed: " + err.Error())
		}
		v := binary.LittleEndian.Uint64(buf[:])
		if v < bound {
			return v % q
		}
	}
}

// modAdd returns (a+b) mod q.
func modAdd(a, b, q uint64) uint64 {
	s := a + b
	if s >= q || s < a { // handle wrap‑around
		s -= q
	}
	return s
}

// modSub returns (a‑b) mod q.
func modSub(a, b, q uint64) uint64 {
	if a >= b {
		return a - b
	}
	return a + q - b
}

// modMul returns (a·b) mod q using big.Int temporaries without allocations.
func modMul(a, b, q uint64) uint64 {
	bigA.SetUint64(a)
	bigB.SetUint64(b)
	bigQ.SetUint64(q)
	bigAB.Mul(&bigA, &bigB)
	bigAB.Mod(&bigAB, &bigQ)
	return bigAB.Uint64()
}

// modInv returns a^{‑1} mod q (q must be prime).
func modInv(a, q uint64) uint64 {
	return ring.ModExp(a, q-2, q) // Fermat since q is prime in all params used.
}

// copyPolyNTT copies src into dst assuming both are in NTT form.
func copyPolyNTT(dst, src *ring.Poly) {
	for i := range dst.Coeffs {
		copy(dst.Coeffs[i], src.Coeffs[i])
	}
}

// -----------------------------------------------------------------------------
// Fiat–Shamir: tiny deterministic PRF stream (SHA‑256(counter || seed))
// -----------------------------------------------------------------------------

type fsRNG struct {
	seed [32]byte
	ctr  uint64
}

// KScalar encodes an element of K ≅ F^θ in φ^{-1}-coordinates.
type KScalar []uint64

// KVec is a convenience alias for a slice of K-scalars.
type KVec []KScalar

// KMat models a matrix whose entries live in K.
type KMat [][]KScalar

// KPoly represents a polynomial in K[X] via limb-wise coefficient slices.
// Limbs[j][k] stores the j-th limb of the X^k coefficient. Degree tracks the
// highest non-zero coefficient index (bounded by the construction input).
type KPoly struct {
	Limbs  [][]uint64
	Degree int
}

// --- Helpers to assemble QK from MK and {Γ′_K, γ′_K} on top of F-polys ---
// addScaledFPolyToKPoly: dst += (Φ(gK) * F[X]) where F has coeffs in F_q.
// Multiplication by an F element scales every limb by that element.
func addScaledFPolyToKPoly(r *ring.Ring, K *kf.Field, dst *KPoly, gK KScalar, F *ring.Poly) {
	if dst == nil || F == nil || K == nil {
		return
	}
	coeff := r.NewPoly()
	r.InvNTT(F, coeff)
	q := r.Modulus[0]
	theta := K.Theta
	if len(dst.Limbs) < theta {
		theta = len(dst.Limbs)
	}
	if len(gK) < theta {
		theta = len(gK)
	}
	for k, a := range coeff.Coeffs[0] {
		if a%q == 0 {
			continue
		}
		for j := 0; j < theta; j++ {
			dst.Limbs[j][k] = modAdd(dst.Limbs[j][k], modMul(gK[j]%q, a%q, q), q)
		}
		if k > dst.Degree {
			dst.Degree = k
		}
	}
}

// deepCopyKPoly returns a copy of kp.
func deepCopyKPoly(kp *KPoly) *KPoly {
	if kp == nil {
		return nil
	}
	out := &KPoly{Degree: kp.Degree, Limbs: make([][]uint64, len(kp.Limbs))}
	for j := range kp.Limbs {
		out.Limbs[j] = append([]uint64(nil), kp.Limbs[j]...)
	}
	return out
}

// BuildQK: Q_i(X) = M_i(X) + Σ_t Γ′_{i,t}·Fpar_t(X) + Σ_u γ′_{i,u}·Fagg_u(X) in K[X].
func BuildQK(
	r *ring.Ring, K *kf.Field,
	MK []*KPoly, Fpar, Fagg []*ring.Poly,
	GammaPrimeK [][]KScalar, GammaAggK [][]KScalar,
) []*KPoly {
	if K == nil {
		return nil
	}
	rho := len(MK)
	out := make([]*KPoly, rho)
	for i := 0; i < rho; i++ {
		qi := deepCopyKPoly(MK[i])
		if qi == nil {
			qi = newZeroKPoly(K.Theta, int(r.N), int(r.N)-1)
		}
		for j := range Fpar {
			if i < len(GammaPrimeK) && j < len(GammaPrimeK[i]) {
				addScaledFPolyToKPoly(r, K, qi, GammaPrimeK[i][j], Fpar[j])
			}
		}
		for j := range Fagg {
			if i < len(GammaAggK) && j < len(GammaAggK[i]) {
				addScaledFPolyToKPoly(r, K, qi, GammaAggK[i][j], Fagg[j])
			}
		}
		out[i] = qi
	}
	return out
}

// firstLimbToFPoly converts the first limb of a K-polynomial to an F[X] polynomial in coeff-domain.
func firstLimbToFPoly(r *ring.Ring, kp *KPoly) *ring.Poly {
	if kp == nil || len(kp.Limbs) == 0 {
		return nil
	}
	poly := r.NewPoly()
	copy(poly.Coeffs[0], kp.Limbs[0])
	return poly
}

// newFSRNG derives a PRF seed from a label and arbitrary transcript material.
func newFSRNG(label string, material ...[]byte) *fsRNG {
	h := sha256.New()
	h.Write([]byte(label))
	for _, m := range material {
		h.Write(m)
	}
	var s [32]byte
	copy(s[:], h.Sum(nil))
	return &fsRNG{seed: s}
}

func (r *fsRNG) nextU64() uint64 {
	var in [40]byte
	copy(in[:32], r.seed[:])
	binary.LittleEndian.PutUint64(in[32:], r.ctr)
	sum := sha256.Sum256(in[:])
	r.ctr++
	return binary.LittleEndian.Uint64(sum[:])
}

// Helpers to serialize inputs for FS binding.
func bytesU64Vec(v []uint64) []byte {
	out := make([]byte, 8*len(v))
	for i, x := range v {
		binary.LittleEndian.PutUint64(out[8*i:], x)
	}
	return out
}

func bytesU64Mat(M [][]uint64) []byte {
	var out []byte
	for i := range M {
		out = append(out, bytesU64Vec(M[i])...)
	}
	return out
}

func bytesFromKScalar(k KScalar) []byte {
	if len(k) == 0 {
		return nil
	}
	out := make([]byte, 8*len(k))
	for i, limb := range k {
		binary.LittleEndian.PutUint64(out[i*8:], limb)
	}
	return out
}

func bytesFromKScalarVec(v []KScalar) []byte {
	var out []byte
	for _, scalar := range v {
		out = append(out, bytesFromKScalar(scalar)...)
	}
	return out
}

func bytesFromKScalarMat(M [][]KScalar) []byte {
	var out []byte
	for _, row := range M {
		out = append(out, bytesFromKScalarVec(row)...)
	}
	return out
}

// sampleFSMatrix(rows × cols) with entries in F_q.
func sampleFSMatrix(rows, cols int, q uint64, rng *fsRNG) [][]uint64 {
	M := make([][]uint64, rows)
	for i := 0; i < rows; i++ {
		M[i] = make([]uint64, cols)
		for j := 0; j < cols; j++ {
			M[i][j] = rng.nextU64() % q
		}
	}
	return M
}

// sampleFSMatrixK draws a rows×cols matrix of K elements using θ limbs per entry.
func sampleFSMatrixK(rows, cols, theta int, q uint64, rng *fsRNG) [][]KScalar {
	if rows < 0 || cols < 0 || theta <= 0 {
		return nil
	}
	mat := make([][]KScalar, rows)
	for i := 0; i < rows; i++ {
		row := make([]KScalar, cols)
		for j := 0; j < cols; j++ {
			k := make(KScalar, theta)
			for t := 0; t < theta; t++ {
				k[t] = rng.nextU64() % q
			}
			row[j] = k
		}
		mat[i] = row
	}
	return mat
}

// sampleFSVectorK draws a rows×cols matrix but exposes it as slices of K scalars.
func sampleFSVectorK(rows, cols, theta int, q uint64, rng *fsRNG) [][]KScalar {
	return sampleFSMatrixK(rows, cols, theta, q, rng)
}

// newZeroKPoly allocates a zero polynomial in K[X] with coefficient support < N
// and degree bounded by dQ.
func newZeroKPoly(theta int, N int, dQ int) *KPoly {
	limbs := make([][]uint64, theta)
	for j := range limbs {
		limbs[j] = make([]uint64, N)
	}
	return &KPoly{Limbs: limbs, Degree: dQ}
}

// setCoeffK writes a K coefficient (given by its limbs) for X^k.
func (kp *KPoly) setCoeffK(k int, aLimbs []uint64) {
	for j := range kp.Limbs {
		kp.Limbs[j][k] = aLimbs[j]
	}
	if k > kp.Degree {
		kp.Degree = k
	}
}

// coeffLimbs returns the limb vector of coefficient X^k.
func (kp *KPoly) coeffLimbs(k int) []uint64 {
	out := make([]uint64, len(kp.Limbs))
	for j := range kp.Limbs {
		out[j] = kp.Limbs[j][k]
	}
	return out
}

// kpolyToCoeffPolys produces θ coefficient-domain polynomials, one per limb.
func kpolyToCoeffPolys(r *ring.Ring, kp *KPoly) []*ring.Poly {
	out := make([]*ring.Poly, len(kp.Limbs))
	for j := range kp.Limbs {
		poly := r.NewPoly()
		copy(poly.Coeffs[0], kp.Limbs[j])
		out[j] = poly
	}
	return out
}

// evalKPolyAtF evaluates kp at an F_q point w (embedded in K).
func evalKPolyAtF(K *kf.Field, kp *KPoly, w uint64) kf.Elem {
	acc := K.Zero()
	x := K.EmbedF(w % K.Q)
	for k := kp.Degree; k >= 0; k-- {
		acc = K.Mul(acc, x)
		coeff := K.Phi(kp.coeffLimbs(k))
		acc = K.Add(acc, coeff)
		if k == 0 {
			break
		}
	}
	return acc
}

// evalKPolyAtK evaluates kp at a K-point e.
func evalKPolyAtK(K *kf.Field, kp *KPoly, e kf.Elem) kf.Elem {
	acc := K.Zero()
	for k := kp.Degree; k >= 0; k-- {
		acc = K.Mul(acc, e)
		coeff := K.Phi(kp.coeffLimbs(k))
		acc = K.Add(acc, coeff)
		if k == 0 {
			break
		}
	}
	return acc
}

// BuildMaskPolynomialsK builds M_i ∈ K[X] of degree ≤ dQ such that ΣΩ Q_i(ω)=0 in K.
type maskSamplerParams struct {
	omega  []uint64
	maxDeg int
}

func validateMaskSamplerParams(q uint64, params maskSamplerParams) {
	s := len(params.omega)
	if s == 0 {
		panic("mask sampler: Ω must be non-empty")
	}
	seen := make(map[uint64]struct{}, s)
	for _, w := range params.omega {
		wm := w % q
		if _, ok := seen[wm]; ok {
			panic(fmt.Sprintf("mask sampler: Ω contains duplicate element %d (mod q)", wm))
		}
		seen[wm] = struct{}{}
	}
	if uint64(s) >= q {
		panic(fmt.Sprintf("mask sampler: |Ω| (= %d) must be < q (= %d)", s, q))
	}
}

func maskSamplerS(omega []uint64, dQ int, q uint64) []uint64 {
	S := make([]uint64, dQ+1)
	S[0] = uint64(len(omega)) % q
	if dQ == 0 {
		return S
	}
	powers := make([]uint64, len(omega))
	for k := 1; k <= dQ; k++ {
		sum := uint64(0)
		for j, w := range omega {
			if k == 1 {
				powers[j] = w % q
			} else {
				powers[j] = (powers[j] * w) % q
			}
			sum = modAdd(sum, powers[j], q)
		}
		S[k] = sum
	}
	return S
}

func sampleMaskPolynomialsF(
	ringQ *ring.Ring,
	params maskSamplerParams,
	rho int,
	extra func(i int) uint64,
) []*ring.Poly {
	q := ringQ.Modulus[0]
	validateMaskSamplerParams(q, params)
	S := maskSamplerS(params.omega, params.maxDeg, q)
	invS0 := ring.ModExp(S[0], q-2, q)
	out := make([]*ring.Poly, rho)
	degreeMod := int(ringQ.N)
	for i := 0; i < rho; i++ {
		sum := uint64(0)
		coeffs := make([]uint64, ringQ.N)
		for k := 1; k <= params.maxDeg; k++ {
			randomCoeff := randUint64Mod(q)
			if k < len(S) {
				sum = modAdd(sum, modMul(randomCoeff, S[k], q), q)
			}
			idx := k % degreeMod
			wraps := k / degreeMod
			if wraps%2 == 0 {
				coeffs[idx] = modAdd(coeffs[idx], randomCoeff, q)
			} else {
				coeffs[idx] = modSub(coeffs[idx], randomCoeff, q)
			}
		}
		if extra != nil {
			sum = modAdd(sum, extra(i)%q, q)
		}
		a0 := modMul(modSub(0, sum%q, q), invS0, q)
		coeffs[0] = modAdd(coeffs[0], a0, q)

		p := ringQ.NewPoly()
		copy(p.Coeffs[0], coeffs[:])
		ringQ.NTT(p, p)
		out[i] = p
	}
	return out
}

func sampleMaskPolynomialsK(
	ringQ *ring.Ring,
	K *kf.Field,
	params maskSamplerParams,
	rho int,
	extra func(i int) kf.Elem,
) []*KPoly {
	if K == nil {
		return nil
	}
	q := ringQ.Modulus[0]
	validateMaskSamplerParams(q, params)
	S := maskSamplerS(params.omega, params.maxDeg, q)
	invS0 := K.Inv(K.EmbedF(S[0] % q))
	out := make([]*KPoly, rho)
	for i := 0; i < rho; i++ {
		kp := newZeroKPoly(K.Theta, int(ringQ.N), params.maxDeg)
		sum := K.Zero()
		for k := 1; k <= params.maxDeg; k++ {
			limbs := make([]uint64, K.Theta)
			for t := 0; t < K.Theta; t++ {
				limbs[t] = randUint64Mod(q)
			}
			coeff := K.Phi(limbs)
			kp.setCoeffK(k, limbs)
			if k < len(S) && S[k]%q != 0 {
				sum = K.Add(sum, K.Mul(coeff, K.EmbedF(S[k]%q)))
			}
		}
		if extra != nil {
			sum = K.Add(sum, extra(i))
		}
		a0 := K.Mul(K.Sub(K.Zero(), sum), invS0)
		kp.setCoeffK(0, K.PhiInv(a0))
		out[i] = kp
	}
	return out
}

// SampleIndependentMaskPolynomials returns rho random polynomials of degree ≤ dQ
// whose evaluations on Ω sum to zero. They are independent from any Fiat–Shamir
// challenges and are used by the LayoutV2 pipeline.
func SampleIndependentMaskPolynomials(
	ringQ *ring.Ring,
	rho, dQ int,
	omega []uint64,
) []*ring.Poly {
	params := maskSamplerParams{omega: omega, maxDeg: dQ}
	return sampleMaskPolynomialsF(ringQ, params, rho, nil)
}

// SampleIndependentMaskPolynomialsK is the extension-field analogue of
// SampleIndependentMaskPolynomials.
func SampleIndependentMaskPolynomialsK(
	ringQ *ring.Ring,
	K *kf.Field,
	rho, dQ int,
	omega []uint64,
) []*KPoly {
	params := maskSamplerParams{omega: omega, maxDeg: dQ}
	return sampleMaskPolynomialsK(ringQ, K, params, rho, nil)
}

func BuildMaskPolynomialsK(
	ringQ *ring.Ring,
	K *kf.Field,
	rho, dQ int,
	omega []uint64,
	GammaPrimeK [][]KScalar,
	GammaAggK [][]KScalar,
	sumFpar []uint64,
	sumFagg []uint64,
) []*KPoly {
	params := maskSamplerParams{omega: omega, maxDeg: dQ}
	extra := func(i int) kf.Elem {
		acc := K.Zero()
		q := ringQ.Modulus[0]
		for t, g := range GammaPrimeK[i] {
			if t < len(sumFpar) {
				acc = K.Add(acc, K.Mul(K.Phi(g), K.EmbedF(sumFpar[t]%q)))
			}
		}
		for u, g := range GammaAggK[i] {
			if u < len(sumFagg) {
				acc = K.Add(acc, K.Mul(K.Phi(g), K.EmbedF(sumFagg[u]%q)))
			}
		}
		return acc
	}
	return sampleMaskPolynomialsK(ringQ, K, params, rho, extra)
}

// randFieldElem draws a uniform element in [0,q) not in the forbidden set.
func randFieldElem(q uint64, forbid map[uint64]struct{}) (uint64, error) {
	if q == 0 {
		return 0, errors.New("q=0")
	}
	bound := ^uint64(0) - (^uint64(0) % q)
	for {
		var buf [8]byte
		if _, err := rand.Read(buf[:]); err != nil {
			return 0, err
		}
		v := uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 | uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56
		if v >= bound {
			continue
		}
		v %= q
		if _, bad := forbid[v]; !bad {
			return v, nil
		}
	}
}

// -----------------------------------------------------------------------------
//  polynomial helpers
// -----------------------------------------------------------------------------

// polyMul naive O(n²)  – sufficient for n ≤ 64.
func polyMul(a, b []uint64, q uint64) []uint64 {
	out := make([]uint64, len(a)+len(b)-1)
	for i, av := range a {
		for j, bv := range b {
			out[i+j] = modAdd(out[i+j], modMul(av, bv, q), q)
		}
	}
	return out
}

// scalePoly returns c·p  (mod q).
func scalePoly(p []uint64, c, q uint64) []uint64 {
	out := make([]uint64, len(p))
	for i, v := range p {
		out[i] = modMul(v, c, q)
	}
	return out
}

// trimPoly removes trailing zero coefficients (mod q) while keeping at least one term.
func trimPoly(coeffs []uint64, q uint64) []uint64 {
	n := len(coeffs)
	for n > 1 {
		if coeffs[n-1]%q != 0 {
			break
		}
		n--
	}
	return coeffs[:n]
}

func reduceModCyclotomic(coeffs []uint64, q uint64, N int) []uint64 {
	if len(coeffs) <= N {
		return trimPoly(coeffs, q)
	}
	res := make([]uint64, N)
	for i, c := range coeffs {
		coeff := c % q
		if coeff == 0 {
			continue
		}
		wraps := i / N
		pos := i % N
		if wraps%2 == 0 {
			res[pos] = modAdd(res[pos], coeff, q)
		} else {
			res[pos] = modSub(res[pos], coeff, q)
		}
	}
	return trimPoly(res, q)
}

// composePolyNTT computes PD(D(X)) and returns it in NTT form.
func composePolyNTT(r *ring.Ring, D *ring.Poly, PD []uint64) *ring.Poly {
	q := r.Modulus[0]
	degPD := len(PD)
	for degPD > 0 && PD[degPD-1]%q == 0 {
		degPD--
	}
	if degPD == 0 {
		return makeConstRow(r, 0)
	}
	coeffD := r.NewPoly()
	r.InvNTT(D, coeffD)
	base := coeffD.Coeffs[0]
	degD := -1
	for i := len(base) - 1; i >= 0; i-- {
		if base[i]%q != 0 {
			degD = i
			break
		}
	}
	var trimmedBase []uint64
	if degD < 0 {
		trimmedBase = []uint64{0}
	} else {
		trimmedBase = append([]uint64(nil), base[:degD+1]...)
	}
	resCoeffs := []uint64{0}
	for idx := degPD - 1; idx >= 0; idx-- {
		resCoeffs = polyMul(resCoeffs, trimmedBase, q)
		if len(resCoeffs) == 0 {
			resCoeffs = []uint64{PD[idx] % q}
		} else {
			resCoeffs[0] = modAdd(resCoeffs[0], PD[idx]%q, q)
		}
	}
	resCoeffs = reduceModCyclotomic(resCoeffs, q, int(r.N))
	out := r.NewPoly()
	copy(out.Coeffs[0], resCoeffs)
	r.NTT(out, out)
	return out
}

// addInto in‑place: dst += src mod q (resize dst if needed).
func addIntoUint(dst *[]uint64, src []uint64, q uint64) {
	if len(src) > len(*dst) {
		newDst := make([]uint64, len(src))
		copy(newDst, *dst)
		*dst = newDst
	}
	for i, v := range src {
		(*dst)[i] = modAdd((*dst)[i], v, q)
	}
}

// resetPoly sets all coefficients of p to zero.
func resetPoly(p *ring.Poly) {
	v := p.Coeffs[0]
	for i := range v {
		v[i] = 0
	}
}

// sumEvals returns Σ_{ω∈Ω} P(ω) mod q. scratch must be a *ring.Poly reused by caller.
func sumEvals(r *ring.Ring, P *ring.Poly, omega []uint64, scratch *ring.Poly) uint64 {
	q := r.Modulus[0]
	r.InvNTT(P, scratch)
	coeffs := scratch.Coeffs[0]
	sum := uint64(0)
	for _, w := range omega {
		sum = modAdd(sum, EvalPoly(coeffs, w%q, q), q)
	}
	return sum
}

// sumPolyList computes ΣΩ for each polynomial in list.
func sumPolyList(r *ring.Ring, polys []*ring.Poly, omega []uint64) []uint64 {
	out := make([]uint64, len(polys))
	scratch := r.NewPoly()
	for i, p := range polys {
		out[i] = sumEvals(r, p, omega, scratch)
	}
	return out
}

// checkOmega ensures Ω has distinct elements and q ∤ |Ω|.
func checkOmega(omega []uint64, q uint64) error {
	seen := make(map[uint64]struct{}, len(omega))
	for _, w := range omega {
		if _, ok := seen[w]; ok {
			return fmt.Errorf("omega has duplicate element %d", w)
		}
		seen[w] = struct{}{}
	}
	if len(omega) == 0 {
		return fmt.Errorf("|Ω| must be > 0")
	}
	if uint64(len(omega)) >= q {
		return fmt.Errorf("|Ω| (= %d) must be < q (= %d) so S0 is invertible", len(omega), q)
	}
	return nil
}

// lagrangeBasisNumerator returns Π_{j≠i} (X - x_j) as a coefficient slice.
func lagrangeBasisNumerator(xs []uint64, i int, q uint64) []uint64 {
	num := []uint64{1}
	for j, xj := range xs {
		if j == i {
			continue
		}
		num = polyMul(num, []uint64{modSub(0, xj, q), 1}, q) // (X - xj)
	}
	return num
}

// Interpolate returns the coefficients of the unique poly of degree <len(xs)
// that satisfies P(xs[k]) = ys[k].  xs must be distinct.
func Interpolate(xs, ys []uint64, q uint64) []uint64 {
	n := len(xs)
	res := make([]uint64, 1) // zero‑poly
	for i := 0; i < n; i++ {
		num := lagrangeBasisNumerator(xs, i, q)
		// denom = Π_{j≠i} (xs[i]-xs[j])
		denom := uint64(1)
		for j, xj := range xs {
			if j == i {
				continue
			}
			denom = modMul(denom, modSub(xs[i], xj, q), q)
		}
		coeff := modMul(ys[i], modInv(denom, q), q)
		term := scalePoly(num, coeff, q)
		addIntoUint(&res, term, q)
	}
	// trim trailing zeros
	for len(res) > 1 && res[len(res)-1] == 0 {
		res = res[:len(res)-1]
	}
	return res
}

// makeConstRow returns a degree-0 polynomial equal to val everywhere.
func makeConstRow(r *ring.Ring, val uint64) *ring.Poly {
	p := r.NewPoly()
	for i := range p.Coeffs[0] {
		p.Coeffs[0][i] = val % r.Modulus[0]
	}
	r.NTT(p, p)
	return p
}

// buildValueRow interpolates a polynomial with prescribed values on Ω.
func buildValueRow(r *ring.Ring, vals, omega []uint64, ell int) *ring.Poly {
	p, _, _, err := BuildRowPolynomial(r, vals, omega, ell)
	if err != nil {
		panic(err)
	}
	return p
}

// scalePolyNTT multiplies polynomial a by scalar c (mod q) and writes to out.
// out may alias a.
func scalePolyNTT(r *ring.Ring, a *ring.Poly, c uint64, out *ring.Poly) {
	if out != a {
		copy(out.Coeffs[0], a.Coeffs[0])
	}
	q := r.Modulus[0]
	c %= q
	for i := range out.Coeffs[0] {
		out.Coeffs[0][i] = modMul(out.Coeffs[0][i], c, q)
	}
}

// makeProductConstraint returns the product polynomial Ψ(X) = W3(X) - W1(X)·W2(X).
// All inputs are in NTT form and Ψ is returned in NTT form as well.
func makeProductConstraint(r *ring.Ring, W1, W2, W3 *ring.Poly) *ring.Poly {
	tmp := r.NewPoly()
	r.MulCoeffs(W1, W2, tmp)
	out := W3.CopyNew()
	r.Sub(out, tmp, out)
	return out
}

// -----------------------------------------------------------------------------
//  Public helper – build P_i(X) with random blinding
// -----------------------------------------------------------------------------

// BuildRowPolynomial takes a witness row (length s), the corresponding
// domain Ω, and a blinding parameter ℓ.  It returns
//   - *ring.Poly in NTT form (degree ≤ s+ℓ-1),
//   - the extra points r[0:ℓ],
//   - their evaluations y[0:ℓ].
//
// Pre‑conditions:  len(row)==len(omega)==s,   ℓ≥1,   xs are all distinct.
func BuildRowPolynomial(ringQ *ring.Ring, row, omega []uint64, ell int) (poly *ring.Poly, rPoints, rEvals []uint64, err error) {
	defer prof.Track(time.Now(), "BuildRowPolynomial")
	if len(row) != len(omega) {
		return nil, nil, nil, errors.New("row and omega length mismatch")
	}
	if ell <= 0 {
		return nil, nil, nil, errors.New("ell must be ≥1")
	}
	q := ringQ.Modulus[0]

	// 1. choose ℓ random points outside Ω
	forbid := make(map[uint64]struct{}, len(omega))
	for _, w := range omega {
		forbid[w] = struct{}{}
	}
	rPoints = make([]uint64, ell)
	for i := 0; i < ell; i++ {
		rp, e := randFieldElem(q, forbid)
		if e != nil {
			return nil, nil, nil, e
		}
		forbid[rp] = struct{}{}
		rPoints[i] = rp
	}

	// 2. choose ℓ random evaluations y_i
	rEvals = make([]uint64, ell)
	for i := 0; i < ell; i++ {
		y, e := randFieldElem(q, nil)
		if e != nil {
			return nil, nil, nil, e
		}
		rEvals[i] = y
	}

	// 3. interpolate over xs = Ω ∪ rPoints, ys = row ∪ rEvals
	xs := append(append([]uint64{}, omega...), rPoints...)
	ys := append(append([]uint64{}, row...), rEvals...)
	coeffs := Interpolate(xs, ys, q) // coeff domain

	// 4. lift to NTT and wrap in *ring.Poly
	poly = ringQ.NewPoly()
	copy(poly.Coeffs[0], coeffs)
	ringQ.NTT(poly, poly)
	return poly, rPoints, rEvals, nil
}

// -----------------------------------------------------------------------------
//  BuildMaskPolynomials
// -----------------------------------------------------------------------------
/*
BuildMaskPolynomials returns ρ random polynomials M₁…Mρ of degree ≤ dQ in
NTT form whose constant term cancels the Ω‑sum of the final
Qᵢ(X) = Mᵢ(X) + Σ_t Γ′_{i,t}F_par,t(X) + Σ_u γ′_{i,u}F_agg,u(X).

Args:
  ringQ       – context (modulus q must not divide len(Ω))
  rho         – number of polynomials
  dQ          – max degree (typically s+ℓ−1)
  omega       – evaluation set Ω
  GammaPrime  – ρ×|F_par| scalars Γ′
  gammaPrime  – ρ×|F_agg| scalars γ′
  sumFpar     – |F_par| precomputed ΣΩ F_par
  sumFagg     – |F_agg| precomputed ΣΩ F_agg

For each i, random coefficients a₁…a_{dQ} are chosen, then a₀ is set so that
ΣΩ Qᵢ(ω) = 0. It panics if q divides |Ω| or Ω has duplicates.
*/
func BuildMaskPolynomials(ringQ *ring.Ring, rho, dQ int, omega []uint64, GammaPrime [][]uint64, gammaPrime [][]uint64, sumFpar []uint64, sumFagg []uint64) []*ring.Poly {
	defer prof.Track(time.Now(), "BuildMaskPolynomials")
	params := maskSamplerParams{omega: omega, maxDeg: dQ}
	q := ringQ.Modulus[0]
	extra := func(i int) uint64 {
		var acc uint64
		for t, g := range GammaPrime[i] {
			if t < len(sumFpar) {
				acc = modAdd(acc, modMul(g%q, sumFpar[t]%q, q), q)
			}
		}
		for u, g := range gammaPrime[i] {
			if u < len(sumFagg) {
				acc = modAdd(acc, modMul(g%q, sumFagg[u]%q, q), q)
			}
		}
		return acc
	}
	M := sampleMaskPolynomialsF(ringQ, params, rho, extra)
	if measure.Enabled {
		qb := new(big.Int).SetUint64(ringQ.Modulus[0])
		bytesR := measure.BytesRing(ringQ.N, qb)
		measure.Global.Add("piop/M", int64(len(M))*int64(bytesR))
	}
	return M
}
