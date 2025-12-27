package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
	"vSIS-Signature/prf"
)

func buildPackingSelectorNTT(ringQ *ring.Ring, ncols int) (*ring.Poly, *ring.Poly, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if ncols <= 0 || ncols > int(ringQ.N) {
		return nil, nil, fmt.Errorf("invalid ncols %d", ncols)
	}
	if ncols%2 != 0 {
		return nil, nil, fmt.Errorf("ncols %d not even for packing selector", ncols)
	}
	selCoeffs, err := buildPackingSelectorCoeff(ringQ, ncols)
	if err != nil {
		return nil, nil, fmt.Errorf("interpolate selector: %w", err)
	}
	selCoeff := ringQ.NewPoly()
	copy(selCoeff.Coeffs[0], selCoeffs)
	selNTT := ringQ.NewPoly()
	ring.Copy(selCoeff, selNTT)
	ringQ.NTT(selNTT, selNTT)
	one := ringQ.NewPoly()
	one.Coeffs[0][0] = 1 % ringQ.Modulus[0]
	ringQ.NTT(one, one)
	oneMinus := ringQ.NewPoly()
	ringQ.Sub(one, selNTT, oneMinus)
	return selNTT, oneMinus, nil
}

// BuildHashConstraints (pre-sign, paper form) enforces the cleared-denominator
// BBS equation with public T:
//
//	(B3 - R1) ⊙ T  -  (B0 + B1·(M1+M2) + B2·R0) = 0
//
// Inputs B must be in NTT; witness polys are in coeff domain; T is provided as
// coeff slice. Returns a single residual poly in NTT.
func BuildHashConstraints(ringQ *ring.Ring, B []*ring.Poly, m1, m2, r0, r1 *ring.Poly, tCoeff []int64) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(B) != 4 {
		return nil, fmt.Errorf("b must have 4 polys, got %d", len(B))
	}
	if m1 == nil || m2 == nil || r0 == nil || r1 == nil {
		return nil, fmt.Errorf("nil hash input poly")
	}
	if len(tCoeff) != ringQ.N {
		return nil, fmt.Errorf("t length mismatch: got %d want %d", len(tCoeff), ringQ.N)
	}
	q := int64(ringQ.Modulus[0])
	// Build T in NTT.
	tPoly := ringQ.NewPoly()
	for i := 0; i < ringQ.N; i++ {
		v := tCoeff[i]
		if v < 0 {
			v += q
		}
		tPoly.Coeffs[0][i] = uint64(v % q)
	}
	ringQ.NTT(tPoly, tPoly)
	// mCombined = m1 + m2 (coeff), then NTT.
	mCombined := ringQ.NewPoly()
	ring.Copy(m1, mCombined)
	ringQ.Add(mCombined, m2, mCombined)
	ringQ.NTT(mCombined, mCombined)
	r0NTT := ringQ.NewPoly()
	r1NTT := ringQ.NewPoly()
	ring.Copy(r0, r0NTT)
	ring.Copy(r1, r1NTT)
	ringQ.NTT(r0NTT, r0NTT)
	ringQ.NTT(r1NTT, r1NTT)
	// num = B0 + B1*(m1+m2) + B2*r0
	num := ringQ.NewPoly()
	tmp := ringQ.NewPoly()
	ring.Copy(B[0], num)
	ringQ.MulCoeffs(B[1], mCombined, tmp)
	ringQ.Add(num, tmp, num)
	ringQ.MulCoeffs(B[2], r0NTT, tmp)
	ringQ.Add(num, tmp, num)
	// den = B3 - r1
	den := ringQ.NewPoly()
	ringQ.Sub(B[3], r1NTT, den)
	// res = den ⊙ T - num
	res := ringQ.NewPoly()
	ringQ.MulCoeffs(den, tPoly, res)
	ringQ.Sub(res, num, res)
	return []*ring.Poly{res}, nil
}

// BuildHashConstraintsNTT enforces the cleared-denominator BBS equation using
// all inputs in the evaluation domain (NTT). This is used for post-signature
// proofs where T is a witness row.
func BuildHashConstraintsNTT(ringQ *ring.Ring, B []*ring.Poly, m1NTT, m2NTT, r0NTT, r1NTT, tNTT *ring.Poly) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(B) != 4 {
		return nil, fmt.Errorf("b must have 4 polys, got %d", len(B))
	}
	if m1NTT == nil || m2NTT == nil || r0NTT == nil || r1NTT == nil || tNTT == nil {
		return nil, fmt.Errorf("nil hash input poly")
	}
	// mCombined = m1 + m2 (NTT).
	mCombined := ringQ.NewPoly()
	ring.Copy(m1NTT, mCombined)
	ringQ.Add(mCombined, m2NTT, mCombined)
	// num = B0 + B1*(m1+m2) + B2*r0
	num := ringQ.NewPoly()
	tmp := ringQ.NewPoly()
	ring.Copy(B[0], num)
	ringQ.MulCoeffs(B[1], mCombined, tmp)
	ringQ.Add(num, tmp, num)
	ringQ.MulCoeffs(B[2], r0NTT, tmp)
	ringQ.Add(num, tmp, num)
	// den = B3 - r1
	den := ringQ.NewPoly()
	ringQ.Sub(B[3], r1NTT, den)
	// res = den ⊙ T - num
	res := ringQ.NewPoly()
	ringQ.MulCoeffs(den, tNTT, res)
	ringQ.Sub(res, num, res)
	return []*ring.Poly{res}, nil
}

// BuildSignatureConstraintNTT builds residual polys for A·U - T with all
// inputs in the evaluation domain (NTT).
func BuildSignatureConstraintNTT(ringQ *ring.Ring, A [][]*ring.Poly, U []*ring.Poly, tNTT *ring.Poly) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(A) == 0 || len(U) == 0 {
		return nil, fmt.Errorf("empty A or U")
	}
	if tNTT == nil {
		return nil, fmt.Errorf("nil T")
	}
	rows := len(A)
	cols := len(A[0])
	if len(U) != cols {
		return nil, fmt.Errorf("u length mismatch: got %d want %d", len(U), cols)
	}
	residuals := make([]*ring.Poly, rows)
	tmp := ringQ.NewPoly()
	for i := 0; i < rows; i++ {
		acc := ringQ.NewPoly()
		for j := 0; j < cols; j++ {
			ringQ.MulCoeffs(A[i][j], U[j], tmp)
			ringQ.Add(acc, tmp, acc)
		}
		ringQ.Sub(acc, tNTT, acc)
		residuals[i] = acc
	}
	return residuals, nil
}

// buildCredentialConstraintSetPreFromRows builds the pre-sign constraint set
// directly from the committed row polynomials (NTT domain). This ensures the
// constraint polynomials include the LVCS tails, matching the paper definition
// F_j(X) = f_j(P(X), Theta(X)) on the full polynomial P.
func buildCredentialConstraintSetPreFromRows(ringQ *ring.Ring, bound int64, pub PublicInputs, rowsNTT []*ring.Poly, ncols int) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if ncols <= 0 || ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("invalid ncols %d", ncols)
	}
	if len(pub.Ac) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing Ac")
	}
	if len(pub.Com) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing Com")
	}
	if len(pub.RI0) == 0 || len(pub.RI1) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing RI0/RI1")
	}
	if len(pub.B) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing B for hash constraint")
	}
	if len(pub.T) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing public T coeffs for hash constraint")
	}
	if len(rowsNTT) < 9 {
		return ConstraintSet{}, fmt.Errorf("rows length %d < 9 (missing K0/K1)", len(rowsNTT))
	}

	// Row order: M1,M2,RU0,RU1,R,R0,R1,K0,K1,(optional T/U...)
	m1NTT := rowsNTT[0]
	m2NTT := rowsNTT[1]
	ru0NTT := rowsNTT[2]
	ru1NTT := rowsNTT[3]
	rNTT := rowsNTT[4]
	r0NTT := rowsNTT[5]
	r1NTT := rowsNTT[6]
	k0NTT := rowsNTT[7]
	k1NTT := rowsNTT[8]

	// Interpolate public polynomials over Ω so constraint evaluation at K-points
	// uses Θ(X) (degree < ncols), not full ring polynomials.
	thetaAc := make([][]*ring.Poly, len(pub.Ac))
	for i := range pub.Ac {
		thetaAc[i] = make([]*ring.Poly, len(pub.Ac[i]))
		for j := range pub.Ac[i] {
			theta, terr := thetaPolyFromNTT(ringQ, pub.Ac[i][j], ncols)
			if terr != nil {
				return ConstraintSet{}, fmt.Errorf("theta Ac[%d][%d]: %w", i, j, terr)
			}
			thetaAc[i][j] = theta
		}
	}
	thetaCom := make([]*ring.Poly, len(pub.Com))
	for i := range pub.Com {
		theta, terr := thetaPolyFromNTT(ringQ, pub.Com[i], ncols)
		if terr != nil {
			return ConstraintSet{}, fmt.Errorf("theta Com[%d]: %w", i, terr)
		}
		thetaCom[i] = theta
	}
	thetaRI0, err := thetaPolyFromNTT(ringQ, pub.RI0[0], ncols)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("theta RI0: %w", err)
	}
	thetaRI1, err := thetaPolyFromNTT(ringQ, pub.RI1[0], ncols)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("theta RI1: %w", err)
	}
	thetaB := make([]*ring.Poly, len(pub.B))
	for i := range pub.B {
		theta, terr := thetaPolyFromNTT(ringQ, pub.B[i], ncols)
		if terr != nil {
			return ConstraintSet{}, fmt.Errorf("theta B[%d]: %w", i, terr)
		}
		thetaB[i] = theta
	}

	// Commit residuals: Ac·[M1||M2||RU0||RU1||R] - Com.
	vec := []*ring.Poly{m1NTT, m2NTT, ru0NTT, ru1NTT, rNTT}
	comRes, err := BuildCommitConstraints(ringQ, thetaAc, vec, thetaCom)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("commit residuals: %w", err)
	}

	centerWrapResidual := func(ru, ri, rVal, kVal *ring.Poly) (*ring.Poly, error) {
		if ru == nil || ri == nil || rVal == nil || kVal == nil {
			return nil, fmt.Errorf("nil center-wrap input poly")
		}
		if bound <= 0 {
			return nil, fmt.Errorf("invalid bound %d", bound)
		}
		q := ringQ.Modulus[0]
		delta := uint64((2*bound + 1) % int64(q))
		// res = RU + RI - R - delta*K   (all in NTT / evaluation domain)
		res := ringQ.NewPoly()
		ringQ.Add(ru, ri, res)
		ringQ.Sub(res, rVal, res)
		tmp := ringQ.NewPoly()
		scalePolyNTT(ringQ, kVal, delta, tmp)
		ringQ.Sub(res, tmp, res)
		return res, nil
	}

	// Center residuals.
	centerRes0, err := centerWrapResidual(ru0NTT, thetaRI0, r0NTT, k0NTT)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("center wrap residual 0: %w", err)
	}
	centerRes1, err := centerWrapResidual(ru1NTT, thetaRI1, r1NTT, k1NTT)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("center wrap residual 1: %w", err)
	}
	centerRes := []*ring.Poly{centerRes0, centerRes1}

	// Packing constraints (evaluation-domain): enforce m1 occupies lower half,
	// m2 upper half over Ω of length ncols.
	if ncols%2 != 0 {
		return ConstraintSet{}, fmt.Errorf("ncols %d is not even for packing", ncols)
	}
	selNTT, oneMinusSel, err := buildPackingSelectorNTT(ringQ, ncols)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("packing selector: %w", err)
	}
	m1Pack := ringQ.NewPoly()
	m2Pack := ringQ.NewPoly()
	ringQ.MulCoeffs(selNTT, m1NTT, m1Pack)
	ringQ.MulCoeffs(oneMinusSel, m2NTT, m2Pack)

	// Hash constraint: T = HashMessage(B, M1, M2, R0, R1).
	toCoeff := func(p *ring.Poly) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		ringQ.InvNTT(cp, cp)
		return cp
	}
	// Interpolate public T over Ω to get Θ_T (degree < ncols), then pass
	// its coefficients to the hash gadget.
	tNTT := ringQ.NewPoly()
	q64 := int64(ringQ.Modulus[0])
	for i := 0; i < ringQ.N && i < len(pub.T); i++ {
		v := pub.T[i]
		if v < 0 {
			v += q64
		}
		tNTT.Coeffs[0][i] = uint64(v % q64)
	}
	ringQ.NTT(tNTT, tNTT)
	tThetaCoeff, err := thetaCoeffFromNTT(ringQ, tNTT, ncols)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("theta T: %w", err)
	}
	tThetaInt := make([]int64, len(tThetaCoeff))
	for i := range tThetaCoeff {
		tThetaInt[i] = int64(tThetaCoeff[i])
	}
	hashRes, err := BuildHashConstraints(
		ringQ,
		thetaB,
		toCoeff(m1NTT),
		toCoeff(m2NTT),
		toCoeff(r0NTT),
		toCoeff(r1NTT),
		tThetaInt,
	)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("hash residuals: %w", err)
	}

	// Bounds (evaluation-domain composition): enforce membership in [-B,B] for
	// witness rows, and [-1,1] for K0/K1.
	q := ringQ.Modulus[0]
	if bound > int64(^uint(0)>>1) {
		return ConstraintSet{}, fmt.Errorf("bound too large for membership spec: %d", bound)
	}
	specVal := NewRangeMembershipSpec(q, int(bound))
	boundedRows := []*ring.Poly{m1NTT, m2NTT, ru0NTT, ru1NTT, rNTT, r0NTT, r1NTT}
	fparBounds := buildFparRangeMembershipCompose(ringQ, boundedRows, specVal)
	specCarry := NewRangeMembershipSpec(q, 1)
	fparCarry := buildFparRangeMembershipCompose(ringQ, []*ring.Poly{k0NTT, k1NTT}, specCarry)
	fparBounds = append(fparBounds, fparCarry...)

	return ConstraintSet{
		FparInt:  append(append(append(comRes, centerRes...), hashRes...), m1Pack, m2Pack),
		FparNorm: fparBounds,
	}, nil
}

// buildCredentialConstraintSetPostFromRows builds the post-sign constraint set
// (signature, hash, packing, bounds) directly from committed row polynomials
// in NTT form. Row order is assumed to be:
// M1,M2,RU0,RU1,R,R0,R1,K0,K1,T,U...
func buildCredentialConstraintSetPostFromRows(ringQ *ring.Ring, bound int64, pub PublicInputs, rowsNTT []*ring.Poly, ncols int) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if ncols <= 0 || ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("invalid ncols %d", ncols)
	}
	if len(pub.A) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing A for signature constraint")
	}
	if len(pub.B) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing B for hash constraint")
	}
	if len(rowsNTT) < 10 {
		return ConstraintSet{}, fmt.Errorf("rows length %d < 10 (missing T/U)", len(rowsNTT))
	}
	uCount := len(pub.A[0])
	if uCount == 0 {
		return ConstraintSet{}, fmt.Errorf("empty A columns")
	}
	tIdx := 9
	uStart := tIdx + 1
	if len(rowsNTT) < uStart+uCount {
		return ConstraintSet{}, fmt.Errorf("rows length %d < %d for U rows", len(rowsNTT), uStart+uCount)
	}

	m1NTT := rowsNTT[0]
	m2NTT := rowsNTT[1]
	r0NTT := rowsNTT[5]
	r1NTT := rowsNTT[6]
	tNTT := rowsNTT[tIdx]
	uRows := rowsNTT[uStart : uStart+uCount]

	thetaA := make([][]*ring.Poly, len(pub.A))
	for i := range pub.A {
		thetaA[i] = make([]*ring.Poly, len(pub.A[i]))
		for j := range pub.A[i] {
			theta, terr := thetaPolyFromNTT(ringQ, pub.A[i][j], ncols)
			if terr != nil {
				return ConstraintSet{}, fmt.Errorf("theta A[%d][%d]: %w", i, j, terr)
			}
			thetaA[i][j] = theta
		}
	}
	thetaB := make([]*ring.Poly, len(pub.B))
	for i := range pub.B {
		theta, terr := thetaPolyFromNTT(ringQ, pub.B[i], ncols)
		if terr != nil {
			return ConstraintSet{}, fmt.Errorf("theta B[%d]: %w", i, terr)
		}
		thetaB[i] = theta
	}

	sigRes, err := BuildSignatureConstraintNTT(ringQ, thetaA, uRows, tNTT)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("signature residuals: %w", err)
	}
	hashRes, err := BuildHashConstraintsNTT(ringQ, thetaB, m1NTT, m2NTT, r0NTT, r1NTT, tNTT)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("hash residuals: %w", err)
	}

	if ncols%2 != 0 {
		return ConstraintSet{}, fmt.Errorf("ncols %d is not even for packing", ncols)
	}
	selNTT, oneMinusSel, err := buildPackingSelectorNTT(ringQ, ncols)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("packing selector: %w", err)
	}
	m1Pack := ringQ.NewPoly()
	m2Pack := ringQ.NewPoly()
	ringQ.MulCoeffs(selNTT, m1NTT, m1Pack)
	ringQ.MulCoeffs(oneMinusSel, m2NTT, m2Pack)

	q := ringQ.Modulus[0]
	specVal := NewRangeMembershipSpec(q, int(bound))
	boundedRows := []*ring.Poly{m1NTT, m2NTT, r0NTT, r1NTT}
	fparBounds := buildFparRangeMembershipCompose(ringQ, boundedRows, specVal)

	fparInt := append(sigRes, hashRes...)
	fparInt = append(fparInt, m1Pack, m2Pack)
	return ConstraintSet{
		FparInt:  fparInt,
		FparNorm: fparBounds,
	}, nil
}

// BuildCredentialConstraintSetPre builds the constraint set for the pre-signature
// credential proof (Com/center/hash/bounds).
func BuildCredentialConstraintSetPre(ringQ *ring.Ring, bound int64, pub PublicInputs, wit WitnessInputs, ncols int) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if ncols <= 0 || ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("invalid ncols %d", ncols)
	}
	if len(pub.Ac) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing Ac")
	}
	if len(pub.Com) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing Com")
	}
	if len(pub.RI0) == 0 || len(pub.RI1) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing RI0/RI1")
	}
	// Witness presence checks.
	require := func(vec []*ring.Poly, name string) error {
		if len(vec) == 0 {
			return fmt.Errorf("missing witness %s", name)
		}
		return nil
	}
	if err := require(wit.M1, "M1"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.M2, "M2"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.RU0, "RU0"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.RU1, "RU1"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.R, "R"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.R0, "R0"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.R1, "R1"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.K0, "K0"); err != nil {
		return ConstraintSet{}, err
	}
	if err := require(wit.K1, "K1"); err != nil {
		return ConstraintSet{}, err
	}
	ensureNTT := func(p *ring.Poly) *ring.Poly {
		if p == nil {
			return nil
		}
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		ringQ.NTT(cp, cp)
		return cp
	}

	// Basic bound sanity on witness polys (evaluation domain).
	allWits := []*ring.Poly{wit.M1[0], wit.M2[0], wit.RU0[0], wit.RU1[0], wit.R[0], wit.R0[0], wit.R1[0], wit.K0[0], wit.K1[0]}
	nttWits := make([]*ring.Poly, len(allWits))
	for i := range allWits {
		nttWits[i] = ensureNTT(allWits[i])
	}
	if err := BuildBoundConstraintsEvalDomain(ringQ, nttWits, bound); err != nil {
		return ConstraintSet{}, fmt.Errorf("bound check failed: %w", err)
	}

	rowsNTT := []*ring.Poly{
		ensureNTT(wit.M1[0]),
		ensureNTT(wit.M2[0]),
		ensureNTT(wit.RU0[0]),
		ensureNTT(wit.RU1[0]),
		ensureNTT(wit.R[0]),
		ensureNTT(wit.R0[0]),
		ensureNTT(wit.R1[0]),
		ensureNTT(wit.K0[0]),
		ensureNTT(wit.K1[0]),
	}
	// Use the same row-based builder (without LVCS tails).
	return buildCredentialConstraintSetPreFromRows(ringQ, bound, pub, rowsNTT, ncols)
}

// BuildPRFConstraintSet constructs the parallel constraints for tag = F(m2, nonce)
// using the Poseidon2-like params in prfParams. This follows the degree-5
// arithmetization (no quadraticization), introducing degree-5 constraints for
// each round/lanes transition and linear constraints for the feed-forward/tag.
//
// Inputs:
//   - ringQ: PCS ring
//   - prfParams: PRF Params (ME/MI/cExt/cInt/d/RF/RP/lentag)
//   - rows: flattened witness rows containing the PRF trace (row polynomials).
//     Rows are expected in NTT (evaluation-domain) form.
//     The slice must contain (R+1)*t consecutive rows starting at startIdx,
//     where R = RF+RP and t = LenKey+LenNonce.
//   - startIdx: index into rows where x^(0)_0 is stored; row order is
//     x^(r)_j = rows[startIdx + r*t + j].
//   - tagPublic: public tag values on Ω (len= lentag, each length ≥ ncols)
//   - noncePublic: optional nonce values on Ω (lenNonce lanes), each length ≥ ncols.
//   - ncols: |Ω|. If 0, defaults to ring dimension.
//
// Output: ConstraintSet with FparInt populated; no bounds or agg constraints.
func BuildPRFConstraintSet(ringQ *ring.Ring, prfParams *prf.Params, rows []*ring.Poly, startIdx int, tagPublic [][]int64, noncePublic [][]int64, ncols int) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if prfParams == nil {
		return ConstraintSet{}, fmt.Errorf("nil prf params")
	}
	if err := prfParams.Validate(); err != nil {
		return ConstraintSet{}, fmt.Errorf("prf params invalid: %w", err)
	}
	if ncols <= 0 {
		ncols = ringQ.N
	}
	if ncols > int(ringQ.N) {
		return ConstraintSet{}, fmt.Errorf("invalid ncols %d", ncols)
	}
	R := prfParams.RF + prfParams.RP
	t := prfParams.T()
	need := startIdx + (R+1)*t
	if startIdx < 0 || need > len(rows) {
		return ConstraintSet{}, fmt.Errorf("rows len=%d too small for PRF trace (need %d from %d)", len(rows), (R+1)*t, startIdx)
	}
	if len(tagPublic) != prfParams.LenTag {
		return ConstraintSet{}, fmt.Errorf("tag lanes=%d want %d", len(tagPublic), prfParams.LenTag)
	}
	for i := range tagPublic {
		if len(tagPublic[i]) < ncols {
			return ConstraintSet{}, fmt.Errorf("tag lane %d len=%d < ncols=%d", i, len(tagPublic[i]), ncols)
		}
	}
	if noncePublic != nil && len(noncePublic) != prfParams.LenNonce {
		return ConstraintSet{}, fmt.Errorf("nonce lanes=%d want %d", len(noncePublic), prfParams.LenNonce)
	}
	if noncePublic != nil {
		for i := range noncePublic {
			if len(noncePublic[i]) < ncols {
				return ConstraintSet{}, fmt.Errorf("nonce lane %d len=%d < ncols=%d", i, len(noncePublic[i]), ncols)
			}
		}
	}
	q := int64(ringQ.Modulus[0])

	getState := func(r, j int) *ring.Poly {
		return rows[startIdx+r*t+j]
	}
	powNTT := func(p *ring.Poly, c uint64, d uint64) *ring.Poly {
		out := ringQ.NewPoly()
		for i := 0; i < ringQ.N; i++ {
			v := (p.Coeffs[0][i] + c) % uint64(q)
			res := uint64(1)
			base := v
			exp := d
			for exp > 0 {
				if exp&1 == 1 {
					res = (res * base) % uint64(q)
				}
				base = (base * base) % uint64(q)
				exp >>= 1
			}
			out.Coeffs[0][i] = res
		}
		return out
	}
	scaleNTT := func(p *ring.Poly, scalar uint64) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		for i := 0; i < ringQ.N; i++ {
			cp.Coeffs[0][i] = (cp.Coeffs[0][i] * scalar) % uint64(q)
		}
		return cp
	}

	// Interpolate public Tag/Nonce over Ω for Θ(X).
	tagTheta, _, err := buildPRFThetaPolys(ringQ, tagPublic, ncols)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("tag theta: %w", err)
	}
	var nonceTheta []*ring.Poly
	if noncePublic != nil {
		nonceTheta, _, err = buildPRFThetaPolys(ringQ, noncePublic, ncols)
		if err != nil {
			return ConstraintSet{}, fmt.Errorf("nonce theta: %w", err)
		}
	}

	residuals := make([]*ring.Poly, 0, (prfParams.RF+prfParams.RP)*t+prfParams.LenTag)

	rIdx := 0
	// External rounds (first half)
	for r := 0; r < prfParams.RF/2; r++ {
		lanePow := make([]*ring.Poly, t)
		for i := 0; i < t; i++ {
			lanePow[i] = powNTT(getState(rIdx, i), prfParams.CExt[r][i]%uint64(q), prfParams.D)
		}
		for j := 0; j < t; j++ {
			acc := ringQ.NewPoly()
			for i := 0; i < t; i++ {
				term := scaleNTT(lanePow[i], prfParams.ME[j][i]%uint64(q))
				ringQ.Add(acc, term, acc)
			}
			res := ringQ.NewPoly()
			ring.Copy(acc, res)
			ringQ.Sub(res, getState(rIdx+1, j), res)
			residuals = append(residuals, res)
		}
		rIdx++
	}
	// Internal rounds
	for ir := 0; ir < prfParams.RP; ir++ {
		u1Pow := powNTT(getState(rIdx, 0), prfParams.CInt[ir]%uint64(q), prfParams.D)
		for j := 0; j < t; j++ {
			acc := ringQ.NewPoly()
			term0 := scaleNTT(u1Pow, prfParams.MI[j][0]%uint64(q))
			ringQ.Add(acc, term0, acc)
			for i := 1; i < t; i++ {
				term := scaleNTT(getState(rIdx, i), prfParams.MI[j][i]%uint64(q))
				ringQ.Add(acc, term, acc)
			}
			res := ringQ.NewPoly()
			ring.Copy(acc, res)
			ringQ.Sub(res, getState(rIdx+1, j), res)
			residuals = append(residuals, res)
		}
		rIdx++
	}
	// External rounds (second half)
	for r := prfParams.RF / 2; r < prfParams.RF; r++ {
		lanePow := make([]*ring.Poly, t)
		for i := 0; i < t; i++ {
			lanePow[i] = powNTT(getState(rIdx, i), prfParams.CExt[r][i]%uint64(q), prfParams.D)
		}
		for j := 0; j < t; j++ {
			acc := ringQ.NewPoly()
			for i := 0; i < t; i++ {
				term := scaleNTT(lanePow[i], prfParams.ME[j][i]%uint64(q))
				ringQ.Add(acc, term, acc)
			}
			res := ringQ.NewPoly()
			ring.Copy(acc, res)
			ringQ.Sub(res, getState(rIdx+1, j), res)
			residuals = append(residuals, res)
		}
		rIdx++
	}

	// Tag binding: x^(R)_j + x^(0)_j - tag_j^public = 0 for j<lentag.
	finalStateIdx := R
	for j := 0; j < prfParams.LenTag; j++ {
		res := ringQ.NewPoly()
		ringQ.Add(getState(finalStateIdx, j), getState(0, j), res)
		ringQ.Sub(res, tagTheta[j], res)
		residuals = append(residuals, res)
	}

	// Nonce binding (public): x^(0)_{lenkey + j} - nonce_j = 0.
	if noncePublic != nil {
		for j := 0; j < prfParams.LenNonce; j++ {
			res := ringQ.NewPoly()
			ringQ.Sub(getState(0, prfParams.LenKey+j), nonceTheta[j], res)
			residuals = append(residuals, res)
		}
	}

	return ConstraintSet{FparInt: residuals}, nil
}
