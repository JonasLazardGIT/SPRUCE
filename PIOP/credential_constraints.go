package PIOP

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
	"vSIS-Signature/prf"
)

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

// BuildCredentialConstraintSetPre builds the constraint set for the pre-signature
// credential proof (Com/center/hash/bounds).
func BuildCredentialConstraintSetPre(ringQ *ring.Ring, bound int64, pub PublicInputs, wit WitnessInputs) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
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
	// Basic bound sanity on witness polys (coeff domain).
	allWits := []*ring.Poly{wit.M1[0], wit.M2[0], wit.RU0[0], wit.RU1[0], wit.R[0], wit.R0[0], wit.R1[0], wit.K0[0], wit.K1[0]}
	if err := BuildBoundConstraints(ringQ, allWits, bound); err != nil {
		return ConstraintSet{}, fmt.Errorf("bound check failed: %w", err)
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

	centerWrapResidual := func(ruNTT, riNTT, rNTT, kNTT *ring.Poly) (*ring.Poly, error) {
		if ruNTT == nil || riNTT == nil || rNTT == nil || kNTT == nil {
			return nil, fmt.Errorf("nil center-wrap input poly")
		}
		if bound <= 0 {
			return nil, fmt.Errorf("invalid bound %d", bound)
		}
		q := ringQ.Modulus[0]
		delta := uint64((2*bound + 1) % int64(q))
		// res = RU + RI - R - delta*K   (all in NTT / evaluation domain)
		res := ringQ.NewPoly()
		ringQ.Add(ruNTT, riNTT, res)
		ringQ.Sub(res, rNTT, res)
		tmp := ringQ.NewPoly()
		scalePolyNTT(ringQ, kNTT, delta, tmp)
		ringQ.Sub(res, tmp, res)
		return res, nil
	}

	// Commit residuals: Ac·[M1||M2||RU0||RU1||R] - Com.
	vec := []*ring.Poly{
		ensureNTT(wit.M1[0]),
		ensureNTT(wit.M2[0]),
		ensureNTT(wit.RU0[0]),
		ensureNTT(wit.RU1[0]),
		ensureNTT(wit.R[0]),
	}
	comRes, err := BuildCommitConstraints(ringQ, pub.Ac, vec, pub.Com)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("commit residuals: %w", err)
	}

	// Center residuals (paper-faithful wrap form):
	// RU* + RI* = R* + (2B+1)·K* where K* ∈ {-1,0,1}.
	centerRes0, err := centerWrapResidual(
		ensureNTT(wit.RU0[0]),
		ensureNTT(pub.RI0[0]),
		ensureNTT(wit.R0[0]),
		ensureNTT(wit.K0[0]),
	)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("center wrap residual 0: %w", err)
	}
	centerRes1, err := centerWrapResidual(
		ensureNTT(wit.RU1[0]),
		ensureNTT(pub.RI1[0]),
		ensureNTT(wit.R1[0]),
		ensureNTT(wit.K1[0]),
	)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("center wrap residual 1: %w", err)
	}
	centerRes := []*ring.Poly{centerRes0, centerRes1}

	// Packing constraints: enforce m1 occupies lower half, m2 upper half.
	if ringQ.N%2 != 0 {
		return ConstraintSet{}, fmt.Errorf("ring dimension %d is not even for packing", ringQ.N)
	}
	half := ringQ.N / 2
	buildPackingResidual := func(src *ring.Poly, keepLower bool) *ring.Poly {
		coeff := ringQ.NewPoly()
		ring.Copy(src, coeff)
		ringQ.InvNTT(coeff, coeff)
		resCoeff := ringQ.NewPoly()
		for i := 0; i < ringQ.N; i++ {
			if keepLower {
				if i < half {
					continue
				}
			} else {
				if i >= half {
					continue
				}
			}
			resCoeff.Coeffs[0][i] = coeff.Coeffs[0][i]
		}
		ringQ.NTT(resCoeff, resCoeff)
		return resCoeff
	}
	m1Pack := buildPackingResidual(ensureNTT(wit.M1[0]), true)
	m2Pack := buildPackingResidual(ensureNTT(wit.M2[0]), false)

	// Hash constraint: T = HashMessage(B, M1, M2, R0, R1).
	if len(pub.B) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing B for hash constraint")
	}
	if len(pub.T) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing public T coeffs for hash constraint")
	}
	if len(wit.T) > 0 && len(wit.T) != len(pub.T) {
		return ConstraintSet{}, fmt.Errorf("t length mismatch: witness=%d public=%d", len(wit.T), len(pub.T))
	}
	for i := 0; i < len(wit.T) && i < len(pub.T); i++ {
		if wit.T[i] != pub.T[i] {
			return ConstraintSet{}, fmt.Errorf("t mismatch between witness and public at %d", i)
		}
	}
	// If desired, an explicit guard for non-zero denominators could be added here.
	// Currently we accept the negligible abort-on-invertible-failure event.
	hashRes, err := BuildHashConstraints(
		ringQ,
		pub.B,
		wit.M1[0],
		wit.M2[0],
		wit.R0[0],
		wit.R1[0],
		pub.T,
	)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("hash residuals: %w", err)
	}

	// In-circuit coefficient bounds (Option B): enforce membership in [-B,B]
	// for all witness rows, and in [-1,1] for carry rows K0/K1.
	q := ringQ.Modulus[0]
	if bound > int64(^uint(0)>>1) {
		return ConstraintSet{}, fmt.Errorf("bound too large for membership spec: %d", bound)
	}
	specVal := NewRangeMembershipSpec(q, int(bound))
	// Note: buildFparRangeMembership expects NTT-domain inputs and applies P_B to
	// the coefficient representation (after InvNTT), which matches our "single
	// ring element per witness row" encoding.
	boundedRows := []*ring.Poly{
		ensureNTT(wit.M1[0]),
		ensureNTT(wit.M2[0]),
		ensureNTT(wit.RU0[0]),
		ensureNTT(wit.RU1[0]),
		ensureNTT(wit.R[0]),
		ensureNTT(wit.R0[0]),
		ensureNTT(wit.R1[0]),
	}
	fparBounds := buildFparRangeMembership(ringQ, boundedRows, specVal)
	specCarry := NewRangeMembershipSpec(q, 1)
	fparCarry := buildFparRangeMembership(ringQ, []*ring.Poly{
		ensureNTT(wit.K0[0]),
		ensureNTT(wit.K1[0]),
	}, specCarry)
	fparBounds = append(fparBounds, fparCarry...)

	return ConstraintSet{
		FparInt:  append(append(append(comRes, centerRes...), hashRes...), m1Pack, m2Pack),
		FparNorm: fparBounds,
		// FaggInt/FaggNorm intentionally empty for pre-sign: pure Fpar statement.
	}, nil
}

// BuildPRFConstraintSet constructs the parallel constraints for tag = F(m2, nonce)
// using the Poseidon2-like params in prfParams. This follows the degree-5
// arithmetization (no quadraticization), introducing degree-5 constraints for
// each round/lanes transition and linear constraints for the feed-forward/tag.
//
// Inputs:
//   - ringQ: PCS ring
//   - prfParams: PRF Params (ME/MI/cExt/cInt/d/RF/RP/lentag)
//   - rows: flattened witness rows containing the PRF trace, in coeff domain.
//     The slice must contain (R+1)*t consecutive rows starting at startIdx,
//     where R = RF+RP and t = LenKey+LenNonce.
//   - startIdx: index into rows where x^(0)_0 is stored; row order is
//     x^(r)_j = rows[startIdx + r*t + j].
//   - tagPublic: public tag coeffs (len = lentag * N) flattened per lane.
//   - noncePublic: optional nonce lanes (lenNonce), each of length N; if nil, nonce is not bound.
//
// Output: ConstraintSet with FparInt populated; no bounds or agg constraints.
func BuildPRFConstraintSet(ringQ *ring.Ring, prfParams *prf.Params, rows []*ring.Poly, startIdx int, tagPublic [][]int64, noncePublic [][]int64) (ConstraintSet, error) {
	if ringQ == nil {
		return ConstraintSet{}, fmt.Errorf("nil ring")
	}
	if prfParams == nil {
		return ConstraintSet{}, fmt.Errorf("nil prf params")
	}
	if err := prfParams.Validate(); err != nil {
		return ConstraintSet{}, fmt.Errorf("prf params invalid: %w", err)
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
		if len(tagPublic[i]) != ringQ.N {
			return ConstraintSet{}, fmt.Errorf("tag lane %d len=%d want %d", i, len(tagPublic[i]), ringQ.N)
		}
	}
	if noncePublic != nil && len(noncePublic) != prfParams.LenNonce {
		return ConstraintSet{}, fmt.Errorf("nonce lanes=%d want %d", len(noncePublic), prfParams.LenNonce)
	}
	if noncePublic != nil {
		for i := range noncePublic {
			if len(noncePublic[i]) != ringQ.N {
				return ConstraintSet{}, fmt.Errorf("nonce lane %d len=%d want %d", i, len(noncePublic[i]), ringQ.N)
			}
		}
	}
	q := int64(ringQ.Modulus[0])

	// Witness states are expected in coeff domain. Copy as-is (no InvNTT).
	toCoeff := func(p *ring.Poly) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		return cp
	}
	toNTT := func(p *ring.Poly) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		ringQ.NTT(cp, cp)
		return cp
	}
	getState := func(r, j int) *ring.Poly {
		return rows[startIdx+r*t+j]
	}
	powCoeff := func(coeff *ring.Poly, d uint64) *ring.Poly {
		for i := 0; i < ringQ.N; i++ {
			v := coeff.Coeffs[0][i] % uint64(q)
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
			coeff.Coeffs[0][i] = res
		}
		return toNTT(coeff)
	}
	scaleNTT := func(p *ring.Poly, scalar uint64) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		for i := 0; i < ringQ.N; i++ {
			cp.Coeffs[0][i] = (cp.Coeffs[0][i] * scalar) % uint64(q)
		}
		return cp
	}

	residuals := make([]*ring.Poly, 0, (prfParams.RF+prfParams.RP)*t+prfParams.LenTag)

	rIdx := 0
	// External rounds (first half)
	for r := 0; r < prfParams.RF/2; r++ {
		lanePow := make([]*ring.Poly, t)
		for i := 0; i < t; i++ {
			coeff := toCoeff(getState(rIdx, i))
			for idx := 0; idx < ringQ.N; idx++ {
				coeff.Coeffs[0][idx] = (coeff.Coeffs[0][idx] + prfParams.CExt[r][i]) % uint64(q)
			}
			lanePow[i] = powCoeff(coeff, prfParams.D)
		}
		for j := 0; j < t; j++ {
			acc := ringQ.NewPoly()
			for i := 0; i < t; i++ {
				term := scaleNTT(lanePow[i], prfParams.ME[j][i]%uint64(q))
				ringQ.Add(acc, term, acc)
			}
			res := ringQ.NewPoly()
			ring.Copy(acc, res)
			nextNTT := toNTT(getState(rIdx+1, j))
			ringQ.Sub(res, nextNTT, res)
			residuals = append(residuals, res)
		}
		rIdx++
	}
	// Internal rounds
	for ir := 0; ir < prfParams.RP; ir++ {
		prevBase := getState(rIdx, 0)
		u1 := toCoeff(prevBase)
		ring.Copy(getState(rIdx, 0), u1)
		for idx := 0; idx < ringQ.N; idx++ {
			u1.Coeffs[0][idx] = (u1.Coeffs[0][idx] + prfParams.CInt[ir]) % uint64(q)
		}
		u1Pow := powCoeff(u1, prfParams.D)
		for j := 0; j < t; j++ {
			acc := ringQ.NewPoly()
			term0 := scaleNTT(u1Pow, prfParams.MI[j][0]%uint64(q))
			ringQ.Add(acc, term0, acc)
			for i := 1; i < t; i++ {
				term := toNTT(getState(rIdx, i))
				term = scaleNTT(term, prfParams.MI[j][i]%uint64(q))
				ringQ.Add(acc, term, acc)
			}
			res := ringQ.NewPoly()
			ring.Copy(acc, res)
			nextNTT := toNTT(getState(rIdx+1, j))
			ringQ.Sub(res, nextNTT, res)
			residuals = append(residuals, res)
		}
		rIdx++
	}
	// External rounds (second half)
	for r := prfParams.RF / 2; r < prfParams.RF; r++ {
		lanePow := make([]*ring.Poly, t)
		for i := 0; i < t; i++ {
			coeff := toCoeff(getState(rIdx, i))
			for idx := 0; idx < ringQ.N; idx++ {
				coeff.Coeffs[0][idx] = (coeff.Coeffs[0][idx] + prfParams.CExt[r][i]) % uint64(q)
			}
			lanePow[i] = powCoeff(coeff, prfParams.D)
		}
		for j := 0; j < t; j++ {
			acc := ringQ.NewPoly()
			for i := 0; i < t; i++ {
				term := scaleNTT(lanePow[i], prfParams.ME[j][i]%uint64(q))
				ringQ.Add(acc, term, acc)
			}
			res := ringQ.NewPoly()
			ring.Copy(acc, res)
			nextNTT := toNTT(getState(rIdx+1, j))
			ringQ.Sub(res, nextNTT, res)
			residuals = append(residuals, res)
		}
		rIdx++
	}

	// Tag binding: x^(R)_j + x^(0)_j - tag_j^public = 0 for j<lentag.
	finalStateIdx := R
	for j := 0; j < prfParams.LenTag; j++ {
		pub := ringQ.NewPoly()
		for idx := 0; idx < ringQ.N; idx++ {
			v := tagPublic[j][idx]
			if v < 0 {
				v += q
			}
			pub.Coeffs[0][idx] = uint64(v % q)
		}
		ringQ.NTT(pub, pub)
		res := ringQ.NewPoly()
		initNTT := toNTT(getState(0, j))
		finalNTT := toNTT(getState(finalStateIdx, j))
		ringQ.Add(finalNTT, initNTT, res)
		ringQ.Sub(res, pub, res)
		residuals = append(residuals, res)
	}

	// Nonce binding (public): x^(0)_{lenkey + j} - nonce_j = 0.
	if noncePublic != nil {
		for j := 0; j < prfParams.LenNonce; j++ {
			pub := ringQ.NewPoly()
			for idx := 0; idx < ringQ.N; idx++ {
				v := noncePublic[j][idx]
				if v < 0 {
					v += q
				}
				pub.Coeffs[0][idx] = uint64(v % q)
			}
			ringQ.NTT(pub, pub)
			res := ringQ.NewPoly()
			initNTT := toNTT(getState(0, prfParams.LenKey+j))
			ringQ.Sub(initNTT, pub, res)
			residuals = append(residuals, res)
		}
	}

	return ConstraintSet{FparInt: residuals}, nil
}
