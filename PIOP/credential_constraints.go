package PIOP

import (
	"fmt"

	vsishash "vSIS-Signature/vSIS-HASH"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// BuildHashConstraints enforces T = HashMessage(B, m1, m2, r0, r1) by computing
// the BBS hash from explicit polys and returning a single residual poly
// (hashNTT - tNTT). Inputs B must be in NTT, witnesses in coeff domain; T is
// provided as coeff slice.
func BuildHashConstraints(ringQ *ring.Ring, B []*ring.Poly, m1, m2, r0, r1 *ring.Poly, tCoeff []int64) ([]*ring.Poly, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if len(B) != 4 {
		return nil, fmt.Errorf("B must have 4 polys, got %d", len(B))
	}
	if m1 == nil || m2 == nil || r0 == nil || r1 == nil {
		return nil, fmt.Errorf("nil hash input poly")
	}
	if len(tCoeff) != ringQ.N {
		return nil, fmt.Errorf("T length mismatch: got %d want %d", len(tCoeff), ringQ.N)
	}
	clone := func(p *ring.Poly) *ring.Poly {
		cp := ringQ.NewPoly()
		ring.Copy(p, cp)
		return cp
	}
	mCombined := clone(m1)
	ringQ.Add(mCombined, m2, mCombined)
	mPoly := clone(mCombined)
	x0 := clone(r0)
	x1 := clone(r1)

	hashNTT, err := vsishash.ComputeBBSHash(ringQ, B, mPoly, x0, x1)
	if err != nil {
		return nil, fmt.Errorf("compute hash: %w", err)
	}
	tPoly := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i := 0; i < ringQ.N; i++ {
		v := tCoeff[i]
		if v < 0 {
			v += q
		}
		tPoly.Coeffs[0][i] = uint64(v % q)
	}
	ringQ.NTT(tPoly, tPoly)

	res := ringQ.NewPoly()
	ringQ.Sub(hashNTT, tPoly, res)
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
	// Basic bound sanity on witness polys (coeff domain).
	allWits := []*ring.Poly{wit.M1[0], wit.M2[0], wit.RU0[0], wit.RU1[0], wit.R[0], wit.R0[0], wit.R1[0]}
	if err := BuildBoundConstraints(allWits, bound); err != nil {
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

	// Center residuals: center(RU*+RI*) - R*.
	ru := []*ring.Poly{ensureNTT(wit.RU0[0]), ensureNTT(wit.RU1[0])}
	ri := []*ring.Poly{ensureNTT(pub.RI0[0]), ensureNTT(pub.RI1[0])}
	rv := []*ring.Poly{ensureNTT(wit.R0[0]), ensureNTT(wit.R1[0])}
	centerRes, err := BuildCenterConstraints(ringQ, bound, ru, ri, rv)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("center residuals: %w", err)
	}

	// Hash constraint: T = HashMessage(B, M1, M2, R0, R1).
	if len(pub.B) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing B for hash constraint")
	}
	if len(wit.T) == 0 {
		return ConstraintSet{}, fmt.Errorf("missing T coeffs for hash constraint")
	}
	hashRes, err := BuildHashConstraints(
		ringQ,
		pub.B,
		wit.M1[0],
		wit.M2[0],
		wit.R0[0],
		wit.R1[0],
		wit.T,
	)
	if err != nil {
		return ConstraintSet{}, fmt.Errorf("hash residuals: %w", err)
	}

	return ConstraintSet{
		FparInt: append(centerRes, hashRes...),
		FaggInt: comRes,
	}, nil
}
