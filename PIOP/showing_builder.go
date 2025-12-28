package PIOP

import (
	"fmt"

	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// BuildShowingCombined constructs a showing statement with post-sign credential
// constraints (signature/hash/bounds) and PRF constraints. It expects base rows
// (M1,M2,RU0,RU1,R,R0,R1,K0,K1), a T row (wit.T), signature rows (wit.U), and
// PRF trace rows in wit.Extras["prf_trace"]. Tag/Nonce must be provided in pub.
func BuildShowingCombined(pub PublicInputs, wit WitnessInputs, opts SimOpts) (*Proof, error) {
	opts.applyDefaults()
	ringQ, _, _, err := loadParamsAndOmega(opts)
	if err != nil {
		return nil, fmt.Errorf("load params: %w", err)
	}
	params, err := prf.LoadDefaultParams()
	if err != nil {
		return nil, fmt.Errorf("load prf params: %w", err)
	}
	if len(pub.A) == 0 {
		return nil, fmt.Errorf("missing A for post-sign constraints")
	}
	if len(pub.B) == 0 {
		return nil, fmt.Errorf("missing B for post-sign hash")
	}
	if len(wit.T) == 0 {
		return nil, fmt.Errorf("missing T witness for post-sign constraints")
	}
	if len(wit.U) == 0 {
		return nil, fmt.Errorf("missing U witness for post-sign constraints")
	}
	if len(pub.Tag) == 0 || len(pub.Nonce) == 0 {
		return nil, fmt.Errorf("missing tag/nonce publics")
	}
	// Build rows/layout with showing builder.
	rows, _, _, _, _, _, _, startIdx, ncols, err := BuildCredentialRowsShowing(ringQ, wit, params.LenKey, params.LenNonce, params.RF, params.RP, opts)
	if err != nil {
		return nil, fmt.Errorf("build showing rows: %w", err)
	}
	// Build NTT rows for constraint construction.
	rowsNTT := make([]*ring.Poly, len(rows))
	for i := range rows {
		rowsNTT[i] = ringQ.NewPoly()
		ring.Copy(rows[i], rowsNTT[i])
		ringQ.NTT(rowsNTT[i], rowsNTT[i])
	}
	// Post-sign constraints (signature/hash/bounds).
	postSet, err := buildCredentialConstraintSetPostFromRows(ringQ, pub.BoundB, pub, rowsNTT, ncols)
	if err != nil {
		return nil, fmt.Errorf("build post-sign constraint set: %w", err)
	}
	// PRF constraints.
	prfSet, err := BuildPRFConstraintSet(ringQ, params, rowsNTT, startIdx, pub.Tag, pub.Nonce, ncols)
	if err != nil {
		return nil, fmt.Errorf("build prf constraint set: %w", err)
	}
	set := ConstraintSet{
		FparInt:  append(append([]*ring.Poly{}, postSet.FparInt...), prfSet.FparInt...),
		FparNorm: postSet.FparNorm,
		FaggInt:  postSet.FaggInt,
		FaggNorm: postSet.FaggNorm,
		PRFLayout: &PRFLayout{
			StartIdx: startIdx,
			LenKey:   params.LenKey,
			LenNonce: params.LenNonce,
			RF:       params.RF,
			RP:       params.RP,
			LenTag:   params.LenTag,
		},
	}
	opts.Credential = true
	return BuildWithConstraints(pub, wit, set, opts, FSModeCredential)
}
