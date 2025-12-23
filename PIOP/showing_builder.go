package PIOP

import (
	"fmt"

	"vSIS-Signature/prf"
)

// BuildShowingPRF constructs and proves a PRF-only showing statement using the committed
// witness rows built by BuildCredentialRowsShowing. It assumes theta=1 for now (matching
// BuildWithRows). Callers must populate all base rows (M1,M2,RU*,R*,K*) and the PRF trace
// polys in wit.Extras["prf_trace"].
func BuildShowingPRF(pub PublicInputs, wit WitnessInputs, tagPublic [][]int64, noncePublic [][]int64, opts SimOpts) (*Proof, error) {
	opts.applyDefaults()
	// Force theta=1 path for BuildWithRows compatibility.
	opts.Theta = 1
	ringQ, _, _, err := loadParamsAndOmega(opts)
	if err != nil {
		return nil, fmt.Errorf("load params: %w", err)
	}
	params, err := prf.LoadDefaultParams()
	if err != nil {
		return nil, fmt.Errorf("load prf params: %w", err)
	}

	// Build rows/layout with showing builder.
	rows, rowInputs, rowLayout, decsParams, maskOffset, maskCount, witnessCount, startIdx, ncols, err := BuildCredentialRowsShowing(ringQ, wit, params.LenKey, params.LenNonce, params.RF, params.RP, opts)
	if err != nil {
		return nil, fmt.Errorf("build showing rows: %w", err)
	}

	// Build constraint set over the committed rows.
	cs, err := BuildPRFConstraintSet(ringQ, params, rows, startIdx, tagPublic, noncePublic)
	if err != nil {
		return nil, fmt.Errorf("build prf constraint set: %w", err)
	}
	cs.PRFLayout = &PRFLayout{
		StartIdx: startIdx,
		LenKey:   params.LenKey,
		LenNonce: params.LenNonce,
		RF:       params.RF,
		RP:       params.RP,
		LenTag:   params.LenTag,
	}

	// Ensure tag/nonce appear in publics for FS binding.
	pub.Tag = tagPublic
	pub.Nonce = noncePublic
	opts.Credential = true

	return BuildWithRows(pub, cs, opts, rows, rowInputs, rowLayout, decsParams, maskOffset, maskCount, witnessCount, ncols)
}
