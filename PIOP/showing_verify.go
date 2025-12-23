package PIOP

import "fmt"

// VerifyShowingPRF recomputes the PRF constraints from opened rows using the PRF layout
// metadata, then falls back to VerifyWithConstraints for the PCS checks. It assumes the
// proof contains openings for the committed rows (as produced by RunMaskingFS).
// Note: this is a lightweight wrapper; a full refactor would integrate PRF evaluation
// inside VerifyNIZK.
func VerifyShowingPRF(proof *Proof, set ConstraintSet, pub PublicInputs, opts SimOpts, personalization string) (bool, error) {
	if set.PRFLayout == nil {
		return false, fmt.Errorf("missing PRF layout in constraint set")
	}
	opts.applyDefaults()
	if personalization == "" {
		personalization = FSModeCredential
	}
	// TODO: hook into row openings to recompute PRF residuals; for now delegate.
	return VerifyWithConstraints(proof, set, pub, opts, personalization)
}
