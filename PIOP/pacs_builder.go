package PIOP

import "fmt"

// pacsBuilder is a thin wrapper around the existing PACS prover/verifier,
// exposed through the StatementBuilder interface. It ignores explicit publics
// and witnesses because the current prover builds them internally from disk
// fixtures or SimOpts defaults.
type pacsBuilder struct {
	opts SimOpts
}

// NewPACSBuilder returns a StatementBuilder backed by the existing PACS flow.
func NewPACSBuilder(opts SimOpts) StatementBuilder {
	opts.applyDefaults()
	return &pacsBuilder{opts: opts}
}

// Build runs the existing prover and returns the transcript proof.
func (b *pacsBuilder) Build(_ PublicInputs, _ WitnessInputs, _ MaskConfig) (*Proof, error) {
	ctx, _, _, _ := buildSimWith(nil, b.opts)
	if ctx == nil || ctx.proof == nil {
		return nil, fmt.Errorf("pacs builder: nil proof")
	}
	return ctx.proof, nil
}

// Verify reuses VerifyNIZK on the provided proof; publics are already embedded.
func (b *pacsBuilder) Verify(_ PublicInputs, proof *Proof) (bool, error) {
	if proof == nil {
		return false, fmt.Errorf("nil proof")
	}
	okLin, okEq4, okSum, err := VerifyNIZK(proof)
	return okLin && okEq4 && okSum, err
}

// Compile-time guard.
var _ StatementBuilder = (*pacsBuilder)(nil)
