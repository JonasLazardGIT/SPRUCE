package PIOP

import "fmt"

// credentialBuilder will host the credential statement; currently returns not implemented.
type credentialBuilder struct {
	opts SimOpts
}

func NewCredentialBuilder(opts SimOpts) StatementBuilder {
	opts.applyDefaults()
	return &credentialBuilder{opts: opts}
}

func (b *credentialBuilder) Build(_ PublicInputs, _ WitnessInputs, _ MaskConfig) (*Proof, error) {
	return nil, fmt.Errorf("credential builder not implemented")
}

func (b *credentialBuilder) Verify(_ PublicInputs, _ *Proof) (bool, error) {
	return false, fmt.Errorf("credential builder not implemented")
}

var _ StatementBuilder = (*credentialBuilder)(nil)
