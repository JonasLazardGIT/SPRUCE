package PIOP

import (
	"fmt"

	"vSIS-Signature/commitment"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// PreSignPublic captures the public inputs of the pre-sign statement.
// Ac and B are expected in NTT domain.
type PreSignPublic struct {
	Com    []*ring.Poly
	RI0    []*ring.Poly
	RI1    []*ring.Poly
	Ac     commitment.Matrix
	B      []*ring.Poly
	T      []int64
	BoundB int64
}

// PreSignWitness holds the secret vectors.
type PreSignWitness struct {
	M1  []*ring.Poly
	M2  []*ring.Poly
	RU0 []*ring.Poly
	RU1 []*ring.Poly
	R   []*ring.Poly
}

// PreSignProof is a placeholder for the future PIOP-backed proof object.
// TODO: replace interface{} with concrete proof type once wired.
type PreSignProof struct {
	Inner interface{}
}

// ProvePreSignZK builds a pre-sign proof using the PIOP/DECS/LVCS stack.
// NOTE: Not implemented yet; wiring requires adding the constraint set to the PIOP builder.
func ProvePreSignZK(pub PreSignPublic, wit PreSignWitness, ringQ *ring.Ring) (*PreSignProof, error) {
	return nil, fmt.Errorf("PreSign PIOP statement not yet implemented")
}

// VerifyPreSignZK verifies a pre-sign proof.
// NOTE: Not implemented yet; wiring requires adding the constraint set to the PIOP verifier.
func VerifyPreSignZK(pub PreSignPublic, proof *PreSignProof, ringQ *ring.Ring) error {
	return fmt.Errorf("PreSign PIOP statement not yet implemented")
}
