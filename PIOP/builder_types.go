package PIOP

import "github.com/tuneinsight/lattigo/v4/ring"

// PublicInputs collects public values for a statement build; unused fields can stay nil.
type PublicInputs struct {
	Com    []*ring.Poly
	RI0    []*ring.Poly
	RI1    []*ring.Poly
	Ac     [][]*ring.Poly
	B      []*ring.Poly
	T      []int64
	U      []*ring.Poly
	BoundB int64
	Extras map[string]interface{}
}

// WitnessInputs collects witness vectors.
type WitnessInputs struct {
	M1  []*ring.Poly
	M2  []*ring.Poly
	RU0 []*ring.Poly
	RU1 []*ring.Poly
	R   []*ring.Poly
	R0  []*ring.Poly
	R1  []*ring.Poly
	U   []*ring.Poly
	// T can be kept internal (hash output) when not exposed as public.
	T      []int64
	Extras map[string]interface{}
}

// ConstraintSet groups the F-polys to be masked/committed in the prover.
// Split mirrors the PACS distinction between parallel and aggregated
// constraints, and integer vs. normalized, to fit existing masking routines.
type ConstraintSet struct {
	FparInt  []*ring.Poly
	FparNorm []*ring.Poly
	FaggInt  []*ring.Poly
	FaggNorm []*ring.Poly
}

// StatementBuilder defines an interface to build/prove/verify a statement.
// This is a placeholder to be implemented by PACS and credential builders.
type StatementBuilder interface {
	Build(pub PublicInputs, wit WitnessInputs, cfg MaskConfig) (*Proof, error)
	Verify(pub PublicInputs, proof *Proof) (bool, error)
}
