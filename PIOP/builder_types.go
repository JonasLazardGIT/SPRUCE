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
	Extras map[string]interface{}
}

// WitnessInputs collects witness vectors.
type WitnessInputs struct {
	M1     []*ring.Poly
	M2     []*ring.Poly
	RU0    []*ring.Poly
	RU1    []*ring.Poly
	R      []*ring.Poly
	Extras map[string]interface{}
}

// StatementBuilder defines an interface to build/prove/verify a statement.
// This is a placeholder to be implemented by PACS and credential builders.
type StatementBuilder interface {
	Build(pub PublicInputs, wit WitnessInputs, cfg MaskConfig) (*Proof, error)
	Verify(pub PublicInputs, proof *Proof) (bool, error)
}
