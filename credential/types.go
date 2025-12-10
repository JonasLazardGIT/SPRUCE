package credential

import "github.com/tuneinsight/lattigo/v4/ring"

// HolderState bundles all user-held vectors that are bound into the credential.
// Each slice entry is a polynomial in the same ring as Ac/B.
type HolderState struct {
	M1  []*ring.Poly
	M2  []*ring.Poly
	RU0 []*ring.Poly
	RU1 []*ring.Poly
	R   []*ring.Poly
}

// IssuerChallenge carries the randomness supplied by the Issuer.
type IssuerChallenge struct {
	RI0 []*ring.Poly
	RI1 []*ring.Poly
}

// Transcript is the on-wire state exchanged during issuance.
// PiCom and PiT are opaque proof objects produced by the PIOP layer.
type Transcript struct {
	Com   []*ring.Poly
	PiCom interface{}
	T     []int64
	PiT   interface{}
	U     []int64
}

// Credential is what the Holder persists after successful issuance.
type Credential struct {
	U   []int64
	M1  []*ring.Poly
	M2  []*ring.Poly
	R0  []*ring.Poly
	R1  []*ring.Poly
	Com []*ring.Poly
	// Metadata for reconstruction/debugging.
	BPath  string
	AcPath string
}
