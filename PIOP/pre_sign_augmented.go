package PIOP

import (
	"fmt"

	"vSIS-Signature/credential"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// PreSignAugmentedProof captures the data checked before signing when running in
// credential mode. This is a deterministic object; the full NIZK wiring is TODO.
type PreSignAugmentedProof struct {
	Com []*ring.Poly
	R0  []*ring.Poly
	R1  []*ring.Poly
	// T is carried through to the signer but not constrained here.
	T []int64
}

// ProvePreSignAugmented builds Com and combines randomness; T is carried through
// but not constrained here (hash remains external).
func ProvePreSignAugmented(p *credential.Params, h credential.HolderState, chal credential.IssuerChallenge, T []int64) (*PreSignAugmentedProof, error) {
	if p == nil {
		return nil, fmt.Errorf("nil params")
	}
	com, err := credential.BuildCommit(p, h)
	if err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	ct, err := credential.ComputeCombinedTarget(p, h, chal)
	if err != nil {
		return nil, fmt.Errorf("combine target: %w", err)
	}
	// Use externally computed T if provided; otherwise adopt the computed one.
	tOut := T
	if len(tOut) == 0 {
		tOut = ct.T
	}
	return &PreSignAugmentedProof{
		Com: com,
		R0:  ct.R0,
		R1:  ct.R1,
		T:   tOut,
	}, nil
}

// VerifyPreSignAugmented deterministically checks Com and center-combine
// constraints. It does not constrain T; hashing remains external.
func VerifyPreSignAugmented(p *credential.Params, h credential.HolderState, chal credential.IssuerChallenge, proof *PreSignAugmentedProof) error {
	if p == nil {
		return fmt.Errorf("nil params")
	}
	if proof == nil {
		return fmt.Errorf("nil proof")
	}
	// Recompute com
	vec := make([]*ring.Poly, 0,
		len(h.M1)+len(h.M2)+len(h.RU0)+len(h.RU1)+len(h.R))
	vec = append(vec, h.M1...)
	vec = append(vec, h.M2...)
	vec = append(vec, h.RU0...)
	vec = append(vec, h.RU1...)
	vec = append(vec, h.R...)
	recomputed, err := credential.BuildCommit(p, h)
	if err != nil {
		return fmt.Errorf("recompute commit: %w", err)
	}
	if len(recomputed) != len(proof.Com) {
		return fmt.Errorf("commit length mismatch")
	}
	diff := p.RingQ.NewPoly()
	zero := p.RingQ.NewPoly()
	for i := range recomputed {
		p.RingQ.Sub(recomputed[i], proof.Com[i], diff)
		if !p.RingQ.Equal(diff, zero) {
			return fmt.Errorf("commit mismatch at row %d", i)
		}
	}
	// Recompute R0/R1
	ct, err := credential.ComputeCombinedTarget(p, h, chal)
	if err != nil {
		return fmt.Errorf("recompute target: %w", err)
	}
	if len(ct.R0) != len(proof.R0) || len(ct.R1) != len(proof.R1) {
		return fmt.Errorf("r0/r1 length mismatch")
	}
	for i := range ct.R0 {
		p.RingQ.Sub(ct.R0[i], proof.R0[i], diff)
		if !p.RingQ.Equal(diff, zero) {
			return fmt.Errorf("r0 mismatch at %d", i)
		}
	}
	for i := range ct.R1 {
		p.RingQ.Sub(ct.R1[i], proof.R1[i], diff)
		if !p.RingQ.Equal(diff, zero) {
			return fmt.Errorf("r1 mismatch at %d", i)
		}
	}
	return nil
}
