package credential

import (
	"fmt"

	"vSIS-Signature/commitment"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// flattenState concatenates holder state into a commitment.Vector matching Ac columns.
func flattenState(h HolderState) commitment.Vector {
	out := make(commitment.Vector, 0,
		len(h.M1)+len(h.M2)+len(h.RU0)+len(h.RU1)+len(h.R))
	out = append(out, h.M1...)
	out = append(out, h.M2...)
	out = append(out, h.RU0...)
	out = append(out, h.RU1...)
	out = append(out, h.R...)
	return out
}

// BuildCommit validates shapes/bounds and computes com = Ac · [m1||m2||rU0||rU1||r].
func BuildCommit(p *Params, h HolderState) (commitment.Vector, error) {
	if p == nil || p.RingQ == nil {
		return nil, fmt.Errorf("nil params or ring")
	}
	if err := CheckLengths(h.M1, p.LenM1, "m1"); err != nil {
		return nil, err
	}
	if err := CheckLengths(h.M2, p.LenM2, "m2"); err != nil {
		return nil, err
	}
	if err := CheckLengths(h.RU0, p.LenRU0, "rU0"); err != nil {
		return nil, err
	}
	if err := CheckLengths(h.RU1, p.LenRU1, "rU1"); err != nil {
		return nil, err
	}
	if err := CheckLengths(h.R, p.LenR, "r"); err != nil {
		return nil, err
	}
	b := p.BoundB
	ringQ := p.RingQ
	for _, check := range []struct {
		vec  []*ring.Poly
		name string
	}{
		{h.M1, "m1"},
		{h.M2, "m2"},
		{h.RU0, "rU0"},
		{h.RU1, "rU1"},
		{h.R, "r"},
	} {
		if err := CheckBound(check.vec, b, check.name, ringQ); err != nil {
			return nil, err
		}
	}
	vec := flattenState(h)
	com, err := commitment.Commit(ringQ, p.Ac, vec)
	if err != nil {
		return nil, err
	}
	return com, nil
}
