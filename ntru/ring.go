package ntru

import (
	"fmt"
	"os"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// BuildRings constructs one Lattigo ring per RNS modulus.
func (p Params) BuildRings() ([]*ring.Ring, error) {
	dbg(os.Stderr, "[Ring] BuildRings N=%d limbs=%d\n", p.N, len(p.Qi))
	if p.N == 0 || (p.N&(p.N-1)) != 0 {
		return nil, fmt.Errorf("N must be a power of two")
	}
	if len(p.Qi) == 0 {
		// attempt single prime modulus Q
		if !p.Q.IsUint64() {
			return nil, fmt.Errorf("Q does not fit in uint64 and no factorization provided")
		}
		r, err := ring.NewRing(p.N, []uint64{p.Q.Uint64()})
		if err != nil {
			return nil, err
		}
		return []*ring.Ring{r}, nil
	}
	rings := make([]*ring.Ring, len(p.Qi))
	for i, qi := range p.Qi {
		r, err := ring.NewRing(p.N, []uint64{qi})
		if err != nil {
			return nil, err
		}
		rings[i] = r
	}
	return rings, nil
}
