package credential

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// NewIssuerChallenge samples RI0, RI1 with coefficients in [-BoundB, BoundB],
// lifts them to NTT, and returns the IssuerChallenge.
func NewIssuerChallenge(p *Params) (IssuerChallenge, error) {
	if p == nil || p.RingQ == nil {
		return IssuerChallenge{}, fmt.Errorf("nil params or ring")
	}
	ringQ := p.RingQ
	ri0 := make([]*ring.Poly, p.LenRU0)
	ri1 := make([]*ring.Poly, p.LenRU1)
	for i := 0; i < p.LenRU0; i++ {
		poly, err := sampleBoundedPoly(ringQ, p.BoundB)
		if err != nil {
			return IssuerChallenge{}, err
		}
		ri0[i] = poly
	}
	for i := 0; i < p.LenRU1; i++ {
		poly, err := sampleBoundedPoly(ringQ, p.BoundB)
		if err != nil {
			return IssuerChallenge{}, err
		}
		ri1[i] = poly
	}
	return IssuerChallenge{RI0: ri0, RI1: ri1}, nil
}

func sampleBoundedPoly(ringQ *ring.Ring, bound int64) (*ring.Poly, error) {
	if bound <= 0 {
		return nil, fmt.Errorf("bound must be > 0")
	}
	p := ringQ.NewPoly()
	prng, err := utils.NewPRNG()
	if err != nil {
		return nil, err
	}
	mod := 2*bound + 1
	q := int64(ringQ.Modulus[0])
	for i := range p.Coeffs[0] {
		rn, err := randInt64(prng, mod)
		if err != nil {
			return nil, err
		}
		v := rn - bound // in [-bound, bound]
		if v < 0 {
			p.Coeffs[0][i] = uint64(v + q)
		} else {
			p.Coeffs[0][i] = uint64(v)
		}
	}
	ringQ.NTT(p, p)
	return p, nil
}

func randInt64(prng utils.PRNG, max int64) (int64, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be > 0")
	}
	buf := make([]byte, 8)
	if _, err := prng.Read(buf); err == nil {
		r := new(big.Int).SetBytes(buf)
		return r.Mod(r, big.NewInt(max)).Int64(), nil
	}
	// fallback to crypto/rand
	rn, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}
	return rn.Int64(), nil
}
