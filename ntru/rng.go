package ntru

import (
	"math/big"
	"math/rand"
)

// RNG wraps a deterministic rand.Rand for tests.
type RNG struct {
	r *rand.Rand
}

// NewRNG creates a new RNG with given seed.
func NewRNG(seed int64) *RNG {
	return &RNG{r: rand.New(rand.NewSource(seed))}
}

// Intn returns random int in [0,n).
func (r *RNG) Intn(n int) int {
	return r.r.Intn(n)
}

// RandBigInt returns a random big.Int uniformly in [0,mod).
func (r *RNG) RandBigInt(mod *big.Int) *big.Int {
	res := new(big.Int)
	res.Rand(r.r, mod)
	return res
}
