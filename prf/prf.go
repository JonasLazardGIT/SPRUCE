package prf

import "fmt"

// Tag computes F(key, nonce) as defined in §B.6:
// tag = Tr(P(key||nonce) + (key||nonce)), truncated to LenTag.
func Tag(key, nonce []Elem, params *Params) ([]Elem, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(key) != params.LenKey {
		return nil, fmt.Errorf("len(key)=%d want %d", len(key), params.LenKey)
	}
	if len(nonce) != params.LenNonce {
		return nil, fmt.Errorf("len(nonce)=%d want %d", len(nonce), params.LenNonce)
	}
	t := params.T()
	state := make([]Elem, t)
	copy(state, key)
	copy(state[params.LenKey:], nonce)
	orig := make([]Elem, t)
	copy(orig, state)
	PermuteInPlace(state, params)
	f := NewField(params.Q)
	for i := 0; i < t; i++ {
		state[i] = f.add(state[i], orig[i])
	}
	return state[:params.LenTag], nil
}
