package prf

import "fmt"

// Trace runs the permutation and returns the state after each round boundary,
// including the initial state. The returned slice has length RF+RP+1.
func Trace(init []Elem, params *Params) ([][]Elem, error) {
	if params == nil {
		return nil, fmt.Errorf("nil params")
	}
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(init) != params.T() {
		return nil, fmt.Errorf("len(init)=%d want %d", len(init), params.T())
	}
	f := NewField(params.Q)
	t := params.T()
	tmp := make([]Elem, t)
	out := make([]Elem, t)

	// states[0] = initial
	states := make([][]Elem, 0, params.RF+params.RP+1)
	state := make([]Elem, t)
	copy(state, init)
	states = append(states, append([]Elem(nil), state...))

	// external rounds (first half)
	for r := 0; r < params.RF/2; r++ {
		externalRound(state, tmp, out, params.CExt[r], params.ME, f, params.D)
		states = append(states, append([]Elem(nil), state...))
	}
	// internal rounds
	for r := 0; r < params.RP; r++ {
		internalRound(state, tmp, out, params.CInt[r], params.MI, f, params.D)
		states = append(states, append([]Elem(nil), state...))
	}
	// external rounds (second half)
	for r := params.RF / 2; r < params.RF; r++ {
		externalRound(state, tmp, out, params.CExt[r], params.ME, f, params.D)
		states = append(states, append([]Elem(nil), state...))
	}
	return states, nil
}

// ConcatKeyNonce builds x^(0) = key || nonce with length checks.
func ConcatKeyNonce(key, nonce []Elem, params *Params) ([]Elem, error) {
	if params == nil {
		return nil, fmt.Errorf("nil params")
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
	return state, nil
}
