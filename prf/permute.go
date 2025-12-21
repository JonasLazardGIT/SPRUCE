package prf

// PermuteInPlace applies the Poseidon2-like permutation P to the provided state.
// state length must equal params.T().
func PermuteInPlace(state []Elem, params *Params) {
	f := NewField(params.Q)
	t := params.T()
	tmp := make([]Elem, t)
	out := make([]Elem, t)

	// external rounds (first half)
	for r := 0; r < params.RF/2; r++ {
		externalRound(state, tmp, out, params.CExt[r], params.ME, f, params.D)
	}
	// internal rounds
	for r := 0; r < params.RP; r++ {
		internalRound(state, tmp, out, params.CInt[r], params.MI, f, params.D)
	}
	// external rounds (second half)
	for r := params.RF / 2; r < params.RF; r++ {
		externalRound(state, tmp, out, params.CExt[r], params.ME, f, params.D)
	}
}

func externalRound(state, tmp, out []Elem, cExt []uint64, mds [][]uint64, f Field, d uint64) {
	t := len(state)
	for i := 0; i < t; i++ {
		tmp[i] = f.powSmall(f.add(state[i], Elem(cExt[i]%f.q)), d)
	}
	matVec(out, mds, tmp, f)
	copy(state, out)
}

func internalRound(state, tmp, out []Elem, cInt uint64, mds [][]uint64, f Field, d uint64) {
	t := len(state)
	tmp[0] = f.powSmall(f.add(state[0], Elem(cInt%f.q)), d)
	for i := 1; i < t; i++ {
		tmp[i] = state[i]
	}
	matVec(out, mds, tmp, f)
	copy(state, out)
}

func matVec(out []Elem, m [][]uint64, v []Elem, f Field) {
	t := len(v)
	for i := 0; i < t; i++ {
		var acc Elem
		for j := 0; j < t; j++ {
			acc = f.add(acc, f.mul(Elem(m[i][j]%f.q), v[j]))
		}
		out[i] = acc
	}
}
