package decs

import (
	"encoding/binary"
	"math/bits"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Verifier holds DECS verification parameters.
type Verifier struct {
	ringQ  *ring.Ring
	r      int
	params Params
}

// NewVerifierWithParams constructs a DECS verifier for r×η with the provided
// parameters. It panics if params.Degree is not in [0,N).
func NewVerifierWithParams(ringQ *ring.Ring, r int, params Params) *Verifier {
	if params.Degree < 0 || params.Degree >= int(ringQ.N) {
		panic("decs: invalid degree parameter")
	}
	if params.Eta <= 0 {
		panic("decs: invalid eta (must be > 0)")
	}
	if params.NonceBytes <= 0 {
		panic("decs: invalid NonceBytes (must be > 0)")
	}
	if len(ringQ.Modulus) != 1 {
		panic("decs: only single-modulus rings are supported (len(Modulus) must be 1)")
	}
	return &Verifier{ringQ: ringQ, r: r, params: params}
}

// DeriveGamma runs step 2 (commit → Γ).
func (v *Verifier) DeriveGamma(root [16]byte) [][]uint64 {
	q := v.ringQ.Modulus[0]
	return DeriveGamma(root, v.params.Eta, v.r, q)
}

func mulMod64(a, b, m uint64) uint64 {
	a %= m
	b %= m
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, m)
	return rem
}

func addMod64(a, b, m uint64) uint64 {
	a %= m
	b %= m
	s, c := bits.Add64(a, b, 0)
	if c == 1 || s >= m {
		s -= m
	}
	return s
}

func equalGamma(a, b [][]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

// VerifyCommit checks deg R_k <= Degree (DECS §3 Step 3).
func (v *Verifier) VerifyCommit(root [16]byte, R []*ring.Poly, Gamma [][]uint64) bool {
	if !equalGamma(v.DeriveGamma(root), Gamma) {
		return false
	}
	for _, p := range R {
		coeffs := p.Coeffs[0] // coeff domain
		for i := v.params.Degree + 1; i < len(coeffs); i++ {
			if coeffs[i] != 0 {
				return false // degree too large
			}
		}
	}
	return true
}

// VerifyEval runs DECS.Eval checks: Merkle paths + masked relation.
func (v *Verifier) VerifyEval(
	root [16]byte, Gamma [][]uint64, R []*ring.Poly,
	open *DECSOpening,
) bool {
	if open == nil {
		return false
	}
	if err := EnsureMerkleDecoded(open); err != nil {
		return false
	}
	n := open.EntryCount()
	if len(open.Pvals) != n || len(open.Mvals) != n || len(open.PathIndex) != n {
		return false
	}
	if len(open.Nonces) > 0 && len(open.Nonces) != n {
		return false
	}
	if len(Gamma) != v.params.Eta || len(R) != v.params.Eta {
		return false
	}
	for k := 0; k < v.params.Eta; k++ {
		if len(Gamma[k]) != v.r {
			return false
		}
	}

	Re := make([]*ring.Poly, v.params.Eta)
	for k := 0; k < v.params.Eta; k++ {
		Re[k] = v.ringQ.NewPoly()
		v.ringQ.NTT(R[k], Re[k])
	}

	mod := v.ringQ.Modulus[0]

	for t := 0; t < n; t++ {
		idx := open.IndexAt(t)
		if idx < 0 || idx >= int(v.ringQ.N) {
			return false
		}
		if len(open.Pvals[t]) != v.r || len(open.Mvals[t]) != v.params.Eta {
			return false
		}
		var nonce []byte
		if len(open.Nonces) > t && len(open.Nonces[t]) > 0 {
			nonce = open.Nonces[t]
		} else if len(open.NonceSeed) > 0 && open.NonceBytes > 0 {
			nonce = deriveNonce(open.NonceSeed, idx, open.NonceBytes)
		}
		if len(nonce) != v.params.NonceBytes {
			return false
		}

		// pack field elements as uint32 and index as uint16 (matching prover)
		buf := make([]byte, 4*(v.r+v.params.Eta)+2+v.params.NonceBytes)
		off := 0
		for j := 0; j < v.r; j++ {
			pv := getPval(open, t, j)
			binary.LittleEndian.PutUint32(buf[off:], uint32(pv))
			off += 4
		}
		for k := 0; k < v.params.Eta; k++ {
			mv := getMval(open, t, k)
			binary.LittleEndian.PutUint32(buf[off:], uint32(mv))
			off += 4
		}
		binary.LittleEndian.PutUint16(buf[off:], uint16(idx))
		off += 2
		copy(buf[off:], nonce[:v.params.NonceBytes])
		// Reconstruct per-index path from union
		ids, ok := pathRowIndices(open, t)
		if !ok {
			return false
		}
		path := make([][]byte, len(ids))
		for lvl, id := range ids {
			if id < 0 || id >= len(open.Nodes) {
				return false
			}
			path[lvl] = open.Nodes[id]
		}
		if !VerifyPath(buf, path, root, idx) {
			return false
		}

		for k := 0; k < v.params.Eta; k++ {
			lhs := Re[k].Coeffs[0][idx]
			rhs := getMval(open, t, k) % mod
			for j := 0; j < v.r; j++ {
				mul := mulMod64(getPval(open, t, j), Gamma[k][j], mod)
				rhs = addMod64(rhs, mul, mod)
			}
			if lhs != rhs {
				return false
			}
		}
	}
	return true
}

// getPval returns Pvals[t][j], reading from packed form if necessary.
func getPval(open *DECSOpening, t, j int) uint64 {
	if open.Pvals != nil {
		return open.Pvals[t][j]
	}
	// unpack from 20-bit stream
	idx := t*open.R + j
	return unpackU20(open.PvalsBits, idx)
}

func getMval(open *DECSOpening, t, k int) uint64 {
	if open.Mvals != nil {
		return open.Mvals[t][k]
	}
	idx := t*open.Eta + k
	return unpackU20(open.MvalsBits, idx)
}

func unpackU20(bits []byte, index int) uint64 {
	if index < 0 {
		return 0
	}
	off := index * 20
	bytePos := off >> 3
	bitOff := uint(off & 7)
	if bytePos+4 > len(bits) { // safe bound
		// read what we can
	}
	var chunk uint64
	// read up to 4 bytes
	for i := 0; i < 4 && (bytePos+i) < len(bits); i++ {
		chunk |= uint64(bits[bytePos+i]) << (8 * i)
	}
	chunk >>= bitOff
	return uint64(chunk & 0xFFFFF)
}

// GetOpeningPval returns the P value at (t,j) from the opening, reading from
// the packed 20-bit stream if the plain matrix is nil.
func GetOpeningPval(open *DECSOpening, t, j int) uint64 {
	if open == nil || t < 0 || j < 0 {
		return 0
	}
	if open.Pvals != nil {
		if t >= len(open.Pvals) || j >= len(open.Pvals[t]) {
			return 0
		}
		return open.Pvals[t][j]
	}
	if open.R <= 0 {
		return 0
	}
	idx := t*open.R + j
	return unpackU20(open.PvalsBits, idx)
}

// GetOpeningMval returns the M value at (t,k) from the opening, reading from
// the packed 20-bit stream if the plain matrix is nil.
func GetOpeningMval(open *DECSOpening, t, k int) uint64 {
	if open == nil || t < 0 || k < 0 {
		return 0
	}
	if open.Mvals != nil {
		if t >= len(open.Mvals) || k >= len(open.Mvals[t]) {
			return 0
		}
		return open.Mvals[t][k]
	}
	if open.Eta <= 0 {
		return 0
	}
	idx := t*open.Eta + k
	return unpackU20(open.MvalsBits, idx)
}

func pathRowIndices(open *DECSOpening, row int) ([]int, bool) {
	if open == nil || row < 0 || row >= open.EntryCount() {
		return nil, false
	}
	if len(open.PathIndex) > row && open.PathIndex[row] != nil {
		return open.PathIndex[row], true
	}
	if open.PathDepth <= 0 || open.PathBitWidth == 0 || len(open.PathBits) == 0 {
		return nil, false
	}
	rowVals, err := unpackPathRow(open.PathBits, row, open.EntryCount(), open.PathDepth, int(open.PathBitWidth))
	if err != nil {
		return nil, false
	}
	return rowVals, true
}

// VerifyEvalAt enforces that the prover opened exactly the challenged set E,
// then runs the standard DECS checks.
func (v *Verifier) VerifyEvalAt(
	root [16]byte, Gamma [][]uint64, R []*ring.Poly,
	open *DECSOpening, E []int,
) bool {
	indices := open.AllIndices()
	if len(indices) != len(E) {
		return false
	}
	seen := make(map[int]struct{}, len(E))
	for _, x := range E {
		if x < 0 || x >= int(v.ringQ.N) {
			return false
		}
		if _, dup := seen[x]; dup {
			return false
		}
		seen[x] = struct{}{}
	}
	for _, y := range indices {
		if _, ok := seen[y]; !ok {
			return false
		}
		delete(seen, y)
	}
	if len(seen) != 0 {
		return false
	}
	return v.VerifyEval(root, Gamma, R, open)
}
