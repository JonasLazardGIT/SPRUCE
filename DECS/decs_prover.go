package decs

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

const nonceDeriveLabel = "decs-nonce"

func deriveNonce(seed []byte, idx int, nonceBytes int) []byte {
	h := sha256.New()
	_, _ = h.Write([]byte(nonceDeriveLabel))
	_, _ = h.Write(seed)
	var idxBuf [4]byte
	binary.LittleEndian.PutUint32(idxBuf[:], uint32(idx))
	_, _ = h.Write(idxBuf[:])
	hSum := h.Sum(nil)
	if nonceBytes >= len(hSum) {
		out := make([]byte, nonceBytes)
		copy(out, hSum)
		if nonceBytes > len(hSum) {
			// expand deterministically if more bytes required
			var counter byte = 1
			pos := len(hSum)
			for pos < nonceBytes {
				hi := sha256.New()
				_, _ = hi.Write([]byte(nonceDeriveLabel))
				_, _ = hi.Write(seed)
				_, _ = hi.Write(idxBuf[:])
				_, _ = hi.Write([]byte{counter})
				counter++
				chunk := hi.Sum(nil)
				n := copy(out[pos:], chunk)
				if n == 0 {
					break
				}
				pos += n
			}
		}
		return out
	}
	return append([]byte(nil), hSum[:nonceBytes]...)
}

// Prover encapsulates the prover state for DECS.
type Prover struct {
	ringQ     *ring.Ring
	P         []*ring.Poly // r input polys (coeff form)
	M         []*ring.Poly // η mask polys (coeff form)
	nonceSeed []byte
	mt        *MerkleTree
	Pvals     []*ring.Poly // NTT(P)
	Mvals     []*ring.Poly // NTT(M)
	root      [16]byte
	R         []*ring.Poly // η output polys in coeff form
	params    Params
}

// NewProverWithParams returns a new DECS prover for polynomials P and the
// provided protocol parameters. It panics if params.Degree is not in [0, N).
func NewProverWithParams(ringQ *ring.Ring, P []*ring.Poly, params Params) *Prover {
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
	return &Prover{ringQ: ringQ, P: P, params: params}
}

// CommitInit does DECS.Commit step 1: sample M, nonces; build Merkle tree; NTT(P,M).
func (pr *Prover) CommitInit() ([16]byte, error) {
	r := len(pr.P)
	N := pr.ringQ.N

	// sampler
	prng, err := utils.NewPRNG()
	if err != nil {
		return [16]byte{}, err
	}
	us := ring.NewUniformSampler(prng, pr.ringQ)

	// 1a) sample η mask polys
	pr.M = make([]*ring.Poly, pr.params.Eta)
	for k := 0; k < pr.params.Eta; k++ {
		pr.M[k] = pr.ringQ.NewPoly()
		us.Read(pr.M[k])
		for i := pr.params.Degree + 1; i < N; i++ {
			pr.M[k].Coeffs[0][i] = 0
		}
	}

	// 1b) NTT-transform P and M
	pr.Pvals = make([]*ring.Poly, r)
	for j := range pr.P {
		pr.Pvals[j] = pr.ringQ.NewPoly()
		pr.ringQ.NTT(pr.P[j], pr.Pvals[j])
	}
	pr.Mvals = make([]*ring.Poly, pr.params.Eta)
	for k := 0; k < pr.params.Eta; k++ {
		pr.Mvals[k] = pr.ringQ.NewPoly()
		pr.ringQ.NTT(pr.M[k], pr.Mvals[k])
	}

	// 1c) build leaves
	leaves := make([][]byte, N)
	pr.nonceSeed = make([]byte, pr.params.NonceBytes)
	if _, err := rand.Read(pr.nonceSeed); err != nil {
		return [16]byte{}, err
	}
	for i := 0; i < N; i++ {
		// pack P and M evaluations as uint32 (q < 2^32), index as uint16
		buf := make([]byte, 4*(r+pr.params.Eta)+2+pr.params.NonceBytes)
		off := 0
		for j := 0; j < r; j++ {
			binary.LittleEndian.PutUint32(buf[off:], uint32(pr.Pvals[j].Coeffs[0][i]))
			off += 4
		}
		for k := 0; k < pr.params.Eta; k++ {
			binary.LittleEndian.PutUint32(buf[off:], uint32(pr.Mvals[k].Coeffs[0][i]))
			off += 4
		}
		// index as uint16
		binary.LittleEndian.PutUint16(buf[off:], uint16(i))
		off += 2
		rho := deriveNonce(pr.nonceSeed, i, pr.params.NonceBytes)
		copy(buf[off:], rho)

		// store the raw buffer; BuildMerkleTree will hash it
		leaves[i] = append([]byte(nil), buf...)
	}

	// 1d) Merkle tree
	pr.mt = BuildMerkleTree(leaves)
	pr.root = pr.mt.Root()

	return pr.root, nil
}

// CommitStep2 does DECS.Commit steps 2+3: given Γ, compute R_k = M_k + Σ_j Γ[k][j]*P_j.
func (pr *Prover) CommitStep2(Gamma [][]uint64) []*ring.Poly {
	r := len(pr.P)
	pr.R = make([]*ring.Poly, pr.params.Eta)
	tmp := pr.ringQ.NewPoly()
	tmp2 := pr.ringQ.NewPoly()

	for k := 0; k < pr.params.Eta; k++ {
		// inv-NTT(M_k) → tmp
		pr.ringQ.InvNTT(pr.Mvals[k], tmp)
		pr.R[k] = tmp.CopyNew()
		for j := 0; j < r; j++ {
			pr.ringQ.InvNTT(pr.Pvals[j], tmp)
			pr.ringQ.MulScalar(tmp, Gamma[k][j], tmp2) // tmp2 = tmp * Γ[k][j]
			pr.ringQ.Add(pr.R[k], tmp2, pr.R[k])       // R[k] += tmp2
		}
		// keep R[k] in coefficient form; verifier will NTT as needed
	}
	return pr.R
}

// EvalOpen does DECS.Eval step 1: given E, returns Pvals,Mvals,Paths,Nonces.
func (pr *Prover) EvalOpen(E []int) *DECSOpening {
	r := len(pr.P)
	open := &DECSOpening{
		Indices:    append([]int(nil), E...),
		Pvals:      make([][]uint64, len(E)),
		Mvals:      make([][]uint64, len(E)),
		Nodes:      nil,
		PathIndex:  make([][]int, len(E)),
		R:          r,
		Eta:        pr.params.Eta,
		NonceSeed:  append([]byte(nil), pr.nonceSeed...),
		NonceBytes: pr.params.NonceBytes,
	}
	// Deduplicate sibling nodes across all paths
	nodeIdx := make(map[string]int)
	addNode := func(b []byte) int {
		key := string(b)
		if id, ok := nodeIdx[key]; ok {
			return id
		}
		id := len(open.Nodes)
		// store a copy
		cp := append([]byte(nil), b...)
		open.Nodes = append(open.Nodes, cp)
		nodeIdx[key] = id
		return id
	}
	for t, idx := range E {
		open.Pvals[t] = make([]uint64, r)
		for j := 0; j < r; j++ {
			open.Pvals[t][j] = pr.Pvals[j].Coeffs[0][idx]
		}
		open.Mvals[t] = make([]uint64, pr.params.Eta)
		for k := 0; k < pr.params.Eta; k++ {
			open.Mvals[t][k] = pr.Mvals[k].Coeffs[0][idx]
		}
		// Build path and map to indices
		depth := len(pr.mt.layers) - 1
		pi := make([]int, depth)
		cur := idx
		for lvl := 0; lvl < depth; lvl++ {
			sib := cur ^ 1
			h := pr.mt.layers[lvl][sib][:]
			pi[lvl] = addNode(h)
			cur >>= 1
		}
		open.PathIndex[t] = pi
	}
	// Return unpacked opening; the caller may pack it after combining
	return open
}

// PackOpening compacts residues (to 20-bit streams) and encodes PathIndex into fixed-width bitstreams.
func PackOpening(op *DECSOpening) {
	if op == nil {
		return
	}
	op.packResidues20()
	op.packTailIndices()
	op.packFrontier()
	op.packPathIndexBits()
	if len(op.NonceSeed) > 0 {
		op.Nonces = nil
	}
}

// packResidues20 packs Pvals and Mvals into 20-bit streams (row-major: t then j/k).
func (op *DECSOpening) packResidues20() {
	if len(op.Pvals) > 0 {
		if op.R <= 0 {
			if len(op.Pvals) > 0 {
				op.R = len(op.Pvals[0])
			}
		}
		op.PvalsBits = packU20Mat(op.Pvals, op.R)
		op.Pvals = nil
	}
	if len(op.Mvals) > 0 {
		if op.Eta <= 0 {
			if len(op.Mvals) > 0 {
				op.Eta = len(op.Mvals[0])
			}
		}
		op.MvalsBits = packU20Mat(op.Mvals, op.Eta)
		op.Mvals = nil
	}
}

// packU20Mat packs len(rows)×rowLen residues (each <2^20) into a compact bitstream.
func packU20Mat(rows [][]uint64, rowLen int) []byte {
	count := len(rows) * rowLen
	totalBits := count * 20
	out := make([]byte, (totalBits+7)/8)
	bitpos := 0
	for t := 0; t < len(rows); t++ {
		row := rows[t]
		for j := 0; j < rowLen; j++ {
			v := uint32(row[j] & 0xFFFFF)
			bytePos := bitpos >> 3
			shift := uint(bitpos & 7)
			// write 20 bits starting at (bytePos, shift)
			var tmp uint64 = uint64(v) << shift
			// write up to 4 bytes
			for k := 0; k < 4; k++ {
				b := byte(tmp & 0xFF)
				if bytePos+k < len(out) {
					out[bytePos+k] |= b
				}
				tmp >>= 8
				if (shift + 20) <= uint(8*(k+1)) {
					break
				}
			}
			bitpos += 20
		}
	}
	return out
}

func (op *DECSOpening) packPathIndexBits() {
	if op == nil {
		return
	}
	if len(op.PathIndex) == 0 {
		if len(op.PathBits) == 0 {
			op.PathBitWidth = 0
			op.PathDepth = 0
		}
		return
	}
	depth := len(op.PathIndex[0])
	if depth == 0 {
		op.PathBits = nil
		op.PathBitWidth = 0
		op.PathDepth = 0
		op.PathIndex = nil
		return
	}
	maxID := 0
	for _, row := range op.PathIndex {
		if len(row) != depth {
			// inconsistent depth; keep explicit form
			return
		}
		for _, id := range row {
			if id > maxID {
				maxID = id
			}
		}
	}
	width := pathBitWidth(maxID)
	if width > 32 {
		// packing beyond 32 bits not supported; keep explicit form
		return
	}
	op.PathBits = packPathMatrix(op.PathIndex, depth, width)
	op.PathBitWidth = uint8(width)
	op.PathDepth = depth
	op.PathIndex = nil
}

// DeriveGamma expands root→η×r matrix Γ with entries uniform in [0,q).
// Uses SHA256(root || ctr) as a PRF and 64-bit rejection sampling for exact uniformity.
func DeriveGamma(root [16]byte, eta, r int, q uint64) [][]uint64 {
	out := make([][]uint64, eta)
	var ctr uint64
	for k := 0; k < eta; k++ {
		out[k] = make([]uint64, r)
		for j := 0; j < r; j++ {
			for {
				var buf [24]byte
				copy(buf[:16], root[:])
				binary.LittleEndian.PutUint64(buf[16:], ctr)
				h := sha256.Sum256(buf[:])
				x := binary.LittleEndian.Uint64(h[:8])
				ctr++
				limit := (^uint64(0) / q) * q
				if x < limit {
					out[k][j] = x % q
					break
				}
			}
		}
	}
	return out
}
