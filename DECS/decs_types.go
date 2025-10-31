package decs

// DECSOpening holds the data sent by the prover in DECS.Eval.
type DECSOpening struct {
	// Mask indices form the contiguous range [MaskBase, MaskBase+MaskCount).
	// Any remaining tail indices are stored explicitly in Indices.
	MaskBase  int
	MaskCount int
	Indices   []int      // explicit indices after the mask segment (optional)
	TailCount int        // number of tail indices when Indices is packed
	IndexBits []byte     // packed tail indices (13-bit per entry; optional)
	Pvals     [][]uint64 // optional: P_j(e) for each e∈E, j∈[0..r)
	Mvals     [][]uint64 // optional: M_k(e) for each e∈E, k∈[0..η)
	// Packed residues (20-bit per element); when set, Pvals/Mvals may be nil.
	PvalsBits []byte
	MvalsBits []byte
	R         int // number of P columns (rows committed)
	Eta       int // number of mask polys (η)
	// Multiproof encoding:
	// Nodes holds the unique list of sibling hashes used to authenticate all indices.
	// PathIndex[t][lvl] is an index into Nodes for the sibling at level lvl of leaf t.
	Nodes            [][]byte
	PathIndex        [][]int // optional: explicit indices
	PathBits         []byte  // packed path indices (row-major t×depth), optional
	PathBitWidth     uint8   // bit width per path entry when PathBits is set
	PathDepth        int     // path length when PathBits is set
	FrontierRefsBits []byte  // packed indices into FrontierNodes (union)
	FrontierRefWidth uint8   // bit width for FrontierRefsBits entries
	FrontierRefCount int     // number of references encoded in FrontierRefsBits
	Nonces           [][]byte
	NonceSeed        []byte
	NonceBytes       int

	// Compact multiproof encoding (frontier based). When populated, Nodes/PathIndex*
	// may be nil and callers should use EnsureMerkleDecoded to expand them.
	FrontierNodes [][]byte
	FrontierProof []byte
	FrontierLR    []byte
	FrontierDepth int
}

// EntryCount returns the total number of opened indices.
func (op *DECSOpening) EntryCount() int {
	if op == nil {
		return 0
	}
	return op.MaskCount + op.tailLen()
}

// IndexAt returns the logical index at position i within the opening.
func (op *DECSOpening) IndexAt(i int) int {
	if op == nil || i < 0 || i >= op.EntryCount() {
		return -1
	}
	if i < op.MaskCount {
		return op.MaskBase + i
	}
	tailPos := i - op.MaskCount
	if tailPos < len(op.Indices) {
		return op.Indices[tailPos]
	}
	if tailPos < op.TailCount {
		return op.tailIndexAt(tailPos)
	}
	return -1
}

// AllIndices materialises the full index set (mask prefix + explicit tail).
func (op *DECSOpening) AllIndices() []int {
	if op == nil {
		return nil
	}
	total := op.EntryCount()
	if total == 0 {
		return nil
	}
	out := make([]int, total)
	for i := 0; i < op.MaskCount; i++ {
		out[i] = op.MaskBase + i
	}
	switch {
	case len(op.Indices) > 0:
		copy(out[op.MaskCount:], op.Indices)
	case op.TailCount > 0 && len(op.IndexBits) > 0:
		op.decodeTailInto(out[op.MaskCount:])
	}
	return out
}

// Params bundles the protocol parameters for DECS.
type Params struct {
	Degree     int // max degree d ≤ N-1
	Eta        int // number of mask polynomials η
	NonceBytes int // size of each nonce ρ_e in bytes
}

// DefaultParams provides legacy parameters for callers that do not
// explicitly configure DECS. It preserves the previous behaviour
// (Degree=4095, Eta=2) but increases NonceBytes to 24 (~192-bit).
var DefaultParams = Params{Degree: 4095, Eta: 2, NonceBytes: 24}
