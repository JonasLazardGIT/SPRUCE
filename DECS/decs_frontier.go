package decs

import (
	"encoding/binary"
	"errors"
	"sort"
)

type frontierActive struct {
	pos    int
	leaves []int
}

func (op *DECSOpening) packFrontier() {
	if op == nil {
		return
	}
	totalEntries := op.EntryCount()
	if totalEntries == 0 {
		op.FrontierNodes = nil
		op.FrontierProof = nil
		op.FrontierLR = nil
		op.FrontierDepth = 0
		return
	}
	// Require Nodes/PathIndex data to be available once; if already packed, skip.
	if len(op.Nodes) == 0 && len(op.PathIndex) == 0 && len(op.PathBits) == 0 {
		return
	}
	pathIdx := op.PathIndex
	if len(pathIdx) == 0 && len(op.PathBits) > 0 && op.PathDepth > 0 && op.PathBitWidth > 0 {
		matrix, err := unpackPathMatrix(op.PathBits, totalEntries, op.PathDepth, int(op.PathBitWidth))
		if err != nil {
			return
		}
		pathIdx = matrix
	}
	if len(pathIdx) == 0 || len(op.Nodes) == 0 {
		return
	}
	depth := len(pathIdx[0])
	if depth == 0 {
		return
	}
	// Assemble per-leaf sibling paths using existing Nodes.
	if len(pathIdx) != totalEntries {
		return
	}
	paths := make([][][]byte, totalEntries)
	for leaf := 0; leaf < totalEntries; leaf++ {
		if len(pathIdx[leaf]) != depth {
			return
		}
		row := make([][]byte, depth)
		for lvl := 0; lvl < depth; lvl++ {
			id := pathIdx[leaf][lvl]
			if id < 0 || id >= len(op.Nodes) {
				return
			}
			row[lvl] = op.Nodes[id]
		}
		paths[leaf] = row
	}

	totalBits := totalEntries * depth
	proofBits := make([]byte, (totalBits+7)/8)
	lrBits := make([]byte, (totalBits+7)/8)

	active := make([]frontierActive, totalEntries)
	for i := 0; i < totalEntries; i++ {
		idx := op.IndexAt(i)
		active[i] = frontierActive{pos: idx, leaves: []int{i}}
	}

	unionMap := make(map[string]int)
	var unionNodes [][]byte
	addUnion := func(node []byte) int {
		key := string(node)
		if id, ok := unionMap[key]; ok {
			return id
		}
		id := len(unionNodes)
		unionMap[key] = id
		unionNodes = append(unionNodes, append([]byte(nil), node...))
		return id
	}
	var proofRefs []int
	for lvl := 0; lvl < depth; lvl++ {
		sort.Slice(active, func(i, j int) bool { return active[i].pos < active[j].pos })
		next := make([]frontierActive, 0, (len(active)+1)>>1)
		for i := 0; i < len(active); {
			cur := active[i]
			lr := (cur.pos & 1) == 1
			for _, leafIdx := range cur.leaves {
				setPackedBit(lrBits, leafIdx, lvl, depth, lr)
			}
			if i+1 < len(active) && active[i+1].pos == (cur.pos^1) {
				sib := active[i+1]
				lrS := (sib.pos & 1) == 1
				for _, leafIdx := range sib.leaves {
					setPackedBit(lrBits, leafIdx, lvl, depth, lrS)
				}
				merged := append([]int(nil), cur.leaves...)
				merged = append(merged, sib.leaves...)
				next = append(next, frontierActive{pos: cur.pos >> 1, leaves: merged})
				i += 2
				continue
			}
			// unmatched: consume proof node from existing path (same for all leaves in node)
			ref := addUnion(paths[cur.leaves[0]][lvl])
			proofRefs = append(proofRefs, ref)
			for _, leafIdx := range cur.leaves {
				setPackedBit(proofBits, leafIdx, lvl, depth, true)
			}
			next = append(next, frontierActive{pos: cur.pos >> 1, leaves: append([]int(nil), cur.leaves...)})
			i++
		}
		active = next
	}

	op.FrontierNodes = unionNodes
	op.FrontierProof = proofBits
	op.FrontierLR = lrBits
	op.FrontierDepth = depth
	if len(proofRefs) > 0 {
		maxRef := len(unionNodes) - 1
		width := pathBitWidth(maxRef)
		if width <= 0 {
			width = 1
		}
		op.FrontierRefWidth = uint8(width)
		op.FrontierRefCount = len(proofRefs)
		refMatrix := [][]int{proofRefs}
		op.FrontierRefsBits = packPathMatrix(refMatrix, len(proofRefs), width)
	} else {
		op.FrontierRefsBits = nil
		op.FrontierRefWidth = 0
		op.FrontierRefCount = 0
	}
	op.PathIndex = nil
	op.PathBits = nil
	op.PathBitWidth = 0
	op.PathDepth = 0
	op.Nodes = nil
}

type decodedNode struct {
	pos    int
	leaves []int
	hash   [16]byte
}

// EnsureMerkleDecoded reconstructs Nodes/PathIndex from the compact frontier
// encoding if necessary so legacy consumers can iterate per-leaf paths.
func EnsureMerkleDecoded(op *DECSOpening) error {
	if op == nil || op.EntryCount() == 0 {
		return nil
	}
	if len(op.Nodes) > 0 && (len(op.PathIndex) > 0 || len(op.PathBits) > 0) {
		return nil
	}
	if len(op.FrontierNodes) == 0 && len(op.FrontierProof) == 0 {
		return nil
	}
	depth := op.FrontierDepth
	if depth <= 0 {
		return errors.New("decs: missing frontier depth")
	}
	numLeaves := op.EntryCount()
	totalBits := numLeaves * depth
	if len(op.FrontierProof) < (totalBits+7)/8 {
		return errors.New("decs: truncated frontier proof bitmap")
	}

	active := make([]decodedNode, numLeaves)
	leafHashes := make([][16]byte, numLeaves)
	for leafIdx := 0; leafIdx < numLeaves; leafIdx++ {
		h, err := computeLeafHash(op, leafIdx)
		if err != nil {
			return err
		}
		leafHashes[leafIdx] = h
		active[leafIdx] = decodedNode{
			pos:    op.IndexAt(leafIdx),
			leaves: []int{leafIdx},
			hash:   h,
		}
	}

	proofIdx := 0
	var refs []int
	var err error
	if len(op.FrontierRefsBits) > 0 && op.FrontierRefCount > 0 && op.FrontierRefWidth > 0 {
		var matrix [][]int
		matrix, err = unpackPathMatrix(op.FrontierRefsBits, 1, op.FrontierRefCount, int(op.FrontierRefWidth))
		if err != nil {
			return err
		}
		if len(matrix) > 0 {
			refs = matrix[0]
		}
		if len(refs) != op.FrontierRefCount {
			return errors.New("decs: inconsistent frontier reference count")
		}
	}
	refIdx := 0
	paths := make([][][]byte, numLeaves)
	for level := 0; level < depth; level++ {
		sort.Slice(active, func(i, j int) bool { return active[i].pos < active[j].pos })
		next := make([]decodedNode, 0, (len(active)+1)>>1)
		for i := 0; i < len(active); {
			cur := active[i]
			usesProof := getPackedBit(op.FrontierProof, cur.leaves[0], level, depth)
			if usesProof {
				var sibBytes []byte
				if len(refs) > 0 {
					if refIdx >= len(refs) {
						return errors.New("decs: exhausted frontier references")
					}
					uid := refs[refIdx]
					refIdx++
					if uid < 0 || uid >= len(op.FrontierNodes) {
						return errors.New("decs: frontier reference out of range")
					}
					sibBytes = op.FrontierNodes[uid]
				} else {
					if proofIdx >= len(op.FrontierNodes) {
						return errors.New("decs: exhausted frontier nodes")
					}
					sibBytes = op.FrontierNodes[proofIdx]
					proofIdx++
				}
				for _, leafIdx := range cur.leaves {
					paths[leafIdx] = append(paths[leafIdx], append([]byte(nil), sibBytes...))
				}
				var sibHash [16]byte
				copy(sibHash[:], sibBytes)
				var parent decodedNode
				parent.pos = cur.pos >> 1
				parent.leaves = append([]int(nil), cur.leaves...)
				if (cur.pos & 1) == 0 {
					parent.hash = hashNode(cur.hash, sibHash)
				} else {
					parent.hash = hashNode(sibHash, cur.hash)
				}
				next = append(next, parent)
				i++
				continue
			}
			if i+1 >= len(active) || active[i+1].pos != (cur.pos^1) {
				return errors.New("decs: inconsistent frontier structure")
			}
			sib := active[i+1]
			for _, leafIdx := range cur.leaves {
				paths[leafIdx] = append(paths[leafIdx], append([]byte(nil), sib.hash[:]...))
			}
			for _, leafIdx := range sib.leaves {
				paths[leafIdx] = append(paths[leafIdx], append([]byte(nil), cur.hash[:]...))
			}
			left := cur
			right := sib
			if (cur.pos & 1) == 1 {
				left = sib
				right = cur
			}
			parent := decodedNode{
				pos:    cur.pos >> 1,
				leaves: append(append([]int(nil), cur.leaves...), sib.leaves...),
				hash:   hashNode(left.hash, right.hash),
			}
			next = append(next, parent)
			i += 2
		}
		active = next
	}
	if len(refs) > 0 {
		if refIdx != len(refs) {
			return errors.New("decs: unused frontier references")
		}
	} else if proofIdx != len(op.FrontierNodes) {
		return errors.New("decs: unused frontier nodes")
	}
	for leafIdx := range paths {
		if len(paths[leafIdx]) != depth {
			return errors.New("decs: reconstructed path length mismatch")
		}
	}

	nodeMap := make(map[string]int)
	var nodes [][]byte
	pathIndex := make([][]int, numLeaves)
	for leafIdx := 0; leafIdx < numLeaves; leafIdx++ {
		row := make([]int, depth)
		for lvl := 0; lvl < depth; lvl++ {
			nodeBytes := paths[leafIdx][lvl]
			key := string(nodeBytes)
			id, ok := nodeMap[key]
			if !ok {
				id = len(nodes)
				nodes = append(nodes, append([]byte(nil), nodeBytes...))
				nodeMap[key] = id
			}
			row[lvl] = id
		}
		pathIndex[leafIdx] = row
	}

	op.Nodes = nodes
	op.PathIndex = pathIndex
	op.PathBits = nil
	op.PathBitWidth = 0
	op.PathDepth = depth
	return nil
}

func setPackedBit(bits []byte, leaf, level, depth int, value bool) {
	idx := leaf*depth + level
	byteIdx := idx >> 3
	bitPos := uint(idx & 7)
	if value {
		bits[byteIdx] |= 1 << bitPos
	} else {
		bits[byteIdx] &^= 1 << bitPos
	}
}

func getPackedBit(bits []byte, leaf, level, depth int) bool {
	idx := leaf*depth + level
	byteIdx := idx >> 3
	if byteIdx >= len(bits) {
		return false
	}
	bitPos := uint(idx & 7)
	return (bits[byteIdx]>>bitPos)&1 == 1
}

func computeLeafHash(op *DECSOpening, leafIdx int) ([16]byte, error) {
	var out [16]byte
	r := op.R
	if r <= 0 {
		if len(op.Pvals) > 0 {
			r = len(op.Pvals[leafIdx])
		} else if len(op.PvalsBits) > 0 && op.R > 0 {
			r = op.R
		}
	}
	if r <= 0 {
		return out, errors.New("decs: unknown row count for opening")
	}
	eta := op.Eta
	if eta <= 0 {
		if len(op.Mvals) > 0 {
			eta = len(op.Mvals[leafIdx])
		}
	}
	if eta < 0 {
		eta = 0
	}
	nonceBytes := op.NonceBytes
	if len(op.Nonces) > leafIdx {
		nonceBytes = len(op.Nonces[leafIdx])
	}
	if nonceBytes <= 0 && len(op.Nonces) > 0 && len(op.Nonces[0]) > 0 {
		nonceBytes = len(op.Nonces[0])
	}
	buf := make([]byte, 4*(r+eta)+2+nonceBytes)
	off := 0
	for j := 0; j < r; j++ {
		val := GetOpeningPval(op, leafIdx, j)
		binary.LittleEndian.PutUint32(buf[off:], uint32(val))
		off += 4
	}
	for k := 0; k < eta; k++ {
		val := GetOpeningMval(op, leafIdx, k)
		binary.LittleEndian.PutUint32(buf[off:], uint32(val))
		off += 4
	}
	idx := op.IndexAt(leafIdx)
	if idx < 0 {
		return out, errors.New("decs: invalid index in opening")
	}
	binary.LittleEndian.PutUint16(buf[off:], uint16(idx))
	off += 2
	if nonceBytes > 0 {
		if len(op.Nonces) > leafIdx && len(op.Nonces[leafIdx]) >= nonceBytes {
			copy(buf[off:], op.Nonces[leafIdx][:nonceBytes])
		} else if len(op.NonceSeed) > 0 {
			rho := deriveNonce(op.NonceSeed, idx, nonceBytes)
			copy(buf[off:], rho)
		}
	}
	withPrefix := make([]byte, 1+len(buf))
	withPrefix[0] = leafPrefix
	copy(withPrefix[1:], buf)
	return shake16(withPrefix), nil
}

func hashNode(left, right [16]byte) [16]byte {
	var buf [1 + 16 + 16]byte
	buf[0] = nodePrefix
	copy(buf[1:], left[:])
	copy(buf[17:], right[:])
	return shake16(buf[:])
}
