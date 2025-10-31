package decs

import (
	"bytes"
	"golang.org/x/crypto/sha3"
)

const (
	leafPrefix byte = 0x00
	nodePrefix byte = 0x01
)

// MerkleTree is a full binary Merkle tree of 16-byte hashes (SHAKE-256 truncated).
type MerkleTree struct {
	layers [][][16]byte
}

// BuildMerkleTree builds a balanced tree from leaves.
func BuildMerkleTree(leaves [][]byte) *MerkleTree {
	n := len(leaves)
	size := 1
	for size < n {
		size <<= 1
	}
	layer := make([][16]byte, size)
	for i := 0; i < n; i++ {
		leaf := leaves[i]
		buf := make([]byte, 1+len(leaf))
		buf[0] = leafPrefix
		copy(buf[1:], leaf)
		layer[i] = shake16(buf)
	}
	for i := n; i < size; i++ {
		layer[i] = shake16([]byte{leafPrefix})
	}
	layers := [][][16]byte{layer}

	for sz := size; sz > 1; sz >>= 1 {
		prev := layers[len(layers)-1]
		next := make([][16]byte, sz/2)
		for i := 0; i < sz; i += 2 {
			var buf [1 + 16 + 16]byte
			buf[0] = nodePrefix
			copy(buf[1:], prev[i][:])
			copy(buf[1+16:], prev[i+1][:])
			next[i/2] = shake16(buf[:])
		}
		layers = append(layers, next)
	}

	return &MerkleTree{layers: layers}
}

// Root returns the root hash.
func (mt *MerkleTree) Root() [16]byte {
	return mt.layers[len(mt.layers)-1][0]
}

// Path returns the sibling path for leaf idx.
func (mt *MerkleTree) Path(idx int) [][]byte {
	path := make([][]byte, len(mt.layers)-1)
	for lvl := 0; lvl < len(mt.layers)-1; lvl++ {
		sib := idx ^ 1
		h := mt.layers[lvl][sib]
		path[lvl] = h[:]
		idx >>= 1
	}
	return path
}

// VerifyPath checks leaf→root via path.
func VerifyPath(leaf []byte, path [][]byte, root [16]byte, idx int) bool {
	buf := make([]byte, 1+len(leaf))
	buf[0] = leafPrefix
	copy(buf[1:], leaf)
	h := shake16(buf)
	for _, sib := range path {
		var tmp [1 + 16 + 16]byte
		tmp[0] = nodePrefix
		if idx&1 == 0 {
			copy(tmp[1:], h[:])
			copy(tmp[1+16:], sib)
		} else {
			copy(tmp[1:], sib)
			copy(tmp[1+16:], h[:])
		}
		h = shake16(tmp[:])
		idx >>= 1
	}
	return bytes.Equal(h[:], root[:])
}

func shake16(data []byte) [16]byte {
	var out [16]byte
	h := sha3.NewShake256()
	_, _ = h.Write(data)
	_, _ = h.Read(out[:])
	return out
}
