package decs

import "testing"

func TestComputeOpeningMetricsPacked(t *testing.T) {
	path := [][]int{{1, 2, 3}, {4, 5, 6}}
	width := pathBitWidth(6)
	pathBits := packPathMatrix(path, len(path[0]), width)
	op := &DECSOpening{
		MaskBase:     10,
		MaskCount:    3,
		Indices:      []int{42, 300},
		PvalsBits:    []byte{0xAA, 0xBB},
		MvalsBits:    []byte{0xCC, 0xDD, 0xEE},
		Nodes:        [][]byte{{0x01, 0x02}, {0x03}},
		PathBits:     pathBits,
		PathBitWidth: uint8(width),
		PathDepth:    len(path[0]),
		FrontierNodes: [][]byte{
			{0x10},
			{0x20, 0x21},
		},
		FrontierProof: []byte{0x01, 0x02, 0x03},
		FrontierLR:    []byte{0x04},
		FrontierDepth: 6,
		NonceSeed:     []byte{0xF0, 0xF1, 0xF2},
		NonceBytes:    24,
	}

	stats := computeOpeningMetrics(op)

	if stats.entries != 5 {
		t.Fatalf("entries mismatch: got=%d want=5", stats.entries)
	}
	if stats.maskPrefixBytes != 2 {
		t.Fatalf("maskPrefixBytes mismatch: got=%d want=2", stats.maskPrefixBytes)
	}
	if stats.tailIndexBytes != 3 {
		t.Fatalf("tailIndexBytes mismatch: got=%d want=3", stats.tailIndexBytes)
	}
	if stats.tailPackedBytes != 0 {
		t.Fatalf("tailPackedBytes mismatch: got=%d want=0", stats.tailPackedBytes)
	}
	if stats.tailMetaBytes != 0 {
		t.Fatalf("tailMetaBytes mismatch: got=%d want=0", stats.tailMetaBytes)
	}
	if stats.pvalsBytes != 2 || stats.mvalsBytes != 3 {
		t.Fatalf("residue bytes mismatch: got P=%d M=%d want P=2 M=3", stats.pvalsBytes, stats.mvalsBytes)
	}
	if stats.nodeBytes != 3 {
		t.Fatalf("nodeBytes mismatch: got=%d want=3", stats.nodeBytes)
	}
	expectedPathBytes := len(pathBits) + 1 + varintLen(len(path[0]))
	if stats.pathBytes != expectedPathBytes {
		t.Fatalf("pathBytes mismatch: got=%d want=%d", stats.pathBytes, expectedPathBytes)
	}
	if stats.pathPackedBytes != len(pathBits) {
		t.Fatalf("pathPackedBytes mismatch: got=%d want=%d", stats.pathPackedBytes, len(pathBits))
	}
	if stats.pathMetaBytes != 1+varintLen(len(path[0])) {
		t.Fatalf("pathMetaBytes mismatch: got=%d want=%d", stats.pathMetaBytes, 1+varintLen(len(path[0])))
	}
	if stats.frontierBytes != 7 {
		t.Fatalf("frontierBytes mismatch: got=%d want=7", stats.frontierBytes)
	}
	if stats.frontierMetaByte != 4 {
		t.Fatalf("frontierMetaByte mismatch: got=%d want=4", stats.frontierMetaByte)
	}
	if stats.nonceValueBytes != 3 {
		t.Fatalf("nonceValueBytes mismatch: got=%d want=3", stats.nonceValueBytes)
	}
	if stats.nonceMetaBytes != 1 {
		t.Fatalf("nonceMetaBytes mismatch: got=%d want=1", stats.nonceMetaBytes)
	}

	want := stats.indicesBytes() + stats.residuesBytes() + stats.merkleBytes() + stats.nonceBytes()
	if stats.totalBytes() != want {
		t.Fatalf("total bytes mismatch: got=%d want=%d", stats.totalBytes(), want)
	}
}

func TestComputeOpeningMetricsFrontierRefs(t *testing.T) {
	refs := []int{0, 1, 0, 1, 1}
	width := pathBitWidth(1)
	refBits := packPathMatrix([][]int{refs}, len(refs), width)
	nodes := [][]byte{
		make([]byte, 16),
		make([]byte, 16),
	}
	op := &DECSOpening{
		FrontierNodes:    nodes,
		FrontierProof:    []byte{0x0f},
		FrontierLR:       []byte{0x00},
		FrontierDepth:    3,
		FrontierRefsBits: refBits,
		FrontierRefWidth: uint8(width),
		FrontierRefCount: len(refs),
	}

	stats := computeOpeningMetrics(op)

	wantRefTotal := len(refBits) + 1 + varintLen(len(refs))
	if stats.frontierRefsBytes != wantRefTotal {
		t.Fatalf("frontierRefsBytes mismatch: got=%d want=%d", stats.frontierRefsBytes, wantRefTotal)
	}
	if stats.frontierRefPacked != len(refBits) {
		t.Fatalf("frontierRefPacked mismatch: got=%d want=%d", stats.frontierRefPacked, len(refBits))
	}
	if stats.frontierRefMeta != wantRefTotal-len(refBits) {
		t.Fatalf("frontierRefMeta mismatch: got=%d want=%d", stats.frontierRefMeta, wantRefTotal-len(refBits))
	}
	if stats.merkleBytes() != stats.nodeBytes+stats.pathBytes+stats.frontierBytes+stats.frontierMetaByte+stats.frontierRefsBytes {
		t.Fatalf("merkle bytes accounting mismatch: got=%d want=%d", stats.merkleBytes(), stats.nodeBytes+stats.pathBytes+stats.frontierBytes+stats.frontierMetaByte+stats.frontierRefsBytes)
	}
}

func TestComputeOpeningMetricsUnpacked(t *testing.T) {
	op := &DECSOpening{
		Indices: []int{5, 17},
		Pvals: [][]uint64{
			{1, 2},
			{3, 4},
		},
		Mvals: [][]uint64{
			{5, 6},
		},
		PathIndex: [][]int{
			{1, 2},
			{3, 4},
		},
		Nodes: [][]byte{
			{0x01},
			{0x02},
		},
		Nonces: [][]byte{
			{0x01, 0x02},
			{0x03, 0x04},
		},
	}

	stats := computeOpeningMetrics(op)

	if stats.entries != 2 {
		t.Fatalf("entries mismatch: got=%d want=2", stats.entries)
	}
	if stats.indicesBytes() != 2 {
		t.Fatalf("indices bytes mismatch: got=%d want=2", stats.indicesBytes())
	}
	if stats.residuesBytes() != 48 {
		t.Fatalf("residues bytes mismatch: got=%d want=48", stats.residuesBytes())
	}
	if stats.merkleBytes() != 18 {
		t.Fatalf("merkle bytes mismatch: got=%d want=18", stats.merkleBytes())
	}
	if stats.nonceBytes() != 4 {
		t.Fatalf("nonce bytes mismatch: got=%d want=4", stats.nonceBytes())
	}
	if stats.totalBytes() != 72 {
		t.Fatalf("total bytes mismatch: got=%d want=72", stats.totalBytes())
	}
}

func TestComputeOpeningMetricsTailPacked(t *testing.T) {
	op := &DECSOpening{
		MaskBase:  4,
		MaskCount: 1,
		Indices:   []int{5, 130, 257},
	}
	op.packTailIndices()
	if len(op.IndexBits) == 0 || op.TailCount != 3 {
		t.Fatalf("expected packed indices, got len(IndexBits)=%d TailCount=%d", len(op.IndexBits), op.TailCount)
	}
	if op.Indices != nil {
		t.Fatalf("expected Indices to be cleared after packing")
	}

	stats := computeOpeningMetrics(op)

	if stats.entries != 4 {
		t.Fatalf("entries mismatch: got=%d want=4", stats.entries)
	}
	if stats.maskPrefixBytes != 2 {
		t.Fatalf("maskPrefixBytes mismatch: got=%d want=2", stats.maskPrefixBytes)
	}
	if stats.tailCount != 3 {
		t.Fatalf("tailCount mismatch: got=%d want=3", stats.tailCount)
	}
	if stats.tailPackedBytes != len(op.IndexBits) {
		t.Fatalf("tailPackedBytes mismatch: got=%d want=%d", stats.tailPackedBytes, len(op.IndexBits))
	}
	meta := varintLen(op.TailCount)
	if stats.tailMetaBytes != meta {
		t.Fatalf("tailMetaBytes mismatch: got=%d want=%d", stats.tailMetaBytes, meta)
	}
	if stats.tailIndexBytes != len(op.IndexBits)+meta {
		t.Fatalf("tailIndexBytes mismatch: got=%d want=%d", stats.tailIndexBytes, len(op.IndexBits)+meta)
	}
	if stats.indicesBytes() != 2+len(op.IndexBits)+meta {
		t.Fatalf("indices bytes mismatch: got=%d want=%d", stats.indicesBytes(), 2+len(op.IndexBits)+meta)
	}
	if stats.totalBytes() != stats.indicesBytes() {
		t.Fatalf("total bytes mismatch: got=%d want=%d", stats.totalBytes(), stats.indicesBytes())
	}
}
