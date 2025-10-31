package decs

import (
	"fmt"
)

type openingMetrics struct {
	entries           int
	maskPrefixCount   int
	tailCount         int
	maskPrefixBytes   int
	tailIndexBytes    int
	tailPackedBytes   int
	tailMetaBytes     int
	pvalsBytes        int
	mvalsBytes        int
	nodeBytes         int
	pathBytes         int
	pathPackedBytes   int
	pathMetaBytes     int
	frontierBytes     int
	frontierMetaByte  int
	frontierRefsBytes int
	frontierRefPacked int
	frontierRefMeta   int
	nonceValueBytes   int
	nonceMetaBytes    int
}

func (m openingMetrics) indicesBytes() int {
	return m.maskPrefixBytes + m.tailIndexBytes
}

func (m openingMetrics) residuesBytes() int {
	return m.pvalsBytes + m.mvalsBytes
}

func (m openingMetrics) merkleBytes() int {
	return m.nodeBytes + m.pathBytes + m.frontierBytes + m.frontierMetaByte + m.frontierRefsBytes
}

func (m openingMetrics) nonceBytes() int {
	return m.nonceValueBytes + m.nonceMetaBytes
}

func (m openingMetrics) totalBytes() int {
	return m.indicesBytes() + m.residuesBytes() + m.merkleBytes() + m.nonceBytes()
}

func logOpeningMetrics(stage string, op *DECSOpening) {
	if !debugOpeningSizes || op == nil {
		return
	}
	stats := computeOpeningMetrics(op)
	tailDetail := fmt.Sprintf("%dB", stats.tailIndexBytes)
	if stats.tailMetaBytes > 0 {
		tailDetail = fmt.Sprintf("%dB (packed=%dB meta=%dB)", stats.tailIndexBytes, stats.tailPackedBytes, stats.tailMetaBytes)
	}
	pathDetail := fmt.Sprintf("%dB", stats.pathBytes)
	if stats.pathMetaBytes > 0 {
		pathDetail = fmt.Sprintf("%dB (packed=%dB meta=%dB)", stats.pathBytes, stats.pathPackedBytes, stats.pathMetaBytes)
	}
	frontierDetail := fmt.Sprintf("%dB", stats.frontierBytes+stats.frontierMetaByte)
	if stats.frontierRefPacked > 0 {
		frontierDetail = fmt.Sprintf("%dB refs=%dB (packed=%dB meta=%dB)", stats.frontierBytes+stats.frontierMetaByte, stats.frontierRefsBytes, stats.frontierRefPacked, stats.frontierRefMeta)
	}
	fmt.Printf(
		"[DECS] opening[%s]: entries=%d mask=%d tail=%d | indices=%dB (prefix=%dB tail=%s) residues=%dB (P=%dB M=%dB) merkle=%dB (nodes=%dB path=%s frontier=%s) nonces=%dB total=%dB\n",
		stage,
		stats.entries,
		stats.maskPrefixCount,
		stats.tailCount,
		stats.indicesBytes(),
		stats.maskPrefixBytes,
		tailDetail,
		stats.residuesBytes(),
		stats.pvalsBytes,
		stats.mvalsBytes,
		stats.merkleBytes(),
		stats.nodeBytes,
		pathDetail,
		frontierDetail,
		stats.nonceBytes(),
		stats.totalBytes(),
	)
}

func computeOpeningMetrics(op *DECSOpening) openingMetrics {
	if op == nil {
		return openingMetrics{}
	}
	stats := openingMetrics{
		entries:         op.EntryCount(),
		maskPrefixCount: op.MaskCount,
		tailCount:       op.tailLen(),
	}
	if op.MaskCount > 0 {
		stats.maskPrefixBytes += varintLen(op.MaskBase)
		stats.maskPrefixBytes += varintLen(op.MaskCount)
	}
	switch {
	case len(op.IndexBits) > 0 && op.tailLen() > 0 && len(op.Indices) == 0:
		stats.tailPackedBytes = len(op.IndexBits)
		stats.tailMetaBytes = varintLen(op.TailCount)
		stats.tailIndexBytes = stats.tailPackedBytes + stats.tailMetaBytes
	default:
		for _, idx := range op.Indices {
			stats.tailIndexBytes += varintLen(idx)
		}
	}
	if len(op.PvalsBits) > 0 {
		stats.pvalsBytes = len(op.PvalsBits)
	} else {
		stats.pvalsBytes = matrixByteSize(op.Pvals)
	}
	if len(op.MvalsBits) > 0 {
		stats.mvalsBytes = len(op.MvalsBits)
	} else {
		stats.mvalsBytes = matrixByteSize(op.Mvals)
	}
	for _, node := range op.Nodes {
		stats.nodeBytes += len(node)
	}
	if len(op.PathBits) > 0 && op.PathDepth > 0 && op.PathBitWidth > 0 && len(op.PathIndex) == 0 {
		stats.pathPackedBytes = len(op.PathBits)
		stats.pathMetaBytes = 1 + varintLen(op.PathDepth)
		stats.pathBytes = stats.pathPackedBytes + stats.pathMetaBytes
	} else {
		for _, row := range op.PathIndex {
			stats.pathBytes += len(row) * 4
		}
	}
	for _, node := range op.FrontierNodes {
		stats.frontierBytes += len(node)
	}
	stats.frontierBytes += len(op.FrontierProof)
	stats.frontierBytes += len(op.FrontierLR)
	if op.FrontierDepth > 0 {
		stats.frontierMetaByte += 4
	}
	if len(op.FrontierRefsBits) > 0 && op.FrontierRefWidth > 0 && op.FrontierRefCount > 0 {
		stats.frontierRefPacked = len(op.FrontierRefsBits)
		stats.frontierRefMeta = 1 + varintLen(op.FrontierRefCount)
		stats.frontierRefsBytes = stats.frontierRefPacked + stats.frontierRefMeta
	}
	if len(op.Nonces) > 0 {
		for _, nonce := range op.Nonces {
			stats.nonceValueBytes += len(nonce)
		}
	} else if len(op.NonceSeed) > 0 {
		stats.nonceValueBytes = len(op.NonceSeed)
	}
	if op.NonceBytes > 0 {
		stats.nonceMetaBytes = varintLen(op.NonceBytes)
	}
	return stats
}

func matrixByteSize(mat [][]uint64) int {
	if len(mat) == 0 {
		return 0
	}
	total := 0
	for _, row := range mat {
		total += len(row) * 8
	}
	return total
}

func varintLen(x int) int {
	if x < 0 {
		return 0
	}
	v := uint32(x)
	n := 1
	for v >= 0x80 {
		v >>= 7
		n++
	}
	return n
}
