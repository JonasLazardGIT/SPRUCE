package decs

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
	n := 0
	for {
		n++
		if x >>= 7; x == 0 {
			break
		}
	}
	return n
}
