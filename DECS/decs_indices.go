package decs

const indexBitsPerValue = 13
const indexBitsMask = (1 << indexBitsPerValue) - 1

func (op *DECSOpening) tailLen() int {
	if op == nil {
		return 0
	}
	if len(op.Indices) > 0 {
		return len(op.Indices)
	}
	if op.TailCount > 0 {
		return op.TailCount
	}
	return 0
}

func (op *DECSOpening) packTailIndices() {
	if op == nil {
		return
	}
	if len(op.IndexBits) > 0 && len(op.Indices) == 0 && op.TailCount > 0 {
		// already packed
		return
	}
	tailLen := len(op.Indices)
	if tailLen == 0 {
		op.IndexBits = nil
		op.TailCount = 0
		return
	}
	maxIdx := 0
	for _, idx := range op.Indices {
		if idx > maxIdx {
			maxIdx = idx
		}
	}
	op.TailCount = tailLen
	if maxIdx >= 1<<indexBitsPerValue {
		// fallback: keep explicit indices if values overflow 13 bits
		return
	}
	op.IndexBits = packIndexBits13(op.Indices)
	op.Indices = nil
}

func (op *DECSOpening) tailIndexAt(pos int) int {
	if op == nil || pos < 0 || pos >= op.TailCount || len(op.IndexBits) == 0 {
		return -1
	}
	v, ok := unpackIndexAt(op.IndexBits, pos)
	if !ok {
		return -1
	}
	return v
}

func (op *DECSOpening) decodeTailInto(dst []int) {
	if op == nil || len(dst) == 0 {
		return
	}
	if len(op.Indices) > 0 {
		n := len(dst)
		if n > len(op.Indices) {
			n = len(op.Indices)
		}
		copy(dst, op.Indices[:n])
		return
	}
	if op.TailCount == 0 || len(op.IndexBits) == 0 {
		for i := range dst {
			dst[i] = 0
		}
		return
	}
	for i := 0; i < len(dst) && i < op.TailCount; i++ {
		if val, ok := unpackIndexAt(op.IndexBits, i); ok {
			dst[i] = val
		} else {
			dst[i] = 0
		}
	}
}

func packIndexBits13(values []int) []byte {
	if len(values) == 0 {
		return nil
	}
	totalBits := len(values) * indexBitsPerValue
	out := make([]byte, (totalBits+7)/8)
	bitPos := 0
	for _, v := range values {
		val := uint32(v & indexBitsMask)
		bytePos := bitPos >> 3
		shift := uint(bitPos & 7)
		var chunk uint32 = val << shift
		for i := 0; i < 3 && (bytePos+i) < len(out); i++ {
			out[bytePos+i] |= byte(chunk & 0xFF)
			chunk >>= 8
			if shift+indexBitsPerValue <= uint(8*(i+1)) {
				break
			}
		}
		bitPos += indexBitsPerValue
	}
	return out
}

func unpackIndexAt(bits []byte, pos int) (int, bool) {
	if pos < 0 {
		return 0, false
	}
	bitPos := pos * indexBitsPerValue
	bytePos := bitPos >> 3
	if bytePos >= len(bits) {
		return 0, false
	}
	shift := uint(bitPos & 7)
	var chunk uint32
	for i := 0; i < 3 && (bytePos+i) < len(bits); i++ {
		chunk |= uint32(bits[bytePos+i]) << (8 * i)
	}
	chunk >>= shift
	value := int(chunk & uint32(indexBitsMask))
	if bytePos*8+int(shift)+indexBitsPerValue > len(bits)*8 {
		return 0, false
	}
	return value, true
}

func unpackIndices(bits []byte, count int) []int {
	if count <= 0 {
		return nil
	}
	out := make([]int, count)
	for i := 0; i < count; i++ {
		if v, ok := unpackIndexAt(bits, i); ok {
			out[i] = v
		}
	}
	return out
}
