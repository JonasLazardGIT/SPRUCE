package decs

import (
	"encoding/binary"
	"errors"
)

// PackUint20Matrix packs a rectangular matrix of residues (<2^20) into a tight
// 20-bit-per-entry bitstream. Callers must provide the row length explicitly to
// ensure consistent packing even if some rows are nil.
func PackUint20Matrix(rows [][]uint64, rowLen int) []byte {
	return packU20Mat(rows, rowLen)
}

// UnpackUint20Matrix expands a 20-bit bitstream back into a rows×rowLen matrix.
// Missing data results in zeroes for the truncated tail.
func UnpackUint20Matrix(bits []byte, rows, rowLen int) [][]uint64 {
	if rows <= 0 || rowLen <= 0 {
		return nil
	}
	out := make([][]uint64, rows)
	for t := 0; t < rows; t++ {
		row := make([]uint64, rowLen)
		for j := 0; j < rowLen; j++ {
			idx := t*rowLen + j
			row[j] = unpackU20(bits, idx)
		}
		out[t] = row
	}
	return out
}

const packedMatrixHeaderSize = 10

// PackUintMatrix encodes a matrix into a bitstream prefixed with a 10-byte header:
// 4 bytes rows, 4 bytes cols, 1 byte bit width, 1 reserved byte. The bit width
// is chosen automatically (16, 20, 32 or 64 bits) depending on the largest entry.
// The returned slice contains the header followed by the packed payload.
func PackUintMatrix(rows [][]uint64) ([]byte, int, int, int) {
	if len(rows) == 0 {
		return nil, 0, 0, 0
	}
	rowLen := maxRowLen(rows)
	if rowLen == 0 {
		return nil, 0, 0, 0
	}
	width := selectBitWidth(maxMatrixValue(rows))
	payload := packUintMatrixBody(rows, rowLen, width)
	buf := make([]byte, packedMatrixHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(buf[0:], uint32(len(rows)))
	binary.LittleEndian.PutUint32(buf[4:], uint32(rowLen))
	buf[8] = byte(width)
	buf[9] = 0
	copy(buf[packedMatrixHeaderSize:], payload)
	return buf, len(rows), rowLen, width
}

// PackUintMatrixWithWidth behaves like PackUintMatrix but uses the provided bit width.
func PackUintMatrixWithWidth(rows [][]uint64, width int) ([]byte, int, int, int) {
	if len(rows) == 0 {
		return nil, 0, 0, 0
	}
	if width <= 0 {
		width = 1
	}
	if width > 64 {
		width = 64
	}
	rowLen := maxRowLen(rows)
	if rowLen == 0 {
		return nil, 0, 0, 0
	}
	payload := packUintMatrixBody(rows, rowLen, width)
	buf := make([]byte, packedMatrixHeaderSize+len(payload))
	binary.LittleEndian.PutUint32(buf[0:], uint32(len(rows)))
	binary.LittleEndian.PutUint32(buf[4:], uint32(rowLen))
	buf[8] = byte(width)
	buf[9] = 0
	copy(buf[packedMatrixHeaderSize:], payload)
	return buf, len(rows), rowLen, width
}

// UnpackUintMatrix parses the header emitted by PackUintMatrix and reconstructs
// the original matrix together with its dimensions and bit width.
func UnpackUintMatrix(bits []byte) ([][]uint64, int, int, int, error) {
	rows, cols, width, payload, err := parsePackedMatrix(bits)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	mat := unpackUintMatrixBody(payload, rows, cols, width)
	return mat, rows, cols, width, nil
}

func parsePackedMatrix(bits []byte) (int, int, int, []byte, error) {
	if len(bits) < packedMatrixHeaderSize {
		return 0, 0, 0, nil, errors.New("decs: packed matrix too short")
	}
	rows := int(binary.LittleEndian.Uint32(bits[0:4]))
	cols := int(binary.LittleEndian.Uint32(bits[4:8]))
	width := int(bits[8])
	if rows < 0 || cols < 0 {
		return 0, 0, 0, nil, errors.New("decs: invalid matrix dimensions")
	}
	if width <= 0 || width > 64 {
		return 0, 0, 0, nil, errors.New("decs: invalid matrix bit width")
	}
	payload := bits[packedMatrixHeaderSize:]
	expectedBits := rows * cols * width
	if len(payload)*8 < expectedBits {
		return 0, 0, 0, nil, errors.New("decs: truncated packed matrix payload")
	}
	return rows, cols, width, payload, nil
}

func packUintMatrixBody(rows [][]uint64, rowLen, width int) []byte {
	if rowLen <= 0 || width <= 0 {
		return nil
	}
	totalVals := len(rows) * rowLen
	totalBits := totalVals * width
	out := make([]byte, (totalBits+7)/8)
	var mask uint64
	if width >= 64 {
		mask = ^uint64(0)
	} else {
		mask = (uint64(1) << width) - 1
	}
	bitPos := 0
	for _, row := range rows {
		for j := 0; j < rowLen; j++ {
			val := uint64(0)
			if j < len(row) {
				val = row[j] & mask
			}
			bytePos := bitPos >> 3
			shift := uint(bitPos & 7)
			chunk := uint64(val) << shift
			bytesNeeded := (width + int(shift) + 7) / 8
			for k := 0; k < bytesNeeded && (bytePos+k) < len(out); k++ {
				out[bytePos+k] |= byte(chunk & 0xFF)
				chunk >>= 8
			}
			bitPos += width
		}
	}
	return out
}

func unpackUintMatrixBody(bits []byte, rows, rowLen, width int) [][]uint64 {
	if rows <= 0 || rowLen <= 0 || width <= 0 {
		return nil
	}
	out := make([][]uint64, rows)
	var mask uint64
	if width >= 64 {
		mask = ^uint64(0)
	} else {
		mask = (uint64(1) << width) - 1
	}
	bitPos := 0
	for r := 0; r < rows; r++ {
		row := make([]uint64, rowLen)
		for c := 0; c < rowLen; c++ {
			bytePos := bitPos >> 3
			shift := uint(bitPos & 7)
			var chunk uint64
			bytesNeeded := (width + int(shift) + 7) / 8
			for k := 0; k < bytesNeeded && (bytePos+k) < len(bits); k++ {
				chunk |= uint64(bits[bytePos+k]) << (8 * k)
			}
			row[c] = (chunk >> shift) & mask
			bitPos += width
		}
		out[r] = row
	}
	return out
}

func maxMatrixValue(rows [][]uint64) uint64 {
	var max uint64
	for _, row := range rows {
		for _, v := range row {
			if v > max {
				max = v
			}
		}
	}
	return max
}

func maxRowLen(rows [][]uint64) int {
	rowLen := 0
	for _, row := range rows {
		if len(row) > rowLen {
			rowLen = len(row)
		}
	}
	return rowLen
}

func selectBitWidth(max uint64) int {
	switch {
	case max < (1 << 16):
		return 16
	case max < (1 << 20):
		return 20
	case max < (1 << 32):
		return 32
	default:
		return 64
	}
}
