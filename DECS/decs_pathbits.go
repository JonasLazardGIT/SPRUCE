package decs

import "errors"

func pathBitWidth(maxValue int) int {
	if maxValue < 0 {
		return 0
	}
	width := 0
	v := maxValue
	for v > 0 {
		width++
		v >>= 1
	}
	if width == 0 {
		width = 1
	}
	return width
}

func packPathMatrix(rows [][]int, depth, width int) []byte {
	if depth <= 0 || width <= 0 {
		return nil
	}
	totalValues := len(rows) * depth
	totalBits := totalValues * width
	out := make([]byte, (totalBits+7)/8)
	mask := uint32((1 << width) - 1)
	bitPos := 0
	for _, row := range rows {
		for _, v := range row {
			val := uint32(v) & mask
			bytePos := bitPos >> 3
			shift := uint(bitPos & 7)
			chunk := uint64(val) << shift
			byteCount := ((width + int(shift) + 7) / 8)
			for i := 0; i < byteCount && (bytePos+i) < len(out); i++ {
				out[bytePos+i] |= byte(chunk & 0xFF)
				chunk >>= 8
			}
			bitPos += width
		}
	}
	return out
}

func unpackPathMatrix(bits []byte, rows, depth, width int) ([][]int, error) {
	if rows < 0 || depth < 0 || width <= 0 {
		return nil, errors.New("invalid path matrix parameters")
	}
	if rows == 0 || depth == 0 {
		return nil, nil
	}
	totalValues := rows * depth
	totalBits := totalValues * width
	if len(bits)*8 < totalBits {
		return nil, errors.New("truncated path bitstream")
	}
	out := make([][]int, rows)
	mask := uint32((1 << width) - 1)
	bitPos := 0
	for r := 0; r < rows; r++ {
		row := make([]int, depth)
		for c := 0; c < depth; c++ {
			bytePos := bitPos >> 3
			shift := uint(bitPos & 7)
			var chunk uint64
			byteCount := ((width + int(shift) + 7) / 8)
			for i := 0; i < byteCount && (bytePos+i) < len(bits); i++ {
				chunk |= uint64(bits[bytePos+i]) << (8 * i)
			}
			val := int((chunk >> shift) & uint64(mask))
			row[c] = val
			bitPos += width
		}
		out[r] = row
	}
	return out, nil
}

func unpackPathRow(bits []byte, rowIndex, rows, depth, width int) ([]int, error) {
	if rowIndex < 0 || rowIndex >= rows {
		return nil, errors.New("row out of range")
	}
	if depth <= 0 || width <= 0 {
		return nil, errors.New("invalid path row parameters")
	}
	if len(bits)*8 < (rowIndex+1)*depth*width {
		return nil, errors.New("truncated path bitstream")
	}
	row := make([]int, depth)
	mask := uint32((1 << width) - 1)
	bitPos := rowIndex * depth * width
	for c := 0; c < depth; c++ {
		bytePos := bitPos >> 3
		shift := uint(bitPos & 7)
		var chunk uint64
		byteCount := ((width + int(shift) + 7) / 8)
		for i := 0; i < byteCount && (bytePos+i) < len(bits); i++ {
			chunk |= uint64(bits[bytePos+i]) << (8 * i)
		}
		row[c] = int((chunk >> shift) & uint64(mask))
		bitPos += width
	}
	return row, nil
}
