package decs

import "testing"

func TestPackTailIndicesRoundTrip(t *testing.T) {
	op := &DECSOpening{
		MaskBase:  8,
		MaskCount: 2,
		Indices:   []int{512, 1023, 2047},
	}
	expected := append([]int{8, 9}, op.Indices...)

	op.packTailIndices()
	if len(op.IndexBits) == 0 {
		t.Fatalf("expected packed indices")
	}
	if op.Indices != nil {
		t.Fatalf("expected Indices to be cleared after packing")
	}
	if op.TailCount != 3 {
		t.Fatalf("unexpected TailCount: got=%d want=3", op.TailCount)
	}

	for i := 0; i < len(expected); i++ {
		got := op.IndexAt(i)
		if got != expected[i] {
			t.Fatalf("IndexAt(%d) mismatch: got=%d want=%d", i, got, expected[i])
		}
	}

	all := op.AllIndices()
	if len(all) != len(expected) {
		t.Fatalf("AllIndices length mismatch: got=%d want=%d", len(all), len(expected))
	}
	for i := range all {
		if all[i] != expected[i] {
			t.Fatalf("AllIndices[%d] mismatch: got=%d want=%d", i, all[i], expected[i])
		}
	}
}

func TestPackTailIndicesOverflowFallback(t *testing.T) {
	// indices >= 2^13 should keep explicit form
	op := &DECSOpening{
		MaskBase:  0,
		MaskCount: 0,
		Indices:   []int{9000, 12000},
	}
	op.packTailIndices()
	if len(op.IndexBits) != 0 {
		t.Fatalf("expected overflow indices to keep explicit form")
	}
	if op.Indices == nil {
		t.Fatalf("expected Indices to remain when packing skipped")
	}
	if op.TailCount != len(op.Indices) {
		t.Fatalf("tailCount mismatch: got=%d want=%d", op.TailCount, len(op.Indices))
	}
}

func TestPackPathMatrixRoundTrip(t *testing.T) {
	matrix := [][]int{
		{0, 1, 2, 3},
		{4, 5, 6, 7},
		{8, 9, 10, 11},
	}
	width := pathBitWidth(11)
	if width != 4 {
		t.Fatalf("unexpected width: got=%d want=4", width)
	}
	bits := packPathMatrix(matrix, len(matrix[0]), width)
	if len(bits) == 0 {
		t.Fatalf("expected packed path bits")
	}
	decoded, err := unpackPathMatrix(bits, len(matrix), len(matrix[0]), width)
	if err != nil {
		t.Fatalf("unpackPathMatrix failed: %v", err)
	}
	for i := range matrix {
		for j := range matrix[i] {
			if decoded[i][j] != matrix[i][j] {
				t.Fatalf("decoded[%d][%d]=%d want=%d", i, j, decoded[i][j], matrix[i][j])
			}
		}
	}
	row, err := unpackPathRow(bits, 1, len(matrix), len(matrix[0]), width)
	if err != nil {
		t.Fatalf("unpackPathRow failed: %v", err)
	}
	for j := range row {
		if row[j] != matrix[1][j] {
			t.Fatalf("row[%d]=%d want=%d", j, row[j], matrix[1][j])
		}
	}
}
