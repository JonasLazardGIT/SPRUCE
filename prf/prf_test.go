package prf

import "testing"

// A minimal sanity test with tiny parameters (not from the paper).
func TestPRFSanity(t *testing.T) {
	p := &Params{
		Q:        101,
		D:        5,
		LenKey:   2,
		LenNonce: 1,
		LenTag:   1,
		RF:       4,
		RP:       1,
		ME: [][]uint64{
			{1, 2, 3},
			{4, 5, 6},
			{7, 8, 10},
		},
		MI: [][]uint64{
			{2, 1, 0},
			{0, 3, 1},
			{1, 0, 2},
		},
		CExt: [][]uint64{
			{1, 1, 1},
			{2, 2, 2},
			{3, 3, 3},
			{4, 4, 4},
		},
		CInt: []uint64{5},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	key := []Elem{1, 2}
	nonce := []Elem{3}
	tag, err := Tag(key, nonce, p)
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	if len(tag) != 1 {
		t.Fatalf("tag length = %d want 1", len(tag))
	}
	// Deterministic check on fixed params.
	const expected = Elem(42)
	if tag[0] != expected {
		t.Fatalf("tag[0]=%d want %d", tag[0], expected)
	}
}
