package lvcs

import (
	"reflect"
	"testing"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestEvalInitManyRoundTrip(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatalf("ring.NewRing: %v", err)
	}
	rows := []RowInput{
		{Head: []uint64{1, 2, 3, 4}, Tail: []uint64{10, 11, 12, 13}},
		{Head: []uint64{5, 6, 7, 8}, Tail: []uint64{14, 15, 16, 17}},
		{Head: []uint64{9, 10, 11, 12}, Tail: nil}, // force random tail generation
	}
	ell := 4
	params := decs.Params{Degree: 7, Eta: 2, NonceBytes: 24}
	_, prover, err := CommitInitWithParams(ringQ, rows, ell, params)
	if err != nil {
		t.Fatalf("CommitInitWithParams: %v", err)
	}
	if len(prover.Rows) != len(rows) {
		t.Fatalf("prover rows mismatch: got %d want %d", len(prover.Rows), len(rows))
	}
	for i, in := range rows {
		if in.Tail != nil && !reflect.DeepEqual(in.Tail, prover.Rows[i].Tail) {
			t.Fatalf("tail #%d mismatch: got %v want %v", i, prover.Rows[i].Tail, in.Tail)
		}
		if len(prover.Rows[i].Tail) != ell {
			t.Fatalf("tail #%d length mismatch: got %d want %d", i, len(prover.Rows[i].Tail), ell)
		}
	}
	reqs := []EvalRequest{
		{Point: 3, Coeffs: []uint64{1, 0, 2}},
		{Point: 5, Coeffs: []uint64{2, 1, 1}},
	}
	bars := EvalInitMany(ringQ, prover, reqs)
	if len(bars) != len(reqs) {
		t.Fatalf("expected %d bar sets, got %d", len(reqs), len(bars))
	}
	q := ringQ.Modulus[0]
	for k, req := range reqs {
		want := make([]uint64, ell)
		for j := range prover.Rows {
			tail := prover.Rows[j].Tail
			for i := 0; i < ell; i++ {
				want[i] = (want[i] + req.Coeffs[j]*tail[i]) % q
			}
		}
		if !reflect.DeepEqual(want, bars[k]) {
			t.Fatalf("bar[%d] mismatch: want %v got %v", k, want, bars[k])
		}
	}
}

func TestEvalOracleRespectsLayout(t *testing.T) {
	ringQ, err := ring.NewRing(16, []uint64{12289})
	if err != nil {
		t.Fatalf("ring.NewRing: %v", err)
	}
	rows := []RowInput{
		{Head: []uint64{1, 0, 2}, Tail: []uint64{3, 4}},
		{Head: []uint64{5, 6, 7}, Tail: []uint64{8, 9}},
		{Head: []uint64{9, 8, 7}, Tail: []uint64{6, 5}},
	}
	ell := 2
	params := decs.Params{Degree: 6, Eta: 2, NonceBytes: 16}
	_, prover, err := CommitInitWithParams(ringQ, rows, ell, params)
	if err != nil {
		t.Fatalf("CommitInitWithParams: %v", err)
	}
	layout := OracleLayout{
		Witness: LayoutSegment{Offset: 0, Count: 2},
		Mask:    LayoutSegment{Offset: 2, Count: 1},
	}
	if err := prover.SetLayout(layout); err != nil {
		t.Fatalf("SetLayout: %v", err)
	}
	points := []uint64{0, 1, 5}
	respDefault, err := EvalOracle(ringQ, prover, points, OracleLayout{})
	if err != nil {
		t.Fatalf("EvalOracle (default layout): %v", err)
	}
	respExplicit, err := EvalOracle(ringQ, prover, points, layout)
	if err != nil {
		t.Fatalf("EvalOracle (explicit layout): %v", err)
	}
	if !reflect.DeepEqual(respDefault.Witness, respExplicit.Witness) || !reflect.DeepEqual(respDefault.Mask, respExplicit.Mask) {
		t.Fatalf("EvalOracle results differ between default and explicit layout")
	}
	expectWitness := make([][]uint64, layout.Witness.Count)
	expectMask := make([][]uint64, layout.Mask.Count)
	mod := ringQ.Modulus[0]
	for idx := 0; idx < layout.Witness.Count; idx++ {
		row := prover.Rows[layout.Witness.Offset+idx]
		poly, interpErr := interpolateRow(ringQ, row.Head, row.Tail, len(row.Head), len(row.Tail))
		if interpErr != nil {
			t.Fatalf("interpolateRow witness %d: %v", idx, interpErr)
		}
		length := len(row.Head) + len(row.Tail)
		expectWitness[idx] = make([]uint64, len(points))
		for j, pt := range points {
			expectWitness[idx][j] = evalPolyCoeffs(poly.Coeffs[0][:length], pt%mod, mod)
		}
	}
	for idx := 0; idx < layout.Mask.Count; idx++ {
		row := prover.Rows[layout.Mask.Offset+idx]
		poly, interpErr := interpolateRow(ringQ, row.Head, row.Tail, len(row.Head), len(row.Tail))
		if interpErr != nil {
			t.Fatalf("interpolateRow mask %d: %v", idx, interpErr)
		}
		length := len(row.Head) + len(row.Tail)
		expectMask[idx] = make([]uint64, len(points))
		for j, pt := range points {
			expectMask[idx][j] = evalPolyCoeffs(poly.Coeffs[0][:length], pt%mod, mod)
		}
	}
	if !reflect.DeepEqual(expectWitness, respExplicit.Witness) {
		t.Fatalf("witness evaluations mismatch\nwant %v\ngot  %v", expectWitness, respExplicit.Witness)
	}
	if !reflect.DeepEqual(expectMask, respExplicit.Mask) {
		t.Fatalf("mask evaluations mismatch\nwant %v\ngot  %v", expectMask, respExplicit.Mask)
	}
	if _, err := EvalOracle(ringQ, prover, points, OracleLayout{
		Witness: LayoutSegment{Offset: 0, Count: len(prover.Rows)},
		Mask:    LayoutSegment{Offset: len(prover.Rows) - 1, Count: 1},
	}); err == nil {
		t.Fatalf("EvalOracle should reject overlapping layout")
	}
}
