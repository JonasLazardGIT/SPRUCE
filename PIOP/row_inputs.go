package PIOP

import (
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildRowInputs constructs LVCS row heads from row polynomials by evaluating
// them on Ω (NTT form) and truncating to ncols. A fresh copy of each head is
// returned to avoid aliasing across rows.
func buildRowInputs(ringQ *ring.Ring, rows []*ring.Poly, ncols int) []lvcs.RowInput {
	rowInputs := make([]lvcs.RowInput, len(rows))
	tmp := ringQ.NewPoly()
	for i := range rows {
		ringQ.NTT(rows[i], tmp)
		head := tmp.Coeffs[0]
		if ncols < len(head) {
			head = head[:ncols]
		}
		headCopy := append([]uint64(nil), head...)
		rowInputs[i] = lvcs.RowInput{Head: headCopy}
	}
	return rowInputs
}
