package PIOP

import (
	"fmt"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// smallFieldParams bundles the extension-field data needed when Theta>1.
type smallFieldParams struct {
	K       *kf.Field
	Chi     []uint64
	OmegaS1 kf.Elem
	MuInv   kf.Elem
	Rows    [][]uint64 // coeff heads of rows (theta>1 projection)
}

// deriveSmallFieldParams reproduces the Theta>1 setup from buildSimWith:
// finds an irreducible chi, constructs K, converts columns to rows over the
// small field, and computes omegaS1/muInv for k-point constraints.
func deriveSmallFieldParams(ringQ *ring.Ring, omega []uint64, w1 []*ring.Poly, w2 *ring.Poly, w3 []*ring.Poly, ell, ncols, theta int) (smallFieldParams, error) {
	var out smallFieldParams
	if ringQ == nil {
		return out, fmt.Errorf("nil ring")
	}
	if theta <= 1 {
		return out, fmt.Errorf("theta must be >1")
	}
	q := ringQ.Modulus[0]
	chi, chiErr := kf.FindIrreducible(q, theta, nil)
	if chiErr != nil {
		return out, fmt.Errorf("FindIrreducible: %w", chiErr)
	}
	K, kErr := kf.New(q, theta, chi)
	if kErr != nil {
		return out, fmt.Errorf("kfield.New: %w", kErr)
	}
	rows, omegaS1, muInv, convErr := columnsToRowsSmallField(ringQ, w1, w2, w3, ell, omega, ncols, K)
	if convErr != nil {
		return out, fmt.Errorf("columnsToRowsSmallField: %w", convErr)
	}
	out = smallFieldParams{
		K:       K,
		Chi:     append([]uint64(nil), chi...),
		OmegaS1: omegaS1,
		MuInv:   muInv,
		Rows:    rows,
	}
	return out, nil
}
