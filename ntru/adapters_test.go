package ntru

import (
	"math/big"
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// TestPolyNTTToEvalCentersCoeffs verifies PolyNTTToEval recovers centered
// coefficients from an NTT-domain polynomial containing raw residues.
func TestPolyNTTToEvalCentersCoeffs(t *testing.T) {
	par, err := NewParams(16, big.NewInt(97))
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	r, err := ring.NewRing(par.N, []uint64{uint64(par.Q.Int64())})
	if err != nil {
		t.Fatalf("ring.NewRing: %v", err)
	}
	// poly has coefficient q-1 which should map to -1 after centering.
	poly := r.NewPoly()
	poly.Coeffs[0][0] = r.Modulus[0] - 1
	r.MForm(poly, poly)
	ToNTT(r, poly)
	epar := EmbedParams{Prec: 128}
	ev, err := PolyNTTToEval(r, poly, par, epar)
	if err != nil {
		t.Fatalf("PolyNTTToEval: %v", err)
	}
	cv, err := ToCoeffInt(ev, par, epar)
	if err != nil {
		t.Fatalf("ToCoeffInt: %v", err)
	}
	if cv.Int[0] != -1 {
		t.Fatalf("centered coeff[0]=%d want -1", cv.Int[0])
	}
}
