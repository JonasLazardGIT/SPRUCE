package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// buildCredentialRows maps WitnessInputs into an ordered row list for credential mode.
// Pre-sign uses 7 witness rows (M1,M2,RU0,RU1,R,R0,R1); post-sign may add U (and
// legacy callers may still provide an internal T row via wit.T).
// It returns the row polynomials,
// LVCS row inputs (heads), a basic RowLayout, decs params, and mask layout offsets.
func buildCredentialRows(ringQ *ring.Ring, wit WitnessInputs, opts SimOpts) (rows []*ring.Poly, rowInputs []lvcs.RowInput, layout RowLayout, decsParams decs.Params, maskRowOffset, maskRowCount, witnessCount, ncols int, err error) {
	if ringQ == nil {
		err = fmt.Errorf("nil ring")
		return
	}
	opts.applyDefaults()
	if opts.NCols <= 0 {
		opts.NCols = int(ringQ.N)
	}
	ncols = opts.NCols

	require := func(vec []*ring.Poly, name string) error {
		if len(vec) == 0 {
			return fmt.Errorf("missing witness row %s", name)
		}
		return nil
	}
	if err = require(wit.M1, "M1"); err != nil {
		return
	}
	if err = require(wit.M2, "M2"); err != nil {
		return
	}
	if err = require(wit.RU0, "RU0"); err != nil {
		return
	}
	if err = require(wit.RU1, "RU1"); err != nil {
		return
	}
	if err = require(wit.R, "R"); err != nil {
		return
	}
	if err = require(wit.R0, "R0"); err != nil {
		return
	}
	if err = require(wit.R1, "R1"); err != nil {
		return
	}
	if err = require(wit.K0, "K0"); err != nil {
		return
	}
	if err = require(wit.K1, "K1"); err != nil {
		return
	}

	rows = []*ring.Poly{
		wit.M1[0],
		wit.M2[0],
		wit.RU0[0],
		wit.RU1[0],
		wit.R[0],
		wit.R0[0],
		wit.R1[0],
		wit.K0[0],
		wit.K1[0],
	}
	// Legacy: some callers still provide T as an internal witness (hash output).
	// Paper-faithful pre-sign issuance treats T/t as public, so new callers should
	// omit wit.T and provide pub.T instead.
	if len(wit.T) > 0 {
		// T is provided as coeff slice; lift to polynomial.
		tPoly := ringQ.NewPoly()
		if len(wit.T) > len(tPoly.Coeffs[0]) {
			err = fmt.Errorf("t length %d exceeds ring dimension %d", len(wit.T), len(tPoly.Coeffs[0]))
			return
		}
		q := int64(ringQ.Modulus[0])
		for i := range wit.T {
			v := wit.T[i] % q
			if v < 0 {
				v += q
			}
			tPoly.Coeffs[0][i] = uint64(v)
		}
		rows = append(rows, tPoly)
	}

	// Post-signature: include U if provided.
	if len(wit.U) > 0 {
		rows = append(rows, wit.U...)
	}

	// Build row inputs (heads) in evaluation domain (Ω).
	rowInputs = buildRowInputs(ringQ, rows, ncols)

	// Layout: we only set counts; range/chain bases unused for credential mode.
	witnessCount = len(rows)
	layout = RowLayout{
		SigCount: witnessCount,
		MsgCount: 0,
		RndCount: 0,
	}

	// Masks start after witness rows.
	maskRowOffset = len(rows)
	maskRowCount = opts.Rho
	if maskRowCount > 0 {
		zeroHead := make([]uint64, ncols)
		for i := 0; i < maskRowCount; i++ {
			rows = append(rows, ringQ.NewPoly())
			rowInputs = append(rowInputs, lvcs.RowInput{Head: zeroHead})
		}
	}

	// DECS params: degree bound based on ncols+ell-1 (clipped by ring size), eta from opts.
	maxDegree := opts.DQOverride
	if maxDegree <= 0 || maxDegree >= int(ringQ.N) {
		maxDegree = ncols + opts.Ell - 1
		if maxDegree >= int(ringQ.N) {
			maxDegree = int(ringQ.N) - 1
		}
	}
	decsParams = decs.Params{Degree: maxDegree, Eta: opts.Eta, NonceBytes: 16}
	return
}
