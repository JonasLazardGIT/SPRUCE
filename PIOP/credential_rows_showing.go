package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// BuildCredentialRowsShowing maps witness inputs into rows for the showing (post-sign) proof.
// It reuses the pre-sign rows (M1,M2,RU0,RU1,R,R0,R1,K0,K1) and appends the full PRF trace:
// x^(r)_j for r=0..R (R=RF+RP), j=0..t-1 in row-major order. startIdx is the index
// where x^(0)_0 begins in the returned rows.
func BuildCredentialRowsShowing(ringQ *ring.Ring, wit WitnessInputs, prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP int, opts SimOpts) (rows []*ring.Poly, rowInputs []lvcs.RowInput, layout RowLayout, decsParams decs.Params, maskRowOffset, maskRowCount, witnessCount, startIdx, ncols int, err error) {
	if ringQ == nil {
		err = fmt.Errorf("nil ring")
		return
	}
	opts.applyDefaults()
	if opts.NCols <= 0 {
		opts.NCols = int(ringQ.N)
	}
	ncols = opts.NCols
	// Pre-sign base rows.
	// Pre-sign rows: optional in PRF-only demos; include only if provided.
	if len(wit.M1) > 0 {
		rows = append(rows, wit.M1[0])
	}
	if len(wit.M2) > 0 {
		rows = append(rows, wit.M2[0])
	}
	if len(wit.RU0) > 0 {
		rows = append(rows, wit.RU0[0])
	}
	if len(wit.RU1) > 0 {
		rows = append(rows, wit.RU1[0])
	}
	if len(wit.R) > 0 {
		rows = append(rows, wit.R[0])
	}
	if len(wit.R0) > 0 {
		rows = append(rows, wit.R0[0])
	}
	if len(wit.R1) > 0 {
		rows = append(rows, wit.R1[0])
	}
	if len(wit.K0) > 0 {
		rows = append(rows, wit.K0[0])
	}
	if len(wit.K1) > 0 {
		rows = append(rows, wit.K1[0])
	}
	// Optional internal T row (hash output) for post-signature proofs.
	if len(wit.T) > 0 {
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
	// Post-signature: include all U rows if provided.
	if len(wit.U) > 0 {
		rows = append(rows, wit.U...)
	}

	// PRF trace rows (required for showing).
	t := prfParamsLenKey + prfParamsLenNonce
	R := prfRF + prfRP
	traceRowsNeeded := (R + 1) * t
	if traceRowsNeeded == 0 {
		err = fmt.Errorf("prf trace rows missing: lenkey=%d lennonce=%d RF=%d RP=%d", prfParamsLenKey, prfParamsLenNonce, prfRF, prfRP)
		return
	}
	if len(wit.Extras) == 0 {
		err = fmt.Errorf("missing PRF trace in witness Extras")
		return
	}
	traceAny, ok := wit.Extras["prf_trace"]
	if !ok {
		err = fmt.Errorf("missing prf_trace in witness Extras")
		return
	}
	tracePolys, ok := traceAny.([]*ring.Poly)
	if !ok {
		err = fmt.Errorf("prf_trace has wrong type")
		return
	}
	if len(tracePolys) != traceRowsNeeded {
		err = fmt.Errorf("prf_trace len=%d want %d", len(tracePolys), traceRowsNeeded)
		return
	}
	startIdx = len(rows)
	rows = append(rows, tracePolys...)

	// Build row inputs (heads) in evaluation domain (Ω).
	rowInputs = buildRowInputs(ringQ, rows, ncols)

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
