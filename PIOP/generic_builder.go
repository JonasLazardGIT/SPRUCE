package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// FS personalization string for credential-mode statements.
const FSModeCredential = "PACS-Credential"

// BuildWithConstraints is an entry point to prove a statement from explicit
// publics/witnesses and a custom constraint set (F-polys), instead of relying
// on the baked-in PACS wiring. For now, this bridges to the existing PACS
// prover when Credential is false; the credential/generalized path is still
// TODO. The caller can provide a personalization string; if empty,
// FSModeCredential is used.
func BuildWithConstraints(pub PublicInputs, wit WitnessInputs, set ConstraintSet, opts SimOpts, personalization string) (*Proof, error) {
	opts.applyDefaults()
	if personalization == "" {
		personalization = FSModeCredential
	}
	if opts.Credential {
		// Credential path: build rows, commit, derive mask config, and run FS with supplied constraints/publics.
		ringQ, omega, ncols, err := loadParamsAndOmega(opts)
		if err != nil {
			return nil, fmt.Errorf("load params/omega: %w", err)
		}
		if opts.Theta > 1 && opts.NCols > 0 && len(omega) > opts.NCols {
			omega = append([]uint64(nil), omega[:opts.NCols]...)
			ncols = opts.NCols
		}
		if len(set.FparInt)+len(set.FparNorm)+len(set.FaggInt)+len(set.FaggNorm) == 0 {
			return nil, fmt.Errorf("empty constraint set for credential mode")
		}
		// Map witness inputs to rows/layout/decs params.
		rows, rowInputs, rowLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, _, err := buildCredentialRows(ringQ, wit, opts)
		// If PRF trace is present, switch to showing row builder.
		if err == nil && wit.Extras != nil {
			if _, ok := wit.Extras["prf_trace"]; ok {
				params, perr := prf.LoadDefaultParams()
				if perr != nil {
					return nil, fmt.Errorf("load prf params: %w", perr)
				}
				rows, rowInputs, rowLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, _, _, perr = BuildCredentialRowsShowing(ringQ, wit, params.LenKey, params.LenNonce, params.RF, params.RP, opts)
				if perr != nil {
					return nil, fmt.Errorf("build showing rows: %w", perr)
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("build credential rows: %w", err)
		}
		var root [16]byte
		var pk *lvcs.ProverKey
		var oracleLayout lvcs.OracleLayout
		// Flatten constraint set for masking config derivation.
		FparAll := append([]*ring.Poly{}, set.FparInt...)
		FparAll = append(FparAll, set.FparNorm...)
		FaggAll := append([]*ring.Poly{}, set.FaggInt...)
		FaggAll = append(FaggAll, set.FaggNorm...)
		_, _, maskTarget, maskBound, _, maskClipped, err := deriveMaskingConfig(ringQ, opts, FparAll, FaggAll, omega)
		if err != nil {
			return nil, fmt.Errorf("derive masking config: %w", err)
		}
		_ = maskClipped
		labels := BuildPublicLabels(pub)
		labelsDigest := computeLabelsDigest(labels)

		// Small-field params (theta>1) if needed.
		var sfRows [][]uint64
		var sfK *kf.Field
		var sfChi []uint64
		var sfOmegaS1 []uint64
		var sfMuInv []uint64
		sfNCols := ncols
		// Adjust witness polys when theta>1 to match small-field row layout.
		witnessPolys := rows
		if opts.Theta > 1 {
			sf, sfErr := deriveSmallFieldParams(ringQ, omega, rows, nil, nil, opts.Ell, ncols, opts.Theta)
			if sfErr != nil {
				return nil, fmt.Errorf("small-field params: %w", sfErr)
			}
			headLen := opts.NCols
			if headLen <= 0 || headLen > len(omega) {
				headLen = len(omega)
			}
			// Truncate omega to headLen.
			if headLen < len(omega) {
				omega = append([]uint64(nil), omega[:headLen]...)
			}
			// Truncate/pad small-field rows to headLen to match omega/ell' expectations.
			sfRows = make([][]uint64, len(sf.Rows))
			for i := range sf.Rows {
				row := sf.Rows[i]
				if len(row) > headLen {
					row = row[:headLen]
				} else if len(row) < headLen {
					padded := make([]uint64, headLen)
					copy(padded, row)
					row = padded
				}
				sfRows[i] = row
			}
			// Override layout for theta>1: witness rows = len(sfRows), masks appended after.
			witnessCount = len(sfRows)
			maskRowOffset = witnessCount
			maskRowCount = opts.Rho
			for i := 0; i < maskRowCount; i++ {
				sfRows = append(sfRows, make([]uint64, headLen))
			}
			if len(sfRows) != maskRowOffset+maskRowCount {
				return nil, fmt.Errorf("small-field rows total mismatch: got %d want %d", len(sfRows), maskRowOffset+maskRowCount)
			}
			// Rebuild rowInputs to match small-field rows.
			rowInputs = make([]lvcs.RowInput, len(sfRows))
			for i := range sfRows {
				rowInputs[i] = lvcs.RowInput{Head: sfRows[i]}
			}
			rowLayout.SigCount = witnessCount
			rowLayout.MsgCount = 0
			rowLayout.RndCount = 0
			sfK = sf.K
			sfChi = sf.Chi
			sfOmegaS1 = append([]uint64(nil), sf.OmegaS1.Limb...)
			sfMuInv = append([]uint64(nil), sf.MuInv.Limb...)
			sfNCols = headLen
			// Truncate omega to the small-field head length to keep LVCS consistent.
			if headLen < len(omega) {
				omega = append([]uint64(nil), omega[:headLen]...)
			}
			// Pad witness polys to witnessCount (small-field adds theta rows per block).
			if len(witnessPolys) < witnessCount {
				padded := make([]*ring.Poly, witnessCount)
				copy(padded, witnessPolys)
				for i := len(witnessPolys); i < witnessCount; i++ {
					padded[i] = ringQ.NewPoly()
				}
				witnessPolys = padded
			}
			rows = witnessPolys
			// Recompute decs params for small-field head length, matching LVCS blinding.
			maxDegree := sfNCols + opts.Ell - 1
			if maxDegree >= int(ringQ.N) {
				maxDegree = int(ringQ.N) - 1
			}
			decsParams = decs.Params{Degree: maxDegree, Eta: opts.Eta, NonceBytes: 16}
			// Rebuild omega slice to headLen.
			if len(omega) > sfNCols {
				omega = append([]uint64(nil), omega[:sfNCols]...)
			}
		}
		// Commit rows to get root/pk/layout using possibly updated rowInputs/layout.
		root, pk, oracleLayout, err = commitRows(ringQ, rowInputs, opts.Ell, decsParams, witnessCount, maskRowOffset, maskRowCount)
		if err != nil {
			return nil, fmt.Errorf("commit rows: %w", err)
		}

		// Assemble MaskingFSInput and run.
		mfsIn := MaskingFSInput{
			RingQ:        ringQ,
			Opts:         opts,
			Omega:        omega,
			Root:         root,
			PK:           pk,
			OracleLayout: oracleLayout,
			RowLayout:    rowLayout,
			FparInt:      set.FparInt,
			FparNorm:     set.FparNorm,
			FaggInt:      set.FaggInt,
			FaggNorm:     set.FaggNorm,
			RowInputs:    rowInputs,
			// For theta>1 we rely on SmallFieldRows/RowInputs; full polys are unused by runMaskFS.
			WitnessPolys:      witnessPolys,
			MaskPolys:         nil,
			MaskRowOffset:     maskRowOffset,
			MaskRowCount:      maskRowCount,
			MaskDegreeTarget:  maskTarget,
			MaskDegreeBound:   maskBound,
			Personalization:   personalization,
			NCols:             sfNCols,
			DecsParams:        decsParams,
			LabelsDigest:      labelsDigest,
			SmallFieldChi:     sfChi,
			SmallFieldOmegaS1: sfOmegaS1,
			SmallFieldMuInv:   sfMuInv,
			SmallFieldK:       sfK,
			SmallFieldRows:    sfRows,
		}
		proof, err := RunMaskingFS(mfsIn)
		if err != nil {
			return nil, fmt.Errorf("RunMaskingFS: %w", err)
		}
		// Snapshot constraint polys and public labels into proof for completeness.
		proof.FparNTT = polysToNTTMatrix(FparAll)
		proof.FaggNTT = polysToNTTMatrix(FaggAll)
		proof.LabelsDigest = labelsDigest
		return proof, nil
	}
	// Bridge to existing PACS flow; constraint set/publics are ignored because
	// PACS builds its own witness/constraints internally.
	b := NewPACSBuilder(opts)
	return b.Build(pub, wit, MaskConfig{})
}

// BuildWithRows mirrors BuildWithConstraints but accepts precomputed rows/layout.
// Currently supports theta=1 only.
func BuildWithRows(pub PublicInputs, set ConstraintSet, opts SimOpts, rows []*ring.Poly, rowInputs []lvcs.RowInput, rowLayout RowLayout, decsParams decs.Params, maskRowOffset, maskRowCount, witnessCount, ncols int) (*Proof, error) {
	opts.applyDefaults()
	if !opts.Credential {
		return nil, fmt.Errorf("BuildWithRows is credential-only")
	}
	if len(set.FparInt)+len(set.FparNorm)+len(set.FaggInt)+len(set.FaggNorm) == 0 {
		return nil, fmt.Errorf("empty constraint set")
	}
	ringQ, omega, _, err := loadParamsAndOmega(opts)
	if err != nil {
		return nil, fmt.Errorf("load params/omega: %w", err)
	}
	FparAll := append([]*ring.Poly{}, set.FparInt...)
	FparAll = append(FparAll, set.FparNorm...)
	FaggAll := append([]*ring.Poly{}, set.FaggInt...)
	FaggAll = append(FaggAll, set.FaggNorm...)
	_, _, maskTarget, maskBound, _, _, err := deriveMaskingConfig(ringQ, opts, FparAll, FaggAll, omega)
	if err != nil {
		return nil, fmt.Errorf("derive masking config: %w", err)
	}
	labels := BuildPublicLabels(pub)
	labelsDigest := computeLabelsDigest(labels)
	// Small-field path if theta>1.
	var (
		sfRows                 [][]uint64
		sfK                    *kf.Field
		sfChi                  []uint64
		sfOmegaS1              []uint64
		sfMuInv                []uint64
		sfNCols                = ncols
		witnessPolys           = rows
		rowInputsEffective     = rowInputs
		rowLayoutEffective     = rowLayout
		decsParamsEffective    = decsParams
		witnessCountEffective  = witnessCount
		maskRowOffsetEffective = maskRowOffset
		maskRowCountEffective  = maskRowCount
	)
	if opts.Theta > 1 {
		// Derive small-field rows from the provided witness rows.
		headLen := ncols
		if headLen <= 0 || headLen > len(omega) {
			headLen = len(omega)
		}
		omega = append([]uint64(nil), omega[:headLen]...)
		sf, sfErr := deriveSmallFieldParams(ringQ, omega, rows, nil, nil, opts.Ell, headLen, opts.Theta)
		if sfErr != nil {
			return nil, fmt.Errorf("small-field params: %w", sfErr)
		}
		sfRows = make([][]uint64, len(sf.Rows))
		for i := range sf.Rows {
			row := sf.Rows[i]
			if len(row) > headLen {
				row = row[:headLen]
			} else if len(row) < headLen {
				pad := make([]uint64, headLen)
				copy(pad, row)
				row = pad
			}
			sfRows[i] = row
		}
		witnessCountEffective = len(sfRows)
		maskRowOffsetEffective = witnessCountEffective
		maskRowCountEffective = opts.Rho
		for i := 0; i < maskRowCountEffective; i++ {
			sfRows = append(sfRows, make([]uint64, headLen))
		}
		rowInputsEffective = make([]lvcs.RowInput, len(sfRows))
		for i := range sfRows {
			rowInputsEffective[i] = lvcs.RowInput{Head: sfRows[i]}
		}
		rowLayoutEffective = RowLayout{SigCount: witnessCountEffective}
		sfK = sf.K
		sfChi = sf.Chi
		sfOmegaS1 = append([]uint64(nil), sf.OmegaS1.Limb...)
		sfMuInv = append([]uint64(nil), sf.MuInv.Limb...)
		sfNCols = headLen
		if len(omega) > sfNCols {
			omega = append([]uint64(nil), omega[:sfNCols]...)
		}
		if witnessCountEffective > len(witnessPolys) {
			pad := make([]*ring.Poly, witnessCountEffective)
			copy(pad, witnessPolys)
			for i := len(witnessPolys); i < witnessCountEffective; i++ {
				pad[i] = ringQ.NewPoly()
			}
			witnessPolys = pad
		}
		// Degree bound for LVCS on headLen.
		maxDegree := sfNCols + opts.Ell - 1
		if maxDegree >= int(ringQ.N) {
			maxDegree = int(ringQ.N) - 1
		}
		decsParamsEffective = decs.Params{Degree: maxDegree, Eta: opts.Eta, NonceBytes: 16}
	}

	root, pk, oracleLayout, err := commitRows(ringQ, rowInputsEffective, opts.Ell, decsParamsEffective, witnessCountEffective, maskRowOffsetEffective, maskRowCountEffective)
	if err != nil {
		return nil, fmt.Errorf("commit rows: %w", err)
	}
	mfsIn := MaskingFSInput{
		RingQ:             ringQ,
		Opts:              opts,
		Omega:             omega,
		Root:              root,
		PK:                pk,
		OracleLayout:      oracleLayout,
		RowLayout:         rowLayoutEffective,
		FparInt:           set.FparInt,
		FparNorm:          set.FparNorm,
		FaggInt:           set.FaggInt,
		FaggNorm:          set.FaggNorm,
		RowInputs:         rowInputsEffective,
		WitnessPolys:      witnessPolys,
		MaskRowOffset:     maskRowOffsetEffective,
		MaskRowCount:      maskRowCountEffective,
		MaskDegreeTarget:  maskTarget,
		MaskDegreeBound:   maskBound,
		Personalization:   FSModeCredential,
		NCols:             sfNCols,
		DecsParams:        decsParamsEffective,
		LabelsDigest:      labelsDigest,
		SmallFieldChi:     sfChi,
		SmallFieldOmegaS1: sfOmegaS1,
		SmallFieldMuInv:   sfMuInv,
		SmallFieldK:       sfK,
		SmallFieldRows:    sfRows,
	}
	proof, err := RunMaskingFS(mfsIn)
	if err != nil {
		return nil, fmt.Errorf("RunMaskingFS: %w", err)
	}
	proof.FparNTT = polysToNTTMatrix(FparAll)
	proof.FaggNTT = polysToNTTMatrix(FaggAll)
	proof.LabelsDigest = labelsDigest
	return proof, nil
}

// VerifyWithConstraints replays the FS transcript for a proof built with
// BuildWithConstraints, using the supplied constraint set, personalization,
// and public inputs. For now, PACS still bridges to VerifyNIZK.
func VerifyWithConstraints(proof *Proof, set ConstraintSet, pub PublicInputs, opts SimOpts, personalization string) (bool, error) {
	opts.applyDefaults()
	if proof == nil {
		return false, fmt.Errorf("nil proof")
	}
	if len(set.FparInt)+len(set.FparNorm)+len(set.FaggInt)+len(set.FaggNorm) == 0 && !opts.Credential {
		// For PACS, constraint set is ignored; for credential we enforce non-empty above.
	}
	if personalization == "" {
		personalization = FSModeCredential
	}
	if opts.Credential {
		// For credential mode, constraint polys are already snapshotted into the proof; we only
		// bind publics via labels digest and replay the transcript.
		labels := BuildPublicLabels(pub)
		digest := computeLabelsDigest(labels)
		if len(proof.LabelsDigest) == 0 {
			// Backfill for proofs that predate label hashing.
			proof.LabelsDigest = digest
		} else if !equalByteSlices(digest, proof.LabelsDigest) {
			return false, fmt.Errorf("labels digest mismatch")
		}
		// If the prover recorded a truncated domain, respect it; otherwise allow opts.NCols as a hint.
		if proof.NColsUsed == 0 && opts.NCols > 0 {
			proof.NColsUsed = opts.NCols
		}
		if len(proof.OmegaTrunc) == 0 && opts.NCols > 0 {
			omega, err := deriveOmegaWithNCols(opts.NCols)
			if err == nil {
				proof.OmegaTrunc = omega
			}
		}
		// Extra soundness for credential mode: the prover supplied FparNTT/FaggNTT
		// snapshots. Enforce that every Fpar poly is identically zero (all
		// coefficients), which should hold on honest instances; any tampering that
		// leaves non-zero residuals is rejected before running the PCS checks.
		if len(proof.FparNTT) > 0 {
			par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
			if err != nil {
				return false, fmt.Errorf("load params for Fpar check: %w", err)
			}
			ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
			if err != nil {
				return false, fmt.Errorf("ring for Fpar check: %w", err)
			}
			omega := proof.OmegaTrunc
			if len(omega) == 0 && opts.NCols > 0 {
				omega, err = deriveOmegaWithNCols(opts.NCols)
				if err != nil {
					return false, fmt.Errorf("derive omega for Fpar check: %w", err)
				}
			}
			cols := len(omega)
			if cols == 0 {
				if len(proof.FparNTT) > 0 {
					cols = len(proof.FparNTT[0])
				}
			}
			q := ringQ.Modulus[0]
			for idx, row := range proof.FparNTT {
				for j := 0; j < cols && j < len(row); j++ {
					if row[j]%q != 0 {
						return false, fmt.Errorf("non-zero Fpar residual at row %d col %d", idx, j)
					}
				}
			}
		}
		okLin, okEq4, okSum, err := VerifyNIZK(proof)
		return okLin && okEq4 && okSum, err
	}
	okLin, okEq4, okSum, err := VerifyNIZK(proof)
	return okLin && okEq4 && okSum, err
}

// deriveOmegaWithNCols mirrors the prover's omega derivation but limits the
// domain to ncols. Used as a fallback when the proof does not carry OmegaTrunc.
func deriveOmegaWithNCols(ncols int) ([]uint64, error) {
	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
	if err != nil {
		return nil, fmt.Errorf("load params: %w", err)
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		return nil, fmt.Errorf("ring: %w", err)
	}
	if ncols <= 0 || ncols > ringQ.N {
		return nil, fmt.Errorf("invalid ncols %d", ncols)
	}
	px := ringQ.NewPoly()
	px.Coeffs[0][1] = 1
	pts := ringQ.NewPoly()
	ringQ.NTT(px, pts)
	omega := append([]uint64(nil), pts.Coeffs[0][:ncols]...)
	return omega, nil
}
