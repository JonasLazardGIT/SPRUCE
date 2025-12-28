package PIOP

import (
	"fmt"

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
// prover when Credential is false. The caller can provide a personalization string; if empty,
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
		labels := BuildPublicLabels(pub)
		labelsDigest := computeLabelsDigest(labels)

		// Small-field params (theta>1) if needed.
		var sfRows [][]uint64
		var sfK *kf.Field
		var sfChi []uint64
		var sfOmegaS1 []uint64
		var sfMuInv []uint64
		sfNCols := ncols
		// Preserve the base witness polynomials (without masks).
		origWitnessCount := witnessCount
		witnessPolys := rows[:origWitnessCount]
		if opts.Theta > 1 {
			sf, sfErr := deriveSmallFieldParamsNoRows(ringQ, omega, opts.Theta)
			if sfErr != nil {
				return nil, fmt.Errorf("small-field params: %w", sfErr)
			}
			// Use row-oriented heads as small-field rows.
			sfRows = make([][]uint64, len(rowInputs))
			for i := range rowInputs {
				head := append([]uint64(nil), rowInputs[i].Head...)
				if headLen := len(omega); len(head) > headLen {
					head = head[:headLen]
				} else if len(head) < headLen {
					padded := make([]uint64, headLen)
					copy(padded, head)
					head = padded
				}
				sfRows[i] = head
			}
			sfK = sf.K
			sfChi = sf.Chi
			sfOmegaS1 = append([]uint64(nil), sf.OmegaS1.Limb...)
			sfMuInv = append([]uint64(nil), sf.MuInv.Limb...)
			sfNCols = len(omega)
		}
		// Commit rows to get root/pk/layout using possibly updated rowInputs/layout.
		root, pk, oracleLayout, err = commitRows(ringQ, rowInputs, opts.Ell, decsParams, witnessCount, maskRowOffset, maskRowCount)
		if err != nil {
			return nil, fmt.Errorf("commit rows: %w", err)
		}

		// Rebuild constraints from the committed row polynomials (with LVCS tails)
		// to match paper-defined F_j(P,Theta). We replace the pre-sign prefix and
		// PRF suffix (if present) to keep ordering stable.
		if opts.Credential && pk != nil && len(pk.RowPolys) > 0 {
			// Rebuild pre-sign constraints when their publics are present.
			if len(pub.Ac) > 0 && len(pub.Com) > 0 && len(pub.RI0) > 0 && len(pub.RI1) > 0 && len(pub.B) > 0 && len(pub.T) > 0 {
				csRows, cerr := buildCredentialConstraintSetPreFromRows(ringQ, pub.BoundB, pub, pk.RowPolys, sfNCols)
				if cerr != nil {
					return nil, fmt.Errorf("rebuild credential constraints from rows: %w", cerr)
				}
				if len(set.FparInt) < len(csRows.FparInt) {
					return nil, fmt.Errorf("constraint set too small: have %d want >=%d", len(set.FparInt), len(csRows.FparInt))
				}
				copy(set.FparInt[:len(csRows.FparInt)], csRows.FparInt)
				set.FparNorm = csRows.FparNorm
			}
			// Rebuild post-sign constraints when A/B are present (showing path).
			if len(pub.A) > 0 && len(pub.B) > 0 {
				postRows, cerr := buildCredentialConstraintSetPostFromRows(ringQ, pub.BoundB, pub, pk.RowPolys, sfNCols)
				if cerr != nil {
					return nil, fmt.Errorf("rebuild post-sign constraints from rows: %w", cerr)
				}
				if len(set.FparInt) < len(postRows.FparInt) {
					return nil, fmt.Errorf("constraint set too small for post-sign prefix: have %d want >=%d", len(set.FparInt), len(postRows.FparInt))
				}
				copy(set.FparInt[:len(postRows.FparInt)], postRows.FparInt)
				set.FparNorm = postRows.FparNorm
				set.FaggInt = postRows.FaggInt
				set.FaggNorm = postRows.FaggNorm
			}

			// Rebuild PRF constraints when layout + tag are present.
			if set.PRFLayout != nil && len(pub.Tag) > 0 {
				params, perr := prf.LoadDefaultParams()
				if perr != nil {
					return nil, fmt.Errorf("load prf params: %w", perr)
				}
				prfSet, perr := BuildPRFConstraintSet(ringQ, params, pk.RowPolys, set.PRFLayout.StartIdx, pub.Tag, pub.Nonce, sfNCols)
				if perr != nil {
					return nil, fmt.Errorf("rebuild prf constraints from rows: %w", perr)
				}
				prfCount := len(prfSet.FparInt)
				if len(set.FparInt) < prfCount {
					return nil, fmt.Errorf("constraint set too small for PRF suffix: have %d want >=%d", len(set.FparInt), prfCount)
				}
				copy(set.FparInt[len(set.FparInt)-prfCount:], prfSet.FparInt)
			}
		}

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
		proof.PRFLayout = set.PRFLayout
		return proof, nil
	}
	// Bridge to existing PACS flow; constraint set/publics are ignored because
	// PACS builds its own witness/constraints internally.
	b := NewPACSBuilder(opts)
	return b.Build(pub, wit, MaskConfig{})
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
		ringQ, omega, _, err := loadParamsAndOmega(opts)
		if err != nil {
			return false, fmt.Errorf("load params for replay: %w", err)
		}
		if len(proof.OmegaTrunc) > 0 {
			omega = append([]uint64(nil), proof.OmegaTrunc...)
		} else if opts.NCols > 0 && len(omega) > opts.NCols {
			omega = append([]uint64(nil), omega[:opts.NCols]...)
		}
		ncols := ringQ.N
		if opts.NCols > 0 {
			ncols = opts.NCols
		}
		if proof.NColsUsed > 0 {
			ncols = proof.NColsUsed
		}

		// Build T in NTT form for replay checks.
		var tNTT *ring.Poly
		var tThetaNTT *ring.Poly
		if len(pub.T) > 0 {
			tCoeff := ringQ.NewPoly()
			q := int64(ringQ.Modulus[0])
			for i := 0; i < ringQ.N && i < len(pub.T); i++ {
				v := pub.T[i]
				if v < 0 {
					v += q
				}
				tCoeff.Coeffs[0][i] = uint64(v % q)
			}
			tNTT = ringQ.NewPoly()
			ring.Copy(tCoeff, tNTT)
			ringQ.NTT(tNTT, tNTT)
			thetaT, err := thetaPolyFromNTT(ringQ, tNTT, ncols)
			if err != nil {
				return false, fmt.Errorf("theta T: %w", err)
			}
			tThetaNTT = thetaT
		}
		var packSelNTT []uint64
		if selNTT, _, err := buildPackingSelectorNTT(ringQ, ncols); err == nil {
			packSelNTT = append([]uint64(nil), selNTT.Coeffs[0]...)
		}

		thetaAc := make([][]*ring.Poly, len(pub.Ac))
		for i := range pub.Ac {
			thetaAc[i] = make([]*ring.Poly, len(pub.Ac[i]))
			for j := range pub.Ac[i] {
				theta, err := thetaPolyFromNTT(ringQ, pub.Ac[i][j], ncols)
				if err != nil {
					return false, fmt.Errorf("theta Ac[%d][%d]: %w", i, j, err)
				}
				thetaAc[i][j] = theta
			}
		}
		thetaCom := make([]*ring.Poly, len(pub.Com))
		for i := range pub.Com {
			theta, err := thetaPolyFromNTT(ringQ, pub.Com[i], ncols)
			if err != nil {
				return false, fmt.Errorf("theta Com[%d]: %w", i, err)
			}
			thetaCom[i] = theta
		}
		thetaA := make([][]*ring.Poly, len(pub.A))
		for i := range pub.A {
			thetaA[i] = make([]*ring.Poly, len(pub.A[i]))
			for j := range pub.A[i] {
				theta, err := thetaPolyFromNTT(ringQ, pub.A[i][j], ncols)
				if err != nil {
					return false, fmt.Errorf("theta A[%d][%d]: %w", i, j, err)
				}
				thetaA[i][j] = theta
			}
		}
		var thetaRI0, thetaRI1 []*ring.Poly
		if len(pub.RI0) > 0 {
			theta, err := thetaPolyFromNTT(ringQ, pub.RI0[0], ncols)
			if err != nil {
				return false, fmt.Errorf("theta RI0: %w", err)
			}
			thetaRI0 = []*ring.Poly{theta}
		}
		if len(pub.RI1) > 0 {
			theta, err := thetaPolyFromNTT(ringQ, pub.RI1[0], ncols)
			if err != nil {
				return false, fmt.Errorf("theta RI1: %w", err)
			}
			thetaRI1 = []*ring.Poly{theta}
		}
		thetaB := make([]*ring.Poly, len(pub.B))
		for i := range pub.B {
			theta, err := thetaPolyFromNTT(ringQ, pub.B[i], ncols)
			if err != nil {
				return false, fmt.Errorf("theta B[%d]: %w", i, err)
			}
			thetaB[i] = theta
		}

		var (
			eval       ConstraintEvaluator
			evalK      KConstraintEvaluator
			rowCount   int
			haveCred   bool
			havePRF    bool
			K          *kf.Field
			boundRows  []int
			carryRows  []int
			boundB     int64
			carryBound int64
			postBoundsEval  ConstraintEvaluator
			postBoundsEvalK KConstraintEvaluator
			splitPostBounds bool
		)
		if proof.Theta > 1 {
			if len(proof.Chi) == 0 {
				return false, fmt.Errorf("missing Chi for K replay")
			}
			k, err := kf.New(ringQ.Modulus[0], proof.Theta, proof.Chi)
			if err != nil {
				return false, fmt.Errorf("kfield.New: %w", err)
			}
			K = k
		}
		// Build post-sign evaluator when A is present.
		if len(pub.A) > 0 {
			uCount := len(pub.A[0])
			cfgPost := PostSignConstraintConfig{
				Ring:          ringQ,
				A:             thetaA,
				B:             thetaB,
				Bound:         pub.BoundB,
				PackingNCols:  ncols,
				PackingSelNTT: packSelNTT,
				IdxM1:         0,
				IdxM2:         1,
				IdxR0:         5,
				IdxR1:         6,
				IdxT:          9,
				IdxUBase:      10,
				UCount:        uCount,
				BoundRows:     []int{0, 1, 5, 6},
				Omega:         omega,
			}
			splitPostBounds = set.PRFLayout != nil && len(pub.Tag) > 0
			if splitPostBounds {
				eval = cfgPost.PostSignEvaluatorCore()
				postBoundsEval = cfgPost.PostSignEvaluatorBounds()
				if proof.Theta > 1 && K != nil {
					ek, err := cfgPost.PostSignKEvaluatorCore(K)
					if err != nil {
						return false, err
					}
					evalK = ek
					bk, err := cfgPost.PostSignKEvaluatorBounds(K)
					if err != nil {
						return false, err
					}
					postBoundsEvalK = bk
				}
			} else {
				eval = cfgPost.PostSignEvaluator()
				if proof.Theta > 1 && K != nil {
					ek, err := cfgPost.PostSignKEvaluator(K)
					if err != nil {
						return false, err
					}
					evalK = ek
				}
			}
			boundRows = append([]int(nil), cfgPost.BoundRows...)
			boundB = cfgPost.Bound
			rowCount = cfgPost.IdxUBase + cfgPost.UCount
			haveCred = true
		} else if len(pub.Ac) > 0 || len(pub.Com) > 0 || len(pub.B) > 0 || len(pub.RI0) > 0 || len(pub.RI1) > 0 {
			cfgEval := CredentialConstraintConfig{
				Ring:          ringQ,
				Ac:            thetaAc,
				B:             thetaB,
				Com:           thetaCom,
				RI0:           thetaRI0,
				RI1:           thetaRI1,
				Bound:         pub.BoundB,
				CarryBound:    1,
				TPublicNTT:    tThetaNTT,
				PackingNCols:  ncols,
				PackingSelNTT: packSelNTT,
				IdxM1:         0,
				IdxM2:         1,
				IdxRU0:        2,
				IdxRU1:        3,
				IdxR:          4,
				IdxR0:         5,
				IdxR1:         6,
				IdxK0:         7,
				IdxK1:         8,
				IdxT:          -1,
				BoundRows:     []int{0, 1, 2, 3, 4, 5, 6},
				CarryRows:     []int{7, 8},
				Omega:         omega,
			}
			cfgK := CredentialConstraintConfig{
				Ring:         ringQ,
				Ac:           thetaAc,
				B:            thetaB,
				Com:          thetaCom,
				RI0:          thetaRI0,
				RI1:          thetaRI1,
				Bound:        pub.BoundB,
				CarryBound:   1,
				TPublicNTT:   tThetaNTT,
				PackingNCols: ncols,
				IdxM1:        0,
				IdxM2:        1,
				IdxRU0:       2,
				IdxRU1:       3,
				IdxR:         4,
				IdxR0:        5,
				IdxR1:        6,
				IdxK0:        7,
				IdxK1:        8,
				IdxT:         -1,
				BoundRows:    []int{0, 1, 2, 3, 4, 5, 6},
				CarryRows:    []int{7, 8},
				Omega:        omega,
			}
			eval = cfgEval.CredentialEvaluator()
			if proof.Theta > 1 && K != nil {
				ek, err := cfgK.CredentialKEvaluator(K)
				if err != nil {
					return false, err
				}
				evalK = ek
			}
			boundRows = append([]int(nil), cfgEval.BoundRows...)
			carryRows = append([]int(nil), cfgEval.CarryRows...)
			boundB = cfgEval.Bound
			carryBound = cfgEval.CarryBound
			rowCount = cfgEval.IdxK1 + 1
			haveCred = true
		}
		// Build PRF evaluator when layout is present.
		if set.PRFLayout != nil && len(pub.Tag) > 0 {
			params, err := prf.LoadDefaultParams()
			if err != nil {
				return false, fmt.Errorf("load prf params: %w", err)
			}
			cfgPRF, err := NewPRFConstraintConfig(ringQ, params, set.PRFLayout, pub.Tag, pub.Nonce, ncols)
			if err != nil {
				return false, fmt.Errorf("prf config: %w", err)
			}
			evalPRF := cfgPRF.PRFEvaluator()
			eval = composeEvaluators(eval, evalPRF)
			if proof.Theta > 1 && K != nil {
				ek, err := cfgPRF.PRFKEvaluator(K)
				if err != nil {
					return false, err
				}
				evalK = composeKEvaluators(evalK, ek)
			}
			if splitPostBounds && postBoundsEval != nil {
				eval = composeEvaluators(eval, postBoundsEval)
				if proof.Theta > 1 && K != nil && postBoundsEvalK != nil {
					evalK = composeKEvaluators(evalK, postBoundsEvalK)
				}
			}
			traceRows := set.PRFLayout.StartIdx + (set.PRFLayout.RF+set.PRFLayout.RP+1)*(set.PRFLayout.LenKey+set.PRFLayout.LenNonce)
			if traceRows > rowCount {
				rowCount = traceRows
			}
			havePRF = true
		}
		if !haveCred && !havePRF {
			return false, fmt.Errorf("no evaluators available for replay")
		}
		replay := &ConstraintReplay{
			Eval:       eval,
			EvalK:      evalK,
			RowCount:   rowCount,
			BoundRows:  boundRows,
			CarryRows:  carryRows,
			BoundB:     boundB,
			CarryBound: carryBound,
		}

		okLin, okEq4, okSum, err := VerifyNIZKWithReplay(proof, replay)
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
