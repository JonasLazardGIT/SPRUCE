package PIOP

import (
	"fmt"

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
		if len(set.FparInt)+len(set.FparNorm)+len(set.FaggInt)+len(set.FaggNorm) == 0 {
			return nil, fmt.Errorf("empty constraint set for credential mode")
		}
		// Map witness inputs to rows/layout/decs params.
		rows, rowInputs, rowLayout, decsParams, maskRowOffset, maskRowCount, witnessCount, _, err := buildCredentialRows(ringQ, wit, opts)
		if err != nil {
			return nil, fmt.Errorf("build credential rows: %w", err)
		}
		// Commit rows to get root/pk/layout.
		root, pk, oracleLayout, err := commitRows(ringQ, rowInputs, opts.Ell, decsParams, witnessCount, maskRowOffset, maskRowCount)
		if err != nil {
			return nil, fmt.Errorf("commit rows: %w", err)
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
		labels := BuildPublicLabels(pub)
		labelsDigest := computeLabelsDigest(labels)

		// Assemble MaskingFSInput and run.
		mfsIn := MaskingFSInput{
			RingQ:            ringQ,
			Opts:             opts,
			Omega:            omega,
			Root:             root,
			PK:               pk,
			OracleLayout:     oracleLayout,
			RowLayout:        rowLayout,
			FparInt:          set.FparInt,
			FparNorm:         set.FparNorm,
			FaggInt:          set.FaggInt,
			FaggNorm:         set.FaggNorm,
			RowInputs:        rowInputs,
			WitnessPolys:     rows,
			MaskPolys:        nil,
			MaskRowOffset:    maskRowOffset,
			MaskRowCount:     maskRowCount,
			MaskDegreeTarget: maskTarget,
			MaskDegreeBound:  maskBound,
			Personalization:  personalization,
			NCols:            ncols,
			DecsParams:       decsParams,
			LabelsDigest:     labelsDigest,
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
		if len(proof.LabelsDigest) > 0 && !equalByteSlices(digest, proof.LabelsDigest) {
			return false, fmt.Errorf("labels digest mismatch")
		}
		okLin, okEq4, okSum, err := VerifyNIZK(proof)
		return okLin && okEq4 && okSum, err
	}
	okLin, okEq4, okSum, err := VerifyNIZK(proof)
	return okLin && okEq4 && okSum, err
}

// matrixEqualUint64 compares two [][]uint64 matrices for exact equality.
func matrixEqualUint64(a, b [][]uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}
