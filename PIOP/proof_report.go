package PIOP

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// ProofReport captures proof size and soundness metrics for a built proof.
type ProofReport struct {
	ProofBytes int
	ProofKB    float64
	Soundness  SoundnessBudget
	NCols      int
	Ell        int
	EllPrime   int
	Rho        int
	Theta      int
	Eta        int
	DQ         int
	Lambda     int
	Kappa      [4]int
}

// BuildProofReport derives proof size + soundness metrics for a given proof/options.
// This is intended for credential issuance/showing runs (outside RunOnce).
func BuildProofReport(proof *Proof, opts SimOpts, ringQ *ring.Ring) (ProofReport, error) {
	if proof == nil {
		return ProofReport{}, fmt.Errorf("nil proof")
	}
	if ringQ == nil {
		return ProofReport{}, fmt.Errorf("nil ring")
	}
	opts.applyDefaults()

	ncols := proof.NColsUsed
	if ncols <= 0 {
		ncols = opts.NCols
	}
	if ncols <= 0 {
		ncols = int(ringQ.N)
	}
	ell := opts.Ell
	ellPrime := opts.EllPrime
	rho := opts.Rho
	eta := opts.Eta
	theta := opts.Theta

	dQ := proof.MaskDegreeBound
	if dQ <= 0 {
		dQ = opts.DQOverride
	}
	if dQ <= 0 {
		return ProofReport{}, fmt.Errorf("missing dQ/MaskDegreeBound in proof")
	}

	witnessCols := proof.MaskRowOffset
	if witnessCols <= 0 {
		if proof.RowLayout.SigCount > 0 {
			witnessCols = proof.RowLayout.SigCount
		} else {
			witnessCols = ncols
		}
	}

	nLeaves := opts.NLeaves
	if nLeaves <= 0 {
		nLeaves = int(ringQ.N)
	}

	q := ringQ.Modulus[0]
	fieldSize := float64(q)
	if theta > 1 {
		fieldSize = math.Pow(float64(q), float64(theta))
	}
	sb := computeSoundnessBudget(opts, q, fieldSize, dQ, ncols, ell, ellPrime, eta, nLeaves, witnessCols)
	size := MeasureProofSize(proof)
	return ProofReport{
		ProofBytes: size.Total,
		ProofKB:    float64(size.Total) / 1024.0,
		Soundness:  sb,
		NCols:      ncols,
		Ell:        ell,
		EllPrime:   ellPrime,
		Rho:        rho,
		Theta:      theta,
		Eta:        eta,
		DQ:         dQ,
		Lambda:     opts.Lambda,
		Kappa:      opts.Kappa,
	}, nil
}
