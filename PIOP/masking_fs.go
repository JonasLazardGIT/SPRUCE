package PIOP

import (
	"fmt"
	"time"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	prof "vSIS-Signature/prof"

	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// MaskingFSInput bundles the data needed to run the masking/Merkle/FS phase
// independently of the PACS-specific witness construction. This is a scaffold
// toward a generic builder; currently unused by the PACS path.
type MaskingFSInput struct {
	RingQ            *ring.Ring
	Opts             SimOpts
	Omega            []uint64
	Root             [16]byte
	PK               *lvcs.ProverKey
	OracleLayout     lvcs.OracleLayout
	RowLayout        RowLayout
	FparInt          []*ring.Poly
	FparNorm         []*ring.Poly
	FaggInt          []*ring.Poly
	FaggNorm         []*ring.Poly
	RowInputs        []lvcs.RowInput
	WitnessPolys     []*ring.Poly // layout base (w1)
	MaskPolys        []*ring.Poly // independent masks (optional; can be empty)
	MaskRowOffset    int
	MaskRowCount     int
	MaskDegreeTarget int
	MaskDegreeBound  int
	Personalization  string // FS personalization label (e.g., FSModeCredential)
	NCols            int    // number of columns in rows (for verifier)
	DecsParams       decs.Params
	LabelsDigest     []byte // hash of public labels included in FS binding
	// Small-field (theta>1) parameters
	SmallFieldChi     []uint64
	SmallFieldOmegaS1 []uint64
	SmallFieldMuInv   []uint64
	SmallFieldK       *kf.Field
	SmallFieldRows    [][]uint64 // coeff heads for theta>1 packing
}

// RunMaskingFS is a placeholder for a reusable masking/Merkle/FS driver.
// It mirrors the masking/FS portion of buildSimWith but takes explicit inputs.
func RunMaskingFS(in MaskingFSInput) (*Proof, error) {
	defer prof.Track(time.Now(), "RunMaskingFS")
	o := in.Opts
	o.applyDefaults()
	args := maskFSArgs{
		ringQ:            in.RingQ,
		omega:            in.Omega,
		q:                in.RingQ.Modulus[0],
		rho:              o.Rho,
		ell:              o.Ell,
		ellPrime:         o.EllPrime,
		opts:             o,
		ncols:            in.NCols,
		root:             in.Root,
		PK:               in.PK,
		w1:               in.WitnessPolys,
		origW1Len:        len(in.WitnessPolys),
		FparInt:          in.FparInt,
		FparNorm:         in.FparNorm,
		FaggInt:          in.FaggInt,
		FaggNorm:         in.FaggNorm,
		FparAll:          append(append([]*ring.Poly{}, in.FparInt...), in.FparNorm...),
		FaggAll:          append(append([]*ring.Poly{}, in.FaggInt...), in.FaggNorm...),
		maskDegreeTarget: in.MaskDegreeTarget,
		maskDegreeBound:  in.MaskDegreeBound,
		rowInputs:        in.RowInputs,
		rowLayout:        in.RowLayout,
		oracleLayout:     in.OracleLayout,
		maskRowOffset:    in.MaskRowOffset,
		maskRowCount:     in.MaskRowCount,
		decsParams:       in.DecsParams,
		ncolsOverride:    in.NCols,
		labelsDigest:     append([]byte(nil), in.LabelsDigest...),
	}
	if o.Theta > 1 {
		args.smallFieldChi = append([]uint64(nil), in.SmallFieldChi...)
		args.smallFieldK = in.SmallFieldK
		args.smallFieldOmegaS1 = kf.Elem{Limb: append([]uint64(nil), in.SmallFieldOmegaS1...)}
		args.smallFieldMuInv = kf.Elem{Limb: append([]uint64(nil), in.SmallFieldMuInv...)}
		// Truncate rows/omega to a consistent head length (use opts.NCols if set).
		headLen := o.NCols
		if headLen <= 0 {
			headLen = len(in.Omega)
		}
		// Use the smallest head length across rows and omega.
		if len(in.SmallFieldRows) > 0 && len(in.SmallFieldRows[0]) < headLen {
			headLen = len(in.SmallFieldRows[0])
		}
		if headLen <= 0 {
			return nil, fmt.Errorf("invalid head length for theta>1")
		}
		args.rows = make([][]uint64, len(in.SmallFieldRows))
		for i, row := range in.SmallFieldRows {
			if len(row) > headLen {
				row = row[:headLen]
			} else if len(row) < headLen {
				tmp := make([]uint64, headLen)
				copy(tmp, row)
				row = tmp
			}
			args.rows[i] = row
		}
		if len(in.Omega) > headLen {
			args.omega = append([]uint64(nil), in.Omega[:headLen]...)
		} else {
			args.omega = in.Omega
		}
	} else {
		args.rows = evalRowsAt(in.RingQ, in.WitnessPolys, in.Omega)
	}
	out, err := runMaskFS(args)
	if err != nil {
		return nil, err
	}
	return out.proof, nil
}
