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
// independently of the PACS-specific witness construction. It is used by the
// credential builders and by the generic replay path.
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
		if len(in.SmallFieldRows) == 0 {
			return nil, fmt.Errorf("missing small-field rows for theta>1")
		}
		headLen := len(in.SmallFieldRows[0])
		if headLen == 0 {
			return nil, fmt.Errorf("empty small-field row heads")
		}
		if len(in.Omega) != headLen {
			return nil, fmt.Errorf("omega length %d != small-field head length %d", len(in.Omega), headLen)
		}
		args.rows = make([][]uint64, len(in.SmallFieldRows))
		for i := range in.SmallFieldRows {
			args.rows[i] = append([]uint64(nil), in.SmallFieldRows[i]...)
		}
		args.omega = in.Omega
	} else {
		args.rows = evalRowsAt(in.RingQ, in.WitnessPolys, in.Omega)
	}
	out, err := runMaskFS(args)
	if err != nil {
		return nil, err
	}
	return out.proof, nil
}
