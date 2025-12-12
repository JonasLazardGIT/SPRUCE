package PIOP

import (
	"fmt"
	"time"

	cryptoRand "crypto/rand"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	prof "vSIS-Signature/prof"

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
}

// RunMaskingFS is a placeholder for a reusable masking/Merkle/FS driver.
// It mirrors the masking/FS portion of buildSimWith but takes explicit inputs.
func RunMaskingFS(in MaskingFSInput) (*Proof, error) {
	defer prof.Track(time.Now(), "RunMaskingFS")
	ringQ := in.RingQ
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if in.PK == nil {
		return nil, fmt.Errorf("nil prover key")
	}
	o := in.Opts
	o.applyDefaults()
	q := ringQ.Modulus[0]
	rho := o.Rho
	if rho <= 0 {
		rho = 1
	}
	// FS initialization
	baseXOF := NewShake256XOF(64)
	salt := make([]byte, 32)
	if _, err := cryptoRand.Read(salt); err != nil {
		return nil, fmt.Errorf("rand salt: %w", err)
	}
	fs := NewFS(baseXOF, salt, FSParams{Lambda: o.Lambda, Kappa: o.Kappa})
	proof := &Proof{
		Root:            in.Root,
		Salt:            append([]byte(nil), salt...),
		Lambda:          o.Lambda,
		Theta:           o.Theta,
		Kappa:           o.Kappa,
		RowLayout:       in.RowLayout,
		MaskRowOffset:   in.MaskRowOffset,
		MaskRowCount:    in.MaskRowCount,
		MaskDegreeBound: in.MaskDegreeBound,
	}
	// Round 1: Gamma
	material0 := [][]byte{in.Root[:]}
	if len(in.LabelsDigest) > 0 {
		material0 = append(material0, in.LabelsDigest)
		proof.LabelsDigest = append([]byte(nil), in.LabelsDigest...)
	}
	round1 := fsRound(fs, proof, 0, "Gamma", material0...)
	gammaRNG := round1.RNG
	Gamma := sampleFSMatrix(o.Eta, in.MaskRowOffset+in.MaskRowCount, q, gammaRNG)
	gammaBytes := bytesFromUint64Matrix(Gamma)
	vrf := lvcs.NewVerifierWithParams(ringQ, in.MaskRowOffset+in.MaskRowCount, in.PK.Params, in.NCols)
	vrf.Root = in.Root
	Rpolys := lvcs.CommitFinish(in.PK, Gamma)
	proof.R = coeffsFromPolysTrunc(Rpolys, in.PK.Params.Degree+1)
	if !vrf.CommitStep2(Rpolys) {
		return nil, fmt.Errorf("deg-check R failed")
	}
	// Assemble Fpar/Fagg
	FparAll := append([]*ring.Poly{}, in.FparInt...)
	FparAll = append(FparAll, in.FparNorm...)
	FaggAll := append([]*ring.Poly{}, in.FaggInt...)
	FaggAll = append(FaggAll, in.FaggNorm...)
	totalParallel := len(FparAll)
	totalAgg := len(FaggAll)
	proof.FparNTT = polysToNTTMatrix(FparAll)
	proof.FaggNTT = polysToNTTMatrix(FaggAll)
	// Round 2: GammaPrime/GammaAgg
	transcript2 := [][]byte{in.Root[:], gammaBytes, polysToBytes(Rpolys)}
	if len(in.LabelsDigest) > 0 {
		transcript2 = append(transcript2, in.LabelsDigest)
	}
	if o.Theta > 1 {
		transcript2 = append(transcript2, encodeUint64Slice(proof.Chi), encodeUint64Slice(proof.Zeta))
	}
	round2 := fsRound(fs, proof, 1, "GammaPrime", transcript2...)
	seed2 := round2.Seed
	gammaPrimeRNG := round2.RNG
	gammaAggRNG := newFSRNG("GammaPrimeAgg", seed2, []byte{1})
	var (
		GammaPrime [][]uint64
		GammaAgg   [][]uint64
	)
	GammaPrime = sampleFSMatrix(rho, totalParallel, q, gammaPrimeRNG)
	GammaAgg = sampleFSMatrix(rho, totalAgg, q, gammaAggRNG)
	proof.GammaPrime = copyMatrix(GammaPrime)
	proof.GammaAgg = copyMatrix(GammaAgg)
	// Masks
	sumFpar := sumPolyList(ringQ, FparAll, in.Omega)
	sumFagg := sumPolyList(ringQ, FaggAll, in.Omega)
	M := BuildMaskPolynomials(ringQ, rho, in.MaskDegreeTarget, in.Omega, GammaPrime, GammaAgg, sumFpar, sumFagg)
	maskDegreeMax := -1
	for _, poly := range M {
		deg := maxPolyDegree(ringQ, poly)
		if deg > maskDegreeMax {
			maskDegreeMax = deg
		}
	}
	if maskDegreeMax > in.MaskDegreeBound {
		return nil, fmt.Errorf("mask degree %d exceeds bound %d", maskDegreeMax, in.MaskDegreeBound)
	}
	layoutWitness := clonePolys(in.WitnessPolys)
	layoutMasks := clonePolys(M)
	qLayout := BuildQLayout{
		WitnessPolys: layoutWitness,
		MaskPolys:    layoutMasks,
	}
	Q := BuildQ(ringQ, qLayout, in.FparInt, in.FparNorm, in.FaggInt, in.FaggNorm, GammaPrime, GammaAgg)
	proof.QNTT = polysToNTTMatrix(Q)
	transcript3 := [][]byte{
		in.Root[:],
		gammaBytes,
		bytesFromUint64Matrix(GammaPrime),
		bytesFromUint64Matrix(GammaAgg),
		polysToBytes(Q),
	}
	if len(in.LabelsDigest) > 0 {
		transcript3 = append(transcript3, in.LabelsDigest)
	}
	round3 := fsRound(fs, proof, 2, "EvalPoints", transcript3...)
	seed3 := round3.Seed
	proof.Gamma = copyMatrix(Gamma)
	proof.GammaK = nil
	proof.GammaPrimeK = nil
	proof.GammaAggK = nil
	proof.MKData = nil
	proof.QKData = nil
	// Eval points (reuse existing helper)
	evalPoints := sampleFSMatrix(o.Theta, len(in.Omega), q, newFSRNG("EvalPoints", seed3))
	proof.Zeta = evalPoints[0]
	// TODO: fill the remaining proof fields as needed by VerifyNIZK or a new verifier.
	return proof, nil
}
