package PIOP

import (
	"bytes"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// local helpers copied from run.go for eval point sampling
func sampleEvalPoints(r *ring.Ring, m int, omega []uint64, seed []byte) []byte {
	fsRNG := newFSRNG("EvalPoints", seed)
	points := make([]uint64, m)
	q := r.Modulus[0]
	for i := 0; i < m; i++ {
		points[i] = fsRNG.nextU64() % q
	}
	return encodeUint64Slice(points)
}

func decodeUint64Slice(b []byte) []uint64 {
	if len(b)%8 != 0 {
		return nil
	}
	out := make([]uint64, len(b)/8)
	for i := 0; i < len(out); i++ {
		out[i] = binary.LittleEndian.Uint64(b[8*i : 8*(i+1)])
	}
	return out
}

// evalRowsAt evaluates a slice of polys (NTT or coeff) at given points in F_q.
func evalRowsAt(r *ring.Ring, polys []*ring.Poly, points []uint64) [][]uint64 {
	if r == nil {
		return nil
	}
	out := make([][]uint64, len(polys))
	for i, p := range polys {
		if p == nil {
			continue
		}
		coeff := r.NewPoly()
		r.InvNTT(p, coeff)
		row := make([]uint64, len(points))
		for j, x := range points {
			row[j] = evalAt(r, coeff, x)
		}
		out[i] = row
	}
	return out
}

// maskFSArgs carries all inputs needed to run the masking/Merkle/FS loop.
// It mirrors the locals present in buildSimWith.
type maskFSArgs struct {
	ringQ    *ring.Ring
	omega    []uint64
	q        uint64
	rho      int
	ell      int
	ellPrime int
	opts     SimOpts
	ncols    int
	root     [16]byte

	// Small-field parameters (Theta > 1)
	smallFieldK       *kf.Field
	smallFieldChi     []uint64
	smallFieldOmegaS1 kf.Elem
	smallFieldMuInv   kf.Elem

	// Public tables / commit key
	PK  *lvcs.ProverKey
	A   [][]*ring.Poly
	b1  []*ring.Poly
	B0c []*ring.Poly
	B0m [][]*ring.Poly
	B0r [][]*ring.Poly

	// Witness
	w1        []*ring.Poly
	w2        *ring.Poly
	w3        []*ring.Poly
	origW1Len int
	mSig      int

	// Range offsets
	msgRangeOffset int
	rndRangeOffset int
	x1RangeOffset  int

	// Constraints
	FparInt     []*ring.Poly
	FparNorm    []*ring.Poly
	FaggInt     []*ring.Poly
	FaggNorm    []*ring.Poly
	FparAll     []*ring.Poly
	FaggAll     []*ring.Poly
	parallelDeg int
	aggDeg      int

	// Mask configuration
	maskDegreeTarget  int
	maskDegreeBound   int
	maskDegreeClipped bool
	maskDegreeBase    int
	independentMasks  []*ring.Poly
	independentMasksK []*KPoly

	// Rows/layout
	rows            [][]uint64
	rowInputs       []lvcs.RowInput
	witnessRowCount int
	maskRowOffset   int
	maskRowCount    int
	rowLayout       RowLayout
	oracleLayout    lvcs.OracleLayout
	decsParams      decs.Params

	labelsDigest []byte

	// Optional ncols override (head length) for theta>1
	ncolsOverride int
}

// maskFSOutput captures the artefacts produced by the masking/FS loop.
type maskFSOutput struct {
	proof *Proof

	Gamma       [][]uint64
	GammaPrime  [][]uint64
	GammaAgg    [][]uint64
	GammaPrimeK [][]KScalar
	GammaAggK   [][]KScalar

	M  []*ring.Poly
	MK []*KPoly
	Q  []*ring.Poly
	QK []*KPoly

	Rpolys          []*ring.Poly
	barSets         [][]uint64
	coeffMatrix     [][]uint64
	kPoint          [][]uint64
	evalPoints      []uint64
	smallFieldEvals []kf.Elem
	barSetsRows     int
	barSetsCols     int
	barSetsBitWidth uint8
	maskPolyCount   int

	vTargets       [][]uint64
	vTargetsPacked []byte
	tailIndices    []int

	// Openings/placeholders as needed
	openMask        *lvcs.Opening
	openTail        *lvcs.Opening
	combinedOpen    *decs.DECSOpening
	rowLayout       RowLayout
	maskRowOffset   int
	maskRowCount    int
	maskDegreeBound int
	Root            [16]byte
	evalReqs        []lvcs.EvalRequest
	Tail            []int
}

// runMaskFS executes the masking/Merkle/FS round 1 scaffold and prepares the proof header.
// It is intentionally minimal for the staged extraction.
func runMaskFS(args maskFSArgs) (maskFSOutput, error) {
	var out maskFSOutput
	if args.ringQ == nil {
		return out, fmt.Errorf("nil ring")
	}
	if args.PK == nil {
		return out, fmt.Errorf("nil prover key")
	}
	o := args.opts
	o.applyDefaults()
	ringQ := args.ringQ
	q := args.q
	if q == 0 && ringQ != nil {
		q = ringQ.Modulus[0]
	}
	// FS initialization
	baseXOF := NewShake256XOF(64)
	salt := make([]byte, 32)
	if _, err := cryptoRand.Read(salt); err != nil {
		return out, fmt.Errorf("rand salt: %w", err)
	}
	fs := NewFS(baseXOF, salt, FSParams{Lambda: o.Lambda, Kappa: o.Kappa})
	proof := &Proof{
		Root:            args.root,
		Salt:            append([]byte(nil), salt...),
		Lambda:          o.Lambda,
		Theta:           o.Theta,
		Kappa:           o.Kappa,
		RowLayout:       args.rowLayout,
		MaskRowOffset:   args.maskRowOffset,
		MaskRowCount:    args.maskRowCount,
		MaskDegreeBound: args.maskDegreeBound,
		NColsUsed:       args.ncols,
		OmegaTrunc:      append([]uint64(nil), args.omega...),
		LabelsDigest:    append([]byte(nil), args.labelsDigest...),
	}
	if o.Theta > 1 {
		proof.Chi = append([]uint64(nil), args.smallFieldChi...)
		proof.Zeta = append([]uint64(nil), args.smallFieldOmegaS1.Limb...)
	}
	// Verifier init
	vrf := lvcs.NewVerifierWithParams(ringQ, len(args.rowInputs), args.decsParams, args.ncols)
	vrf.Root = args.root
	// Round 1: Gamma
	material0 := [][]byte{args.root[:]}
	if len(args.labelsDigest) > 0 {
		material0 = append(material0, args.labelsDigest)
	}
	round1 := fsRound(fs, proof, 0, "Gamma", material0...)
	gammaRNG := round1.RNG
	Gamma := sampleFSMatrix(o.Eta, len(args.rowInputs), q, gammaRNG)
	gammaBytes := bytesFromUint64Matrix(Gamma)
	vrf.AcceptGamma(Gamma)
	Rpolys := lvcs.CommitFinish(args.PK, Gamma)
	proof.R = coeffsFromPolys(Rpolys)
	if !vrf.CommitStep2(Rpolys) {
		return out, fmt.Errorf("deg-check R failed")
	}
	// Round 2: GammaPrime/GammaAgg
	totalParallel := len(args.FparAll)
	totalAgg := len(args.FaggAll)
	transcript2 := [][]byte{args.root[:], gammaBytes, polysToBytes(Rpolys)}
	if len(args.labelsDigest) > 0 {
		transcript2 = append(transcript2, args.labelsDigest)
	}
	if proof.Theta > 1 {
		transcript2 = append(transcript2, encodeUint64Slice(proof.Chi), encodeUint64Slice(proof.Zeta))
	}
	round2 := fsRound(fs, proof, 1, "GammaPrime", transcript2...)
	seed2 := round2.Seed
	gammaPrimeRNG := round2.RNG
	gammaAggRNG := newFSRNG("GammaPrimeAgg", seed2, []byte{1})
	var GammaPrime, GammaAgg [][]uint64
	var GammaPrimeK, GammaAggK [][]KScalar
	if proof.Theta > 1 {
		GammaPrimeK = sampleFSMatrixK(args.rho, totalParallel, proof.Theta, q, gammaPrimeRNG)
		GammaAggK = sampleFSVectorK(args.rho, totalAgg, proof.Theta, q, gammaAggRNG)
		GammaPrime = kMatrixFirstLimb(GammaPrimeK)
		GammaAgg = kMatrixFirstLimb(GammaAggK)
		proof.GammaPrimeK = copyKMatrix(GammaPrimeK)
		proof.GammaAggK = copyKMatrix(GammaAggK)
	} else {
		GammaPrime = sampleFSMatrix(args.rho, totalParallel, q, gammaPrimeRNG)
		GammaAgg = sampleFSMatrix(args.rho, totalAgg, q, gammaAggRNG)
	}
	proof.GammaPrime = copyMatrix(GammaPrime)
	proof.GammaAgg = copyMatrix(GammaAgg)

	out.proof = proof
	out.Gamma = Gamma
	out.GammaPrime = GammaPrime
	out.GammaAgg = GammaAgg
	out.GammaPrimeK = GammaPrimeK
	out.GammaAggK = GammaAggK
	out.Rpolys = Rpolys
	out.maskRowOffset = args.maskRowOffset
	out.maskRowCount = args.maskRowCount
	out.maskDegreeBound = args.maskDegreeBound
	out.rowLayout = args.rowLayout

	// Masks and Q/QK generation (delegated, same logic as buildSimWith)
	if proof.Theta > 1 {
		// Small-field branch
		// Use compensated masks (PACS style) so ΣΩ holds on valid inputs.
		// Residual constraints still detect tampering (non-zero Q/QK evals).
		sumFpar := sumPolyList(ringQ, args.FparAll, args.omega)
		sumFagg := sumPolyList(ringQ, args.FaggAll, args.omega)
		MK := BuildMaskPolynomialsK(ringQ, args.smallFieldK, args.rho, args.maskDegreeTarget, args.omega, GammaPrimeK, GammaAggK, sumFpar, sumFagg)
		M := make([]*ring.Poly, args.rho)
		for i := range MK {
			poly := ringQ.NewPoly()
			for idx := range poly.Coeffs[0] {
				if idx < len(MK[i].Limbs[0]) {
					poly.Coeffs[0][idx] = MK[i].Limbs[0][idx] % q
				}
			}
			ringQ.NTT(poly, poly)
			M[i] = poly
		}
		out.M = M
		out.MK = MK
		proof.MKData = snapshotKPolys(MK)
		// Q and QK
		qLayout := BuildQLayout{
			WitnessPolys: args.w1[:args.origW1Len],
			MaskPolys:    M,
		}
		out.Q = BuildQ(ringQ, qLayout, args.FparInt, args.FparNorm, args.FaggInt, args.FaggNorm, GammaPrime, GammaAgg)
		proof.QNTT = polysToNTTMatrix(out.Q)
		out.QK = BuildQK(ringQ, args.smallFieldK, MK, args.FparAll, args.FaggAll, GammaPrimeK, GammaAggK)
		proof.QKData = snapshotKPolys(out.QK)
		// Sanity check: QK should equal MK + Γ'·Fpar + γ'·Fagg coefficient-wise.
		checkMismatch := false
		for i := range out.QK {
			if checkMismatch {
				break
			}
			kcoeff := kpolyToCoeffPolys(ringQ, out.QK[i])
			for idx := 0; idx < len(kcoeff[0].Coeffs[0]); idx++ {
				lhsLimbs := make([]uint64, len(kcoeff))
				rhsLimbs := make([]uint64, len(kcoeff))
				for j := range kcoeff {
					lhsLimbs[j] = kcoeff[j].Coeffs[0][idx] % q
					if i < len(MK) && MK[i] != nil && idx < len(MK[i].Limbs[j]) {
						rhsLimbs[j] = MK[i].Limbs[j][idx] % q
					}
				}
				rhs := args.smallFieldK.Phi(rhsLimbs)
				if i < len(GammaPrimeK) {
					row := GammaPrimeK[i]
					for j := range args.FparAll {
						if j >= len(row) || args.FparAll[j] == nil {
							continue
						}
						tmp := ringQ.NewPoly()
						ringQ.InvNTT(args.FparAll[j], tmp)
						if idx < len(tmp.Coeffs[0]) {
							rhs = args.smallFieldK.Add(rhs, args.smallFieldK.Mul(args.smallFieldK.Phi(row[j]), args.smallFieldK.EmbedF(tmp.Coeffs[0][idx]%q)))
						}
					}
				}
				if i < len(GammaAggK) {
					row := GammaAggK[i]
					for j := range args.FaggAll {
						if j >= len(row) || args.FaggAll[j] == nil {
							continue
						}
						tmp := ringQ.NewPoly()
						ringQ.InvNTT(args.FaggAll[j], tmp)
						if idx < len(tmp.Coeffs[0]) {
							rhs = args.smallFieldK.Add(rhs, args.smallFieldK.Mul(args.smallFieldK.Phi(row[j]), args.smallFieldK.EmbedF(tmp.Coeffs[0][idx]%q)))
						}
					}
				}
				lhs := args.smallFieldK.Phi(lhsLimbs)
				if !elemEqual(args.smallFieldK, lhs, rhs) {
					fmt.Printf("[debug runMaskFS] QK mismatch i=%d idx=%d lhs=%v rhs=%v\n", i, idx, lhs, rhs)
					checkMismatch = true
					break
				}
			}
		}
		// Mask degree check
		maskDegreeMax := -1
		for _, kp := range MK {
			if kp != nil && kp.Degree > maskDegreeMax {
				maskDegreeMax = kp.Degree
			}
		}
		if maskDegreeMax > args.maskDegreeBound {
			return out, fmt.Errorf("mask degree %d exceeds bound %d", maskDegreeMax, args.maskDegreeBound)
		}

	}

	// Round 3 eval points (no proof population; outputs for caller)
	ellPrime := args.ellPrime
	if ellPrime <= 0 {
		ellPrime = 1
	}
	// If caller provided an override for ncols (head length), enforce it for omega/rows/degree expectations.
	if args.ncolsOverride > 0 && args.ncolsOverride < len(args.omega) {
		args.omega = append([]uint64(nil), args.omega[:args.ncolsOverride]...)
	}
	gammaBytes = bytesFromUint64Matrix(Gamma)
	gammaPrimeBytes := bytesFromUint64Matrix(GammaPrime)
	gammaAggBytes := bytesFromUint64Matrix(GammaAgg)
	if proof.Theta > 1 {
		gammaPrimeBytes = bytesFromKScalarMat(GammaPrimeK)
		gammaAggBytes = bytesFromKScalarMat(GammaAggK)
	}
	round3Material := [][]byte{args.root[:], gammaBytes, gammaPrimeBytes, gammaAggBytes, polysToBytes(out.Q)}
	if len(args.labelsDigest) > 0 {
		round3Material = append(round3Material, args.labelsDigest)
	}
	round3 := fsRound(fs, proof, 2, func() string {
		if proof.Theta > 1 {
			return "EvalKPoint"
		}
		return "EvalPoints"
	}(), round3Material...)
	seed3 := round3.Seed
	var coeffMatrix [][]uint64
	var kPointLimbs [][]uint64
	var barSets [][]uint64
	var vTargets [][]uint64
	if proof.Theta > 1 {
		kPointRNG := round3.RNG
		coeffMatrix = make([][]uint64, 0, ellPrime*proof.Theta)
		kPointLimbs = make([][]uint64, 0, ellPrime)
		barSets = [][]uint64{}
		evalReqs := make([]lvcs.EvalRequest, 0, ellPrime*proof.Theta)
		smallFieldEvals := make([]kf.Elem, 0, ellPrime)
		for len(smallFieldEvals) < ellPrime {
			limbs := make([]uint64, proof.Theta)
			for i := 0; i < proof.Theta; i++ {
				limbs[i] = kPointRNG.nextU64() % q
			}
			zeroTail := true
			for i := 1; i < len(limbs); i++ {
				if limbs[i]%q != 0 {
					zeroTail = false
					break
				}
			}
			candidate := args.smallFieldK.Phi(limbs)
			conflict := false
			for _, w := range args.omega {
				if elemEqual(args.smallFieldK, candidate, args.smallFieldK.EmbedF(w%q)) {
					conflict = true
					break
				}
			}
			if !conflict {
				for _, prev := range smallFieldEvals {
					if elemEqual(args.smallFieldK, candidate, prev) {
						conflict = true
						break
					}
				}
			}
			if zeroTail || conflict {
				continue
			}
			coeffBlock := buildKPointCoeffMatrix(ringQ, args.smallFieldK, args.omega, args.rows, candidate, args.smallFieldMuInv, args.maskRowOffset, args.maskRowCount)
			coeffMatrix = append(coeffMatrix, coeffBlock...)
			for i := range coeffBlock {
				rowCopy := append([]uint64(nil), coeffBlock[i]...)
				evalReqs = append(evalReqs, lvcs.EvalRequest{
					Coeffs: rowCopy,
					KPoint: append([]uint64(nil), candidate.Limb...),
				})
			}
			smallFieldEvals = append(smallFieldEvals, candidate)
			kPointLimbs = append(kPointLimbs, append([]uint64(nil), candidate.Limb...))
		}
		if len(evalReqs) > 0 {
			barSets = lvcs.EvalInitMany(ringQ, args.PK, evalReqs)
		}
		vTargets := computeVTargets(q, args.rows, coeffMatrix)
		proof.setBarSets(barSets)
		proof.setVTargets(vTargets)
		proof.CoeffMatrix = copyMatrix(coeffMatrix)
		proof.KPoint = copyMatrix(kPointLimbs)
		out.barSets = barSets
		out.coeffMatrix = coeffMatrix
		out.kPoint = kPointLimbs
		out.smallFieldEvals = smallFieldEvals
		out.vTargets = vTargets
		out.vTargetsPacked = append([]byte(nil), proof.VTargetsBits...)
		out.barSetsRows = proof.BarSetsRows
		out.barSetsCols = proof.BarSetsCols
		out.barSetsBitWidth = proof.BarSetsBitWidth
		out.evalReqs = evalReqs
	} else {
		evalPointBytes := sampleEvalPoints(ringQ, ellPrime, args.omega, seed3)
		out.evalPoints = decodeUint64Slice(evalPointBytes)
	}

	// Round 4: tail sampling and openings (use same FS state) – only for θ>1
	if proof.Theta <= 1 {
		return out, fmt.Errorf("runMaskFS currently supports theta>1 only")
	}
	tailStart := args.ncols + args.ell
	tailLen := int(ringQ.N) - tailStart
	if tailLen < args.ell {
		return out, fmt.Errorf("insufficient tail: tailLen=%d ell=%d", tailLen, args.ell)
	}
	transcript4 := [][]byte{
		args.root[:],
		gammaBytes,
		bytesFromKScalarMat(GammaPrimeK),
		bytesFromKScalarMat(GammaAggK),
		bytesFromUint64Matrix(kPointLimbs),
		bytesFromUint64Matrix(coeffMatrix),
		bytesFromUint64Matrix(barSets),
		bytesFromUint64Matrix(vTargets),
	}
	proof.TailTranscript = flattenBytes(transcript4)
	round4 := fsRound(fs, proof, 3, "TailPoints", transcript4...)
	tailRNG := round4.RNG
	input := make([]byte, len(proof.Salt))
	copy(input, proof.Salt)
	for _, m := range transcript4 {
		input = append(input, m...)
	}
	input = append(input, u64le(proof.Ctr[3])...)
	expected := fs.xof.Expand(fs.labels[3], input)
	if !bytes.Equal(expected, proof.Digests[3]) {
		fmt.Printf("[debug fs internal] round3 digest mismatch len(transcript4)=%d ctr=%d\n", len(transcript4), proof.Ctr[3])
	}
	E := sampleDistinctIndices(tailStart, tailLen, args.ell, tailRNG)
	proof.Tail = append([]int(nil), E...)

	maskIdx := make([]int, args.ell)
	for i := 0; i < args.ell; i++ {
		maskIdx[i] = args.ncols + i
	}
	openMask := lvcs.EvalFinish(args.PK, maskIdx)
	openTail := lvcs.EvalFinish(args.PK, E)
	combinedOpen := combineOpenings(openMask.DECSOpen, openTail.DECSOpen)
	proof.RowOpening = cloneDECSOpening(combinedOpen)
	proof.RowOpening.R = len(args.rowInputs)
	proof.RowOpening.Eta = args.decsParams.Eta
	decs.PackOpening(proof.RowOpening)

	maskEval := evalPolySetAtIndices(ringQ, out.M, E)
	maskOpen := makeMaskTailOpening(E, maskEval)
	proof.MOpening = cloneDECSOpening(maskOpen)

	out.openMask = openMask
	out.openTail = openTail
	out.combinedOpen = combinedOpen
	out.tailIndices = append([]int(nil), E...)
	out.maskDegreeBound = args.maskDegreeBound
	out.maskRowOffset = args.maskRowOffset
	out.maskRowCount = args.maskRowCount
	out.maskPolyCount = len(out.M)

	return out, nil
}
