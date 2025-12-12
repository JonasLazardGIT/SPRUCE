package PIOP

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"
	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// VerifyNIZK replays the Fiat–Shamir transcript and performs the verifier-side
// checks that do not require access to the witness polynomials. Implemented
// checks currently cover FS rounds 0–3, LVCS EvalStep2, DECS mask verification,
// Eq.(4) (via tail openings), and the ΣΩ sum constraints.
func VerifyNIZK(proof *Proof) (okLin, okEq4, okSum bool, err error) {
	if proof == nil {
		return false, false, false, errors.New("VerifyNIZK: nil proof")
	}
	defer func() {
		if proof != nil {
			decs.PackOpening(proof.RowOpening)
			decs.PackOpening(proof.MOpening)
		}
	}()
	vTargets := proof.VTargetsMatrix()
	if len(vTargets) == 0 || len(vTargets[0]) == 0 {
		return false, false, false, errors.New("VerifyNIZK: missing VTargets")
	}
	barSets := proof.BarSetsMatrix()
	if len(barSets) == 0 || len(barSets[0]) == 0 {
		return false, false, false, errors.New("VerifyNIZK: missing BarSets")
	}
	if proof.RowOpening == nil {
		return false, false, false, errors.New("VerifyNIZK: missing row opening")
	}
	if len(proof.Digests[0]) == 0 || len(proof.Digests[1]) == 0 || len(proof.Digests[3]) == 0 {
		return false, false, false, errors.New("VerifyNIZK: incomplete transcript digests")
	}

	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: load parameters: %w", err)
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: ring.NewRing: %w", err)
	}
	q := ringQ.Modulus[0]
	ncols := len(vTargets[0])

	// Derive Ω as in the prover.
	px := ringQ.NewPoly()
	if len(px.Coeffs) == 0 || len(px.Coeffs[0]) < 2 {
		return false, false, false, errors.New("VerifyNIZK: unexpected ring dimension")
	}
	px.Coeffs[0][1] = 1
	pts := ringQ.NewPoly()
	ringQ.NTT(px, pts)
	if len(pts.Coeffs[0]) < ncols {
		return false, false, false, errors.New("VerifyNIZK: Ω exceeds ring dimension")
	}
	omega := append([]uint64(nil), pts.Coeffs[0][:ncols]...)
	if err := checkOmega(omega, q); err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: invalid Ω: %w", err)
	}

	ell := len(proof.Tail)
	rRows := proof.RowOpening.R
	eta := proof.RowOpening.Eta

	// ----------------------------------------------------------------- FS round 0
	lambda := proof.Lambda
	if lambda <= 0 {
		lambda = 256
	}
	fs := NewFS(NewShake256XOF(64), proof.Salt, FSParams{Lambda: lambda, Kappa: proof.Kappa})
	rootBytes := append([]byte(nil), proof.Root[:]...)
	material0 := [][]byte{rootBytes}
	if len(proof.LabelsDigest) > 0 {
		material0 = append(material0, proof.LabelsDigest)
	}
	h1, err := verifyRoundDigest(fs, 0, proof.Ctr[0], material0, proof.Digests[0], proof.Kappa[0])
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: FS round 0: %w", err)
	}
	seed1 := h1
	gammaRNG := newFSRNG("Gamma", seed1)
	Gamma := sampleFSMatrix(eta, rRows, q, gammaRNG)

	// LVCS degree check binds Γ to Root.
	if len(proof.R) != eta {
		return false, false, false, fmt.Errorf("VerifyNIZK: expected %d R-polynomials, got %d", eta, len(proof.R))
	}
	Rpolys := coeffsToPolys(ringQ, proof.R)

	degBound := ncols + ell - 1
	if degBound >= int(ringQ.N) {
		degBound = int(ringQ.N) - 1
	}
	nonceBytes := 16
	if proof.RowOpening.NonceBytes > 0 {
		nonceBytes = proof.RowOpening.NonceBytes
	} else if len(proof.RowOpening.Nonces) > 0 && len(proof.RowOpening.Nonces[0]) > 0 {
		nonceBytes = len(proof.RowOpening.Nonces[0])
	}
	lvcsParams := decs.Params{Degree: degBound, Eta: eta, NonceBytes: nonceBytes}
	vrf := lvcs.NewVerifierWithParams(ringQ, rRows, lvcsParams, ncols)
	vrf.Root = proof.Root
	vrf.AcceptGamma(Gamma)
	if !vrf.CommitStep2(Rpolys) {
		return false, false, false, errors.New("VerifyNIZK: LVCS CommitStep2 rejected R polynomials")
	}

	// ----------------------------------------------------------------- FS round 1
	gammaBytes := bytesFromUint64Matrix(Gamma)
	rBytes := polysToBytes(Rpolys)
	transcript2 := [][]byte{rootBytes, gammaBytes, rBytes}
	if len(proof.LabelsDigest) > 0 {
		transcript2 = append(transcript2, proof.LabelsDigest)
	}
	if proof.Theta > 1 {
		if len(proof.Chi) == 0 || len(proof.Zeta) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing Chi/Zeta for θ>1")
		}
		transcript2 = append(transcript2, encodeUint64Slice(proof.Chi), encodeUint64Slice(proof.Zeta))
	}
	h2, err := verifyRoundDigest(fs, 1, proof.Ctr[1], transcript2, proof.Digests[1], proof.Kappa[1])
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: FS round 1: %w", err)
	}
	seed2 := h2

	var (
		gammaPrimeBytes []byte
		gammaAggBytes   []byte
	)

	if proof.Theta > 1 {
		if len(proof.GammaPrimeK) == 0 || len(proof.GammaAggK) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing GammaPrimeK/GammaAggK for θ>1")
		}
		rows := len(proof.GammaPrimeK)
		cols := len(proof.GammaPrimeK[0])
		fsGammaPrime := sampleFSMatrixK(rows, cols, proof.Theta, q, newFSRNG("GammaPrime", seed2))
		if !kMatrixEqual(fsGammaPrime, proof.GammaPrimeK) {
			return false, false, false, errors.New("VerifyNIZK: GammaPrimeK mismatch")
		}
		fsGammaAgg := sampleFSVectorK(len(proof.GammaAggK), len(proof.GammaAggK[0]), proof.Theta, q, newFSRNG("GammaPrimeAgg", seed2, []byte{1}))
		if !kMatrixEqual(fsGammaAgg, proof.GammaAggK) {
			return false, false, false, errors.New("VerifyNIZK: GammaAggK mismatch")
		}
		gammaPrimeBytes = bytesFromKScalarMat(fsGammaPrime)
		gammaAggBytes = bytesFromKScalarMat(fsGammaAgg)
	} else {
		if len(proof.GammaPrime) == 0 || len(proof.GammaPrime[0]) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing GammaPrime")
		}
		if len(proof.GammaAgg) == 0 || len(proof.GammaAgg[0]) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing GammaAgg")
		}
		rows := len(proof.GammaPrime)
		cols := len(proof.GammaPrime[0])
		fsGammaPrime := sampleFSMatrix(rows, cols, q, newFSRNG("GammaPrime", seed2))
		if !matrixEqual(fsGammaPrime, proof.GammaPrime) {
			return false, false, false, errors.New("VerifyNIZK: GammaPrime mismatch")
		}
		rowsAgg := len(proof.GammaAgg)
		colsAgg := len(proof.GammaAgg[0])
		fsGammaAgg := sampleFSMatrix(rowsAgg, colsAgg, q, newFSRNG("GammaPrimeAgg", seed2, []byte{1}))
		if !matrixEqual(fsGammaAgg, proof.GammaAgg) {
			return false, false, false, errors.New("VerifyNIZK: GammaAgg mismatch")
		}
		gammaPrimeBytes = bytesFromUint64Matrix(fsGammaPrime)
		gammaAggBytes = bytesFromUint64Matrix(fsGammaAgg)
	}

	if len(proof.FparNTT) == 0 || len(proof.FaggNTT) == 0 || len(proof.QNTT) == 0 {
		return false, false, false, errors.New("VerifyNIZK: missing Eq.(4) polynomial data")
	}
	FparPolys := nttMatrixToPolys(ringQ, proof.FparNTT)
	FaggPolys := nttMatrixToPolys(ringQ, proof.FaggNTT)
	QPolys := nttMatrixToPolys(ringQ, proof.QNTT)

	var (
		coeffMatrix [][]uint64
		transcript4 [][]byte
	)

	transcript3 := [][]byte{
		rootBytes,
		gammaBytes,
		gammaPrimeBytes,
		gammaAggBytes,
		polysToBytes(QPolys),
	}
	if len(proof.LabelsDigest) > 0 {
		transcript3 = append(transcript3, proof.LabelsDigest)
	}
	h3, err := verifyRoundDigest(fs, 2, proof.Ctr[2], transcript3, proof.Digests[2], proof.Kappa[2])
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: FS round 2: %w", err)
	}
	seed3 := h3

	if proof.Theta > 1 {
		if len(proof.CoeffMatrix) == 0 || len(proof.KPoint) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing coefficient matrix or K points for θ>1")
		}
		coeffMatrix = copyMatrix(proof.CoeffMatrix)
		transcript4 = [][]byte{
			rootBytes,
			gammaBytes,
			gammaPrimeBytes,
			bytesFromKScalarMat(proof.GammaAggK),
			bytesFromUint64Matrix(proof.KPoint),
			bytesFromUint64Matrix(coeffMatrix),
			bytesFromUint64Matrix(barSets),
			bytesFromUint64Matrix(vTargets),
		}
	} else {
		ellPrime := len(barSets)
		if ellPrime == 0 {
			return false, false, false, errors.New("VerifyNIZK: empty bar sets")
		}
		points := sampleDistinctFieldElemsAvoid(ellPrime, q, newFSRNG("EvalPoints", seed3), omega)
		coeffMatrix = make([][]uint64, ellPrime)
		coeffRNG := newFSRNG("EvalCoeffs", seed3, []byte{1})
		for i := 0; i < ellPrime; i++ {
			row := make([]uint64, rRows)
			for j := 0; j < rRows; j++ {
				row[j] = coeffRNG.nextU64() % q
			}
			coeffMatrix[i] = row
		}
		if len(proof.CoeffMatrix) > 0 && !matrixEqual(coeffMatrix, proof.CoeffMatrix) {
			return false, false, false, errors.New("VerifyNIZK: coefficient matrix mismatch")
		}
		transcript4 = [][]byte{
			rootBytes,
			gammaBytes,
			gammaPrimeBytes,
			encodeUint64Slice(points),
			bytesFromUint64Matrix(coeffMatrix),
			bytesFromUint64Matrix(barSets),
			bytesFromUint64Matrix(vTargets),
		}
	}
	transcriptForRound3 := transcript4
	if len(proof.TailTranscript) > 0 {
		transcriptForRound3 = [][]byte{proof.TailTranscript}
	}
	h4, err := verifyRoundDigest(fs, 3, proof.Ctr[3], transcriptForRound3, proof.Digests[3], proof.Kappa[3])
	if err != nil {
		if proof.Theta > 1 {
			material := append([]byte{}, fs.salt...)
			for _, m := range transcriptForRound3 {
				material = append(material, m...)
			}
			material = append(material, u64le(proof.Ctr[3])...)
			exp := fs.xof.Expand(fs.labels[3], material)
			fmt.Printf("[debug verify] round3 exp digest (len=%d) ctr=%d match=%v\n", len(exp), proof.Ctr[3], bytes.Equal(exp, proof.Digests[3]))
			if len(exp) >= 8 && len(proof.Digests[3]) >= 8 {
				fmt.Printf("[debug verify] digests: expected(prefix)=%x proof(prefix)=%x material_len=%d kappa=%d\n", exp[:8], proof.Digests[3][:8], len(material), proof.Kappa[3])
			}
		}
		return false, false, false, fmt.Errorf("VerifyNIZK: FS round 3: %w", err)
	}
	seed4 := h4
	tailStart := ncols + ell
	tailLen := int(ringQ.N) - tailStart
	if tailLen < ell {
		return false, false, false, errors.New("VerifyNIZK: insufficient tail region")
	}
	derivedTail := sampleDistinctIndices(tailStart, tailLen, ell, newFSRNG("TailPoints", seed4))
	if !equalIntSlices(derivedTail, proof.Tail) {
		return false, false, false, errors.New("VerifyNIZK: tail indices mismatch")
	}

	// ----------------------------------------------------------------- LVCS EvalStep2
	maskIdx := make([]int, ell)
	for i := 0; i < ell; i++ {
		maskIdx[i] = ncols + i
	}
	etaMerged := proof.RowOpening.Eta
	if etaMerged <= 0 {
		etaMerged = len(Gamma)
	}
	okLin, err = verifyLVCSConstraints(ringQ, lvcsParams, proof, Gamma, Rpolys, coeffMatrix, barSets, vTargets, maskIdx, proof.Tail, ncols)
	if err != nil {
		return false, false, false, fmt.Errorf("VerifyNIZK: %w", err)
	}

	// ----------------------------------------------------------------- DECS mask verification
	unpackedMask := expandPackedOpening(proof.MOpening)
	if unpackedMask == nil || len(unpackedMask.Pvals) == 0 && len(unpackedMask.PvalsBits) == 0 {
		return false, false, false, errors.New("VerifyNIZK: missing merged mask opening data")
	}

	var smallFieldK *kf.Field
	var QK []*KPoly
	var MK []*KPoly
	if proof.Theta > 1 {
		if len(proof.Chi) == 0 {
			return false, false, false, errors.New("VerifyNIZK: missing Chi for θ>1")
		}
		field, fieldErr := kf.New(q, proof.Theta, proof.Chi)
		if fieldErr != nil {
			return false, false, false, fmt.Errorf("VerifyNIZK: kfield.New: %w", fieldErr)
		}
		smallFieldK = field
		QK = restoreKPolys(proof.QKData)
		MK = restoreKPolys(proof.MKData)
	}
	if !checkEq4OnTailOpen(ringQ, smallFieldK, proof.Theta, proof.Tail, QPolys, QK, MK, FparPolys, FaggPolys, proof.GammaPrime, proof.GammaAgg, proof.GammaPrimeK, proof.GammaAggK, proof.MOpening) {
		return okLin, false, false, errors.New("VerifyNIZK: Eq.(4) tail check failed")
	}
	okEq4 = true

	// ----------------------------------------------------------------- ΣΩ check (Eq.7)
	okSum = VerifyQ(ringQ, QPolys, omega)

	return okLin, okEq4, okSum, nil
}

func verifyRoundDigest(fs *FS, round int, ctr uint64, material [][]byte, expected []byte, kappa int) ([]byte, error) {
	if fs == nil {
		return nil, errors.New("nil FS state")
	}
	if round < 0 || round >= len(fs.labels) {
		return nil, fmt.Errorf("invalid FS round %d", round)
	}
	input := append([]byte(nil), fs.salt...)
	for _, m := range material {
		input = append(input, m...)
	}
	input = append(input, u64le(ctr)...)
	digest := fs.xof.Expand(fs.labels[round], input)
	if !bytes.Equal(digest, expected) {
		return nil, fmt.Errorf("digest mismatch in round %d", round)
	}
	if !hasZeroPrefix(digest, kappa) {
		return nil, fmt.Errorf("grinding predicate failed in round %d", round)
	}
	return digest, nil
}

func kMatrixEqual(a, b [][]KScalar) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if len(a[i][j]) != len(b[i][j]) {
				return false
			}
			for t := range a[i][j] {
				if a[i][j][t] != b[i][j][t] {
					return false
				}
			}
		}
	}
	return true
}

func equalIntSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func verifyLVCSConstraints(
	ringQ *ring.Ring,
	params decs.Params,
	proof *Proof,
	Gamma [][]uint64,
	Rpolys []*ring.Poly,
	coeffMatrix [][]uint64,
	barSets [][]uint64,
	vTargets [][]uint64,
	maskIdx []int,
	tail []int,
	ncols int,
) (bool, error) {
	base := proof.RowOpening
	if base == nil {
		return false, errors.New("VerifyNIZK: nil row opening")
	}
	if len(coeffMatrix) == 0 || len(coeffMatrix[0]) == 0 {
		return false, errors.New("VerifyNIZK: empty coefficient matrix")
	}
	rowCount := base.R
	if rowCount <= 0 {
		rowCount = len(coeffMatrix[0])
	}
	if len(coeffMatrix[0]) != rowCount {
		return false, errors.New("VerifyNIZK: coefficient matrix row length mismatch")
	}
	eta := base.Eta
	if eta <= 0 {
		eta = len(Gamma)
	}
	maskOpen, err := buildSubsetOpening(base, maskIdx, rowCount, eta)
	if err != nil {
		return false, fmt.Errorf("VerifyNIZK: mask opening: %w", err)
	}
	tailOpen, err := buildSubsetOpening(base, tail, rowCount, eta)
	if err != nil {
		return false, fmt.Errorf("VerifyNIZK: tail opening: %w", err)
	}
	for i := range maskOpen.Pvals {
		if len(maskOpen.Pvals[i]) != rowCount {
			return false, fmt.Errorf("VerifyNIZK: mask Pvals[%d] len=%d want=%d", i, len(maskOpen.Pvals[i]), rowCount)
		}
		if eta > 0 && len(maskOpen.Mvals[i]) != eta {
			return false, fmt.Errorf("VerifyNIZK: mask Mvals[%d] len=%d want=%d", i, len(maskOpen.Mvals[i]), eta)
		}
	}
	for i := range tailOpen.Pvals {
		if len(tailOpen.Pvals[i]) != rowCount {
			return false, fmt.Errorf("VerifyNIZK: tail Pvals[%d] len=%d want=%d", i, len(tailOpen.Pvals[i]), rowCount)
		}
		if eta > 0 && len(tailOpen.Mvals[i]) != eta {
			return false, fmt.Errorf("VerifyNIZK: tail Mvals[%d] len=%d want=%d", i, len(tailOpen.Mvals[i]), eta)
		}
	}
	subsetParams := decs.Params{Degree: params.Degree, Eta: eta, NonceBytes: params.NonceBytes}
	if err := verifyDECSSubset(ringQ, proof.Root, subsetParams, Gamma, Rpolys, maskOpen, maskIdx); err != nil {
		return false, fmt.Errorf("VerifyNIZK: mask subset: %w", err)
	}
	if err := verifyDECSSubset(ringQ, proof.Root, subsetParams, Gamma, Rpolys, tailOpen, tail); err != nil {
		return false, fmt.Errorf("VerifyNIZK: tail subset: %w", err)
	}
	if len(coeffMatrix) != len(barSets) || len(coeffMatrix) != len(vTargets) {
		return false, errors.New("VerifyNIZK: coefficient matrix dimension mismatch")
	}
	mod := ringQ.Modulus[0]
	for t, idx := range maskIdx {
		maskedPos := idx - ncols
		row := maskOpen.Pvals[t]
		for k := 0; k < len(barSets); k++ {
			if len(coeffMatrix[k]) != len(row) {
				return false, errors.New("VerifyNIZK: coeff row length mismatch")
			}
			sum := uint64(0)
			for j := 0; j < len(row); j++ {
				sum = lvcs.MulAddMod64(sum, coeffMatrix[k][j], row[j], mod)
			}
			if sum != barSets[k][maskedPos]%mod {
				return false, fmt.Errorf("VerifyNIZK: masked linear relation mismatch k=%d pos=%d sum=%d target=%d", k, maskedPos, sum, barSets[k][maskedPos]%mod)
			}
		}
	}
	ell := len(barSets[0])
	Qvals := make([]*ring.Poly, len(barSets))
	for k := 0; k < len(barSets); k++ {
		poly, interpErr := interpolateRowLocal(ringQ, vTargets[k], barSets[k], ncols, ell)
		if interpErr != nil {
			return false, fmt.Errorf("VerifyNIZK: interpolateRow(%d): %w", k, interpErr)
		}
		Qvals[k] = ringQ.NewPoly()
		ringQ.NTT(poly, Qvals[k])
	}
	for t, idx := range tail {
		row := tailOpen.Pvals[t]
		for k := 0; k < len(barSets); k++ {
			lhs := Qvals[k].Coeffs[0][idx] % mod
			sum := uint64(0)
			for j := 0; j < len(row); j++ {
				sum = lvcs.MulAddMod64(sum, coeffMatrix[k][j], row[j], mod)
			}
			if lhs != sum {
				return false, fmt.Errorf("VerifyNIZK: tail linear relation mismatch k=%d idx=%d lhs=%d rhs=%d", k, idx, lhs, sum)
			}
		}
	}
	return true, nil
}

func buildSubsetOpening(base *decs.DECSOpening, indices []int, rowCount, eta int) (*decs.DECSOpening, error) {
	if base == nil {
		return nil, errors.New("nil base opening")
	}
	if err := decs.EnsureMerkleDecoded(base); err != nil {
		return nil, err
	}
	posByIdx := make(map[int]int, base.EntryCount())
	for i := 0; i < base.EntryCount(); i++ {
		idx := base.IndexAt(i)
		posByIdx[idx] = i
	}
	nonceBytes := base.NonceBytes
	if nonceBytes <= 0 && len(base.Nonces) > 0 && len(base.Nonces[0]) > 0 {
		nonceBytes = len(base.Nonces[0])
	}
	sub := &decs.DECSOpening{
		Indices:    make([]int, len(indices)),
		Pvals:      make([][]uint64, len(indices)),
		Nodes:      append([][]byte(nil), base.Nodes...),
		R:          rowCount,
		Eta:        eta,
		NonceSeed:  append([]byte(nil), base.NonceSeed...),
		NonceBytes: nonceBytes,
	}
	if len(base.Nonces) > 0 {
		sub.Nonces = make([][]byte, len(indices))
	}
	if len(base.PathIndex) > 0 {
		sub.PathIndex = make([][]int, len(indices))
	}
	if eta > 0 {
		sub.Mvals = make([][]uint64, len(indices))
	}
	for i, idx := range indices {
		pos, ok := posByIdx[idx]
		if !ok {
			return nil, fmt.Errorf("opening missing index %d", idx)
		}
		sub.Indices[i] = idx
		if len(base.Pvals) > 0 {
			sub.Pvals[i] = append([]uint64(nil), base.Pvals[pos]...)
		} else {
			sub.Pvals[i] = make([]uint64, rowCount)
			for j := 0; j < rowCount; j++ {
				sub.Pvals[i][j] = decs.GetOpeningPval(base, pos, j)
			}
		}
		if eta > 0 {
			if len(base.Mvals) > 0 {
				sub.Mvals[i] = append([]uint64(nil), base.Mvals[pos]...)
			} else {
				sub.Mvals[i] = make([]uint64, eta)
				for j := 0; j < eta; j++ {
					sub.Mvals[i][j] = decs.GetOpeningMval(base, pos, j)
				}
			}
		}
		if len(base.PathIndex) > 0 {
			sub.PathIndex[i] = append([]int(nil), base.PathIndex[pos]...)
		}
		if len(base.Nonces) > pos && len(base.Nonces[pos]) > 0 {
			sub.Nonces[i] = append([]byte(nil), base.Nonces[pos]...)
		}
	}
	if len(sub.PathIndex) > 0 && len(sub.PathIndex[0]) > 0 {
		sub.PathDepth = len(sub.PathIndex[0])
	}
	return sub, nil
}

func interpolateRowLocal(ringQ *ring.Ring, row []uint64, mask []uint64, ncols, ell int) (*ring.Poly, error) {
	mod := ringQ.Modulus[0]
	N := ringQ.N
	m := ncols + ell
	if m > int(N) {
		return nil, errors.New("interpolateRow: degree exceed ring.N")
	}
	px := ringQ.NewPoly()
	px.Coeffs[0][1] = 1
	pvs := ringQ.NewPoly()
	ringQ.NTT(px, pvs)
	xs := append([]uint64(nil), pvs.Coeffs[0][:m]...)
	ys := make([]uint64, m)
	copy(ys[:ncols], row)
	copy(ys[ncols:], mask)
	T := make([]uint64, m+1)
	T[0] = 1
	for _, xj := range xs {
		for k := m; k >= 1; k-- {
			T[k] = (T[k-1] + mod - (xj * T[k] % mod)) % mod
		}
		T[0] = (mod - (xj * T[0] % mod)) % mod
	}
	Pcoefs := make([]uint64, m)
	tmp := make([]uint64, m)
	for i, xi := range xs {
		tmp[m-1] = T[m]
		for k := m - 2; k >= 0; k-- {
			tmp[k] = (T[k+1] + xi*tmp[k+1]) % mod
		}
		denom := uint64(1)
		for j, xj := range xs {
			if j == i {
				continue
			}
			diff := (xi + mod - xj) % mod
			denom = (denom * diff) % mod
		}
		inv := new(big.Int).ModInverse(new(big.Int).SetUint64(denom), new(big.Int).SetUint64(mod))
		if inv == nil {
			return nil, errors.New("interpolateRow: denom not invertible")
		}
		scale := (ys[i] * inv.Uint64()) % mod
		for k := 0; k < m; k++ {
			Pcoefs[k] = (Pcoefs[k] + tmp[k]*scale) % mod
		}
	}
	P := ringQ.NewPoly()
	copy(P.Coeffs[0][:m], Pcoefs)
	for k := m; k < int(N); k++ {
		P.Coeffs[0][k] = 0
	}
	return P, nil
}

func verifyDECSSubset(ringQ *ring.Ring, root [16]byte, params decs.Params, Gamma [][]uint64, R []*ring.Poly, open *decs.DECSOpening, indices []int) error {
	entryCount := open.EntryCount()
	if len(indices) != entryCount {
		return fmt.Errorf("DECS subset: index length mismatch")
	}
	rowCount := len(Gamma[0])
	if rowCount <= 0 {
		return fmt.Errorf("DECS subset: empty Gamma rows")
	}
	if len(R) != params.Eta {
		return fmt.Errorf("DECS subset: R count mismatch")
	}
	Re := make([]*ring.Poly, params.Eta)
	for k := 0; k < params.Eta; k++ {
		poly := ringQ.NewPoly()
		ringQ.NTT(R[k], poly)
		Re[k] = poly
	}
	mod := ringQ.Modulus[0]
	for t, idx := range indices {
		if idx < 0 || idx >= int(ringQ.N) {
			return fmt.Errorf("DECS subset: index %d out of range", idx)
		}
		buf := make([]byte, 4*(rowCount+params.Eta)+2+params.NonceBytes)
		off := 0
		pvals := make([]uint64, rowCount)
		for j := 0; j < rowCount; j++ {
			pv := decs.GetOpeningPval(open, t, j) % mod
			pvals[j] = pv
			binary.LittleEndian.PutUint32(buf[off:], uint32(pv))
			off += 4
		}
		mvals := make([]uint64, params.Eta)
		for k := 0; k < params.Eta; k++ {
			mv := decs.GetOpeningMval(open, t, k) % mod
			mvals[k] = mv
			binary.LittleEndian.PutUint32(buf[off:], uint32(mv))
			off += 4
		}
		binary.LittleEndian.PutUint16(buf[off:], uint16(idx))
		off += 2
		var nonce []byte
		if len(open.Nonces) > t && len(open.Nonces[t]) > 0 {
			nonce = open.Nonces[t]
		} else if len(open.NonceSeed) > 0 && open.NonceBytes > 0 {
			nonce = decs.DeriveNonce(open.NonceSeed, idx, open.NonceBytes)
		}
		if len(nonce) != params.NonceBytes {
			return fmt.Errorf("DECS subset: nonce length mismatch at t=%d", t)
		}
		copy(buf[off:], nonce[:params.NonceBytes])
		path, err := extractPathNodes(open, t)
		if err != nil {
			return fmt.Errorf("DECS subset: %w", err)
		}
		if !decs.VerifyPath(buf, path, root, idx) {
			return fmt.Errorf("DECS subset: Merkle verification failed at idx=%d", idx)
		}
		for k := 0; k < params.Eta; k++ {
			lhs := Re[k].Coeffs[0][idx] % mod
			rhs := mvals[k]
			for j := 0; j < rowCount; j++ {
				rhs = lvcs.MulAddMod64(rhs, Gamma[k][j], pvals[j], mod)
			}
			if lhs != rhs%mod {
				return fmt.Errorf("DECS subset: relation mismatch k=%d idx=%d lhs=%d rhs=%d", k, idx, lhs, rhs%mod)
			}
		}
	}
	return nil
}

func extractPathNodes(open *decs.DECSOpening, t int) ([][]byte, error) {
	if err := decs.EnsureMerkleDecoded(open); err != nil {
		return nil, err
	}
	if len(open.PathIndex) == 0 || t < 0 || t >= len(open.PathIndex) {
		return nil, errors.New("missing path indices")
	}
	path := make([][]byte, len(open.PathIndex[t]))
	for lvl, id := range open.PathIndex[t] {
		if id < 0 || id >= len(open.Nodes) {
			return nil, fmt.Errorf("path node index out of range at t=%d lvl=%d", t, lvl)
		}
		path[lvl] = open.Nodes[id]
	}
	return path, nil
}

func expandPackedOpening(op *decs.DECSOpening) *decs.DECSOpening {
	if op == nil {
		return nil
	}
	clone := cloneDECSOpening(op)
	fullIndices := clone.AllIndices()
	if len(fullIndices) > 0 {
		clone.Indices = append([]int(nil), fullIndices...)
		clone.TailCount = len(fullIndices)
	} else {
		clone.Indices = nil
		clone.TailCount = 0
	}
	clone.MaskBase = 0
	clone.MaskCount = 0
	clone.IndexBits = nil
	clone.PathBits = nil
	clone.PathBitWidth = 0
	clone.PathDepth = 0
	if len(clone.Pvals) == 0 && clone.R > 0 {
		clone.Pvals = make([][]uint64, len(clone.Indices))
		for i := range clone.Indices {
			clone.Pvals[i] = make([]uint64, clone.R)
			for j := 0; j < clone.R; j++ {
				clone.Pvals[i][j] = decs.GetOpeningPval(op, i, j)
			}
		}
	}
	if len(clone.Mvals) == 0 && clone.Eta > 0 {
		clone.Mvals = make([][]uint64, len(clone.Indices))
		for i := range clone.Indices {
			clone.Mvals[i] = make([]uint64, clone.Eta)
			for j := 0; j < clone.Eta; j++ {
				clone.Mvals[i][j] = decs.GetOpeningMval(op, i, j)
			}
		}
	}
	_ = decs.EnsureMerkleDecoded(clone)
	return clone
}
