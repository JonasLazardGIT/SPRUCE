// PACS_Simulation.go – upgraded demo that now uses the strict LVCS
// evaluation check (EvalStep2) that binds openings to tail-only challenges.
//
// Key changes vs. the previous version
// -----------------------------------
//  1. A public coefficient matrix **C** (here: one‑row, deterministic) is
//     generated so we actually prove a *linear map* of the committed rows.
//  2. The prover calls  lvcs.EvalInit  to compute the masked targets **bar**.
//     These values are sent to the verifier (locally just stored).
//  3. The verifier now calls  EvalStep2  – which re‑runs the Slim tests *and*
//     additionally checks that the opened coordinates satisfy the linear
//     relation and match **bar**.
//
// Nothing else in the PACS layer (Eq.(4), Σ_Ω, etc.) changes.
// --------------------------------------------------------------------------
package PIOP

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	mrand "math/rand"
	"reflect"
	"testing"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"
	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const linfChainTestQ = uint64(1038337)

// --------------------------------------------------------------------------
// transcript – printed once at the end so humans can diff two runs quickly.
// --------------------------------------------------------------------------
type transcript struct {
	Root                string
	Gamma0, GammaPrime0 [][]uint64
	Rhash               string
	E                   []int // indices opened through DECS
	Flags               struct{ Merkle, Deg, LinMap, Eq4, Sum bool }
}

func bumpAt(r *ring.Ring, p *ring.Poly, idx int, q uint64) {
	tmp := r.NewPoly()
	r.InvNTT(p, tmp)
	tmp.Coeffs[0][idx] = (tmp.Coeffs[0][idx] + 1) % q
	r.NTT(tmp, p)
}

func bumpConst(r *ring.Ring, p *ring.Poly, q uint64) { bumpAt(r, p, 0, q) }

func secureSimOpts() SimOpts {
	return SimOpts{
		Ell:      32,
		NCols:    8,
		Rho:      2,
		EllPrime: 2,
		Eta:      2,
		NLeaves:  0,
		Kappa:    [4]int{8, 8, 8, 8},
	}
}

func setRowValue(r *ring.Ring, omega []uint64, ell int, row *ring.Poly, idx int, val uint64) {
	q := r.Modulus[0]
	coeff := r.NewPoly()
	r.InvNTT(row, coeff)
	vals := make([]uint64, len(omega))
	for j := 0; j < len(omega); j++ {
		vals[j] = EvalPoly(coeff.Coeffs[0], omega[j]%q, q)
	}
	vals[idx] = val % q
	updated := buildValueRow(r, vals, omega, ell)
	copy(row.Coeffs[0], updated.Coeffs[0])
}

func clonePolySlice(polys []*ring.Poly) []*ring.Poly {
	out := make([]*ring.Poly, len(polys))
	for i, p := range polys {
		if p != nil {
			out[i] = p.CopyNew()
		}
	}
	return out
}

func assertMaskRowsMatch(t *testing.T, ctx *simCtx) {
	t.Helper()
	if ctx == nil {
		t.Fatalf("assertMaskRowsMatch: nil context")
	}
	if ctx.maskRowCount <= 0 {
		t.Fatalf("expected mask rows, got %d", ctx.maskRowCount)
	}
	if ctx.maskRowOffset < 0 || ctx.maskRowOffset+ctx.maskRowCount > len(ctx.rows) {
		t.Fatalf("mask row slice out of bounds: offset=%d count=%d len=%d", ctx.maskRowOffset, ctx.maskRowCount, len(ctx.rows))
	}
	if len(ctx.maskIndependent) > ctx.maskRowCount {
		t.Fatalf("mask polynomial count %d exceeds row count %d", len(ctx.maskIndependent), ctx.maskRowCount)
	}
	q := ctx.q
	tmp := ctx.ringQ.NewPoly()
	for i := 0; i < ctx.maskRowCount; i++ {
		row := ctx.rows[ctx.maskRowOffset+i]
		if i < len(ctx.maskIndependent) && ctx.maskIndependent[i] != nil {
			ctx.ringQ.InvNTT(ctx.maskIndependent[i], tmp)
			coeffs := tmp.Coeffs[0]
			rowSum := uint64(0)
			for j, w := range ctx.omega {
				expected := EvalPoly(coeffs, w%q, q)
				if row[j]%q != expected%q {
					t.Fatalf("mask row %d col %d mismatch: got %d want %d", i, j, row[j]%q, expected%q)
				}
				rowSum = (rowSum + row[j]) % q
			}
			if rowSum%q != 0 {
				t.Fatalf("mask row %d has ΣΩ=%d (expected 0)", i, rowSum%q)
			}
		} else {
			rowSum := uint64(0)
			for j, val := range row {
				if val%q != 0 {
					t.Fatalf("mask filler row %d col %d = %d (expected 0)", i, j, val%q)
				}
				rowSum = (rowSum + val) % q
			}
			if rowSum%q != 0 {
				t.Fatalf("mask filler row %d has ΣΩ=%d", i, rowSum%q)
			}
		}
	}
}

func assertPolySlicesEqual(t *testing.T, ringQ *ring.Ring, name string, want, got []*ring.Poly) {
	t.Helper()
	if len(want) != len(got) {
		t.Fatalf("%s length mismatch: got %d want %d", name, len(got), len(want))
	}
	for i := range want {
		if !ringQ.Equal(want[i], got[i]) {
			t.Fatalf("%s[%d] mismatch", name, i)
		}
	}
}

type proofDigest map[string]string

func proofSnapshotDigest(ps ProofSnapshot) proofDigest {
	d := proofDigest{
		"Lambda":          hashValue(ps.Lambda),
		"Theta":           hashValue(ps.Theta),
		"RowLayout":       hashValue(ps.RowLayout),
		"MaskRowOffset":   hashValue(ps.MaskRowOffset),
		"MaskRowCount":    hashValue(ps.MaskRowCount),
		"MaskDegreeBound": hashValue(ps.MaskDegreeBound),
		"FparNTT":         hashValue(ps.FparNTT),
		"FaggNTT":         hashValue(ps.FaggNTT),
		"QNTT":            hashValue(ps.QNTT),
		"R":               hashValue(ps.R),
	}
	return d
}

func hashValue(v interface{}) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%#v", v)))
	return hex.EncodeToString(h[:])
}

func compareProofDigest(t *testing.T, legacy, merged proofDigest, expectedDiff map[string]bool) {
	t.Helper()
	actualDiff := make(map[string]bool, len(legacy))
	for key, legacyHash := range legacy {
		mergedHash, ok := merged[key]
		if !ok {
			t.Fatalf("proof digest missing key %q in merged snapshot", key)
		}
		actualDiff[key] = legacyHash != mergedHash
	}
	for key := range merged {
		if _, ok := legacy[key]; !ok {
			t.Fatalf("proof digest missing key %q in legacy snapshot", key)
		}
	}
	if !reflect.DeepEqual(actualDiff, expectedDiff) {
		t.Fatalf("unexpected proof delta: got %+v want %+v", actualDiff, expectedDiff)
	}
}

func assertMaskInvariants(t *testing.T, ctx *simCtx) {
	t.Helper()
	if ctx == nil {
		t.Fatalf("nil simulation context")
	}
	if ctx.proof.MaskRowCount <= 0 {
		t.Fatalf("expected non-zero MaskRowCount")
	}
	if ctx.maskRowCount != ctx.proof.MaskRowCount {
		t.Fatalf("maskRowCount mismatch: ctx=%d proof=%d", ctx.maskRowCount, ctx.proof.MaskRowCount)
	}
	if len(ctx.maskIndependent) != ctx.maskRowCount {
		t.Fatalf("maskIndependent count mismatch: got %d want %d", len(ctx.maskIndependent), ctx.maskRowCount)
	}
	sums := sumPolyList(ctx.ringQ, ctx.maskIndependent, ctx.omega)
	for i, sum := range sums {
		if sum%ctx.q != 0 {
			t.Fatalf("independent mask %d ΣΩ=%d (want 0)", i, sum%ctx.q)
		}
		deg := maxPolyDegree(ctx.ringQ, ctx.maskIndependent[i])
		if deg > ctx.maskDegreeBound {
			t.Fatalf("independent mask %d degree %d exceeds bound %d", i, deg, ctx.maskDegreeBound)
		}
	}
	if ctx.theta <= 1 {
		return
	}
	if ctx.KField == nil {
		t.Fatalf("expected KField for theta=%d", ctx.theta)
	}
	if len(ctx.maskIndependentK) != ctx.maskRowCount {
		t.Fatalf("maskIndependentK count mismatch: got %d want %d", len(ctx.maskIndependentK), ctx.maskRowCount)
	}
	for i, kp := range ctx.maskIndependentK {
		sum := ctx.KField.Zero()
		for _, w := range ctx.omega {
			sum = ctx.KField.Add(sum, evalKPolyAtF(ctx.KField, kp, w))
		}
		for limb, val := range sum.Limb {
			if val%ctx.q != 0 {
				t.Fatalf("independent K-mask %d limb %d ΣΩ=%d (want 0)", i, limb, val%ctx.q)
			}
		}
		if kp != nil && kp.Degree > ctx.maskDegreeBound {
			t.Fatalf("independent K-mask %d degree %d exceeds bound %d", i, kp.Degree, ctx.maskDegreeBound)
		}
	}
}

func extractChainDecomp(spec LinfSpec, base int, count int, w1 []*ring.Poly) ChainDecomp {
	chainRowsPer := 1 + spec.L
	out := ChainDecomp{M: make([]*ring.Poly, count), D: make([][]*ring.Poly, count)}
	for row := 0; row < count; row++ {
		rowBase := base + row*chainRowsPer
		out.M[row] = w1[rowBase]
		out.D[row] = make([]*ring.Poly, spec.L)
		for digit := 0; digit < spec.L; digit++ {
			out.D[row][digit] = w1[rowBase+1+digit]
		}
	}
	return out
}

func deepCopyOpen(o *decs.DECSOpening) *decs.DECSOpening {
	if o == nil {
		return nil
	}
	return cloneDECSOpening(o)
}

// --------------------------------------------------------------------------
// go test entry‑point
// --------------------------------------------------------------------------
func TestPACSSimulation(t *testing.T) {
	opts := secureSimOpts()
	ctx, okLin, okEq4, okSum := buildSimWith(t, opts)
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("verifier rejected – some check failed, OkLin= %v, OkEq4= %v, OkSum= %v", okLin, okEq4, okSum)
	}
	if ctx == nil || ctx.proof == nil {
		t.Fatalf("expected proof context")
	}
	t.Logf("RowOpening.R=%d Eta=%d rows=%d", ctx.proof.RowOpening.R, ctx.proof.RowOpening.Eta, len(ctx.proof.RowOpening.Pvals))
	if len(ctx.proof.RowOpening.Pvals) > 0 {
		for i := 0; i < len(ctx.proof.RowOpening.Pvals) && i < 2; i++ {
			t.Logf("Pvals[%d] len=%d", i, len(ctx.proof.RowOpening.Pvals[i]))
		}
	}
	if len(ctx.proof.RowOpening.Mvals) > 0 {
		for i := 0; i < len(ctx.proof.RowOpening.Mvals) && i < 2; i++ {
			t.Logf("Mvals[%d] len=%d", i, len(ctx.proof.RowOpening.Mvals[i]))
		}
	}
	if len(ctx.proof.RowOpening.Nonces) > 0 {
		for i := 0; i < len(ctx.proof.RowOpening.Nonces) && i < 2; i++ {
			t.Logf("Nonce[%d] len=%d", i, len(ctx.proof.RowOpening.Nonces[i]))
		}
	}
	okLinNI, okEq4NI, okSumNI, err := VerifyNIZK(ctx.proof)
	if err != nil {
		t.Fatalf("VerifyNIZK failed: %v", err)
	}
	if !(okLinNI && okEq4NI && okSumNI) {
		t.Fatalf("VerifyNIZK rejected: OkLin=%v OkEq4=%v OkSum=%v", okLinNI, okEq4NI, okSumNI)
	}
}

func TestMaskDegreeBoundIsDQ(t *testing.T) {
	ctx, okLin, okEq4, okSum := buildSimWith(t, defaultSimOpts())
	if ctx == nil {
		t.Fatalf("expected simulation context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline simulation rejected: lin=%v eq4=%v sum=%v", okLin, okEq4, okSum)
	}
	if ctx.maskDegreeBound != ctx.dQ {
		t.Fatalf("mask degree bound %d != dQ %d", ctx.maskDegreeBound, ctx.dQ)
	}
}

func TestSmallFieldGammaKBinding(t *testing.T) {
	opts := defaultSimOpts()
	opts.Theta = 2
	opts.Rho = 1
	opts.EllPrime = 1
	ctx, okLin, okEq4, okSum := buildSimWith(t, opts)
	if ctx == nil {
		t.Fatalf("expected simulation context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline small-field verification failed: lin=%v eq4=%v sum=%v", okLin, okEq4, okSum)
	}
	assertMaskInvariants(t, ctx)
	if ctx.KField == nil {
		t.Skip("small-field extension not initialised")
	}
	if len(ctx.GammaPrimeScalars) == 0 || len(ctx.GammaPrimeScalars[0]) == 0 {
		t.Fatalf("expected GammaPrime scalars")
	}
	if len(ctx.GammaPrimeK) == 0 || len(ctx.GammaPrimeK[0]) == 0 || len(ctx.GammaPrimeK[0][0]) < 2 {
		t.Skip("insufficient theta/limbs to test K-limb tamper")
	}
	if len(ctx.QK) == 0 || len(ctx.MK) == 0 {
		t.Fatalf("expected K-polynomials in context")
	}
	tampered := copyKMatrix(ctx.GammaPrimeK)
	tampered[0][0][1] = (tampered[0][0][1] + 1) % ctx.q
	evalElem := ctx.KField.Phi(ctx.KPoint[0])
	ok := checkEq4AtK_K_QK(ctx.ringQ, ctx.KField, evalElem, ctx.QK, ctx.MK, ctx.Fpar, ctx.Fagg, tampered, ctx.GammaAggK)
	if ok {
		t.Fatalf("Eq.(4)@K accepted tampered Γ′_K limb")
	}
}

func TestEq4OnTailDetectsMaskTamper(t *testing.T) {
	ctx, okLin, okEq4, okSum := buildSimWith(t, defaultSimOpts())
	if ctx == nil {
		t.Fatalf("expected context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline verification failed: lin=%v eq4=%v sum=%v", okLin, okEq4, okSum)
	}
	badOpening := cloneDECSOpening(ctx.maskOpenValues)
	if badOpening == nil {
		t.Fatalf("expected mask opening values")
	}
	badOpening.Pvals[0][0] = (badOpening.Pvals[0][0] + 1) % ctx.q
	ok := checkEq4OnTailOpen(ctx.ringQ, ctx.KField, ctx.theta, ctx.E, ctx.Q, ctx.QK, ctx.MK, ctx.Fpar, ctx.Fagg, ctx.GammaPrimeScalars, ctx.GammaPrimeAgg, ctx.GammaPrimeK, ctx.GammaAggK, badOpening)
	if ok {
		t.Fatalf("Eq.(4)@E accepted tampered mask opening")
	}
}

func TestPIOP_MultiEval_MultiBatch(t *testing.T) {
	opts := SimOpts{
		NCols:    8,
		Ell:      64,
		EllPrime: 8,
		Rho:      4,
		Eta:      3,
		NLeaves:  0,
		Kappa:    [4]int{16, 16, 16, 16},
	}
	rep, err := RunOnce(opts)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if !rep.Verdict.OkLin || !rep.Verdict.OkEq4 || !rep.Verdict.OkSum {
		t.Fatalf("expected all checks to pass, got OkLin=%v OkEq4=%v OkSum=%v", rep.Verdict.OkLin, rep.Verdict.OkEq4, rep.Verdict.OkSum)
	}
	if rep.Soundness.DQ <= 0 {
		t.Fatalf("expected positive dQ, got %d", rep.Soundness.DQ)
	}
}

func TestPIOP_MultiBatch_MultiEval_Rejects(t *testing.T) {
	opts := SimOpts{
		NCols:    8,
		Ell:      16,
		EllPrime: 4,
		Rho:      2,
		Eta:      2,
		NLeaves:  0,
		Kappa:    [4]int{8, 8, 8, 8},
	}
	ctx, okLin, okEq4, okSum := buildSimWith(t, opts)
	if ctx == nil {
		t.Fatalf("expected context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline simulation failed: OkLin=%v OkEq4=%v OkSum=%v", okLin, okEq4, okSum)
	}
	q := ctx.q
	orig := ctx.Q[0].Coeffs[0][0]
	ctx.Q[0].Coeffs[0][0] = modAdd(orig, 1, q)
	if checkEq4OnOpening(ctx.ringQ, ctx.Q, ctx.M, nil, ctx.Fpar, ctx.Fagg, ctx.GammaPrimePoly, ctx.GammaPrimeAgg, ctx.omega, ctx.Eprime) {
		t.Fatalf("Eq.(4) check should fail after tamper")
	}
}

func TestPIOP_SoundnessKnobs(t *testing.T) {
	base := SimOpts{
		NCols:    8,
		Ell:      16,
		EllPrime: 4,
		Rho:      4,
		Eta:      3,
		NLeaves:  0,
		Kappa:    [4]int{12, 12, 12, 12},
	}
	baseline, err := RunOnce(base)
	if err != nil {
		t.Fatalf("baseline RunOnce failed: %v", err)
	}
	variants := []struct {
		name string
		opts SimOpts
	}{}
	for _, variant := range variants {
		rep, err := RunOnce(variant.opts)
		if err != nil {
			t.Fatalf("%s RunOnce failed: %v", variant.name, err)
		}
		delta := rep.Soundness.TotalBits - baseline.Soundness.TotalBits
		t.Logf("%s: total bits %.2f (Δ%.2f)", variant.name, rep.Soundness.TotalBits, delta)
	}
}

func TestProofSerialization(t *testing.T) {
	opts := secureSimOpts()
	ctx, okLin, okEq4, okSum := buildSimWith(t, opts)
	if ctx == nil {
		t.Fatalf("expected context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline verification failed")
	}
	snap := ctx.proof.Snapshot()
	clone := snap.Restore()
	if !bytes.Equal(clone.Salt, ctx.proof.Salt) {
		t.Fatalf("salt mismatch after restore")
	}
	if clone.Ctr != ctx.proof.Ctr {
		t.Fatalf("counters mismatch after restore")
	}
	if !reflect.DeepEqual(clone.Digests, ctx.proof.Digests) {
		t.Fatalf("digests mismatch after restore")
	}
	if !reflect.DeepEqual(clone.Tail, ctx.proof.Tail) {
		t.Fatalf("Tail indices mismatch")
	}
	cloneVTargets := clone.VTargetsMatrix()
	proofVTargets := ctx.proof.VTargetsMatrix()
	if !reflect.DeepEqual(cloneVTargets, proofVTargets) {
		t.Fatalf("VTargets mismatch")
	}
	cloneBarSets := clone.BarSetsMatrix()
	proofBarSets := ctx.proof.BarSetsMatrix()
	if !reflect.DeepEqual(cloneBarSets, proofBarSets) {
		t.Fatalf("BarSets mismatch")
	}
	packedClone := cloneDECSOpening(clone.MOpening)
	packedProof := cloneDECSOpening(ctx.proof.MOpening)
	decs.PackOpening(packedClone)
	decs.PackOpening(packedProof)
	if !reflect.DeepEqual(packedClone, packedProof) {
		t.Fatalf("Mask opening mismatch")
	}
	packedRowClone := cloneDECSOpening(clone.RowOpening)
	packedRowProof := cloneDECSOpening(ctx.proof.RowOpening)
	decs.PackOpening(packedRowClone)
	decs.PackOpening(packedRowProof)
	if !reflect.DeepEqual(packedRowClone, packedRowProof) {
		t.Fatalf("Row opening mismatch")
	}
}

func TestVerifyNIZKSnapshotRoundTrip(t *testing.T) {
	opts := secureSimOpts()
	ctx, okLin, okEq4, okSum := buildSimWith(t, opts)
	if ctx == nil {
		t.Fatalf("expected context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline simulation rejected: lin=%v eq4=%v sum=%v", okLin, okEq4, okSum)
	}
	if ctx.proof.MaskRowOffset == 0 {
		t.Fatalf("expected non-zero MaskRowOffset")
	}
	if ctx.proof.MaskRowCount == 0 {
		t.Fatalf("expected non-zero MaskRowCount")
	}
	if ctx.maskRowCount != ctx.proof.MaskRowCount {
		t.Fatalf("maskRowCount mismatch: ctx=%d proof=%d", ctx.maskRowCount, ctx.proof.MaskRowCount)
	}
	if ctx.proof.MaskDegreeBound == 0 {
		t.Fatalf("expected non-zero MaskDegreeBound")
	}
	okLinBase, okEq4Base, okSumBase, err := VerifyNIZK(ctx.proof)
	if err != nil {
		t.Fatalf("VerifyNIZK on original proof failed: %v", err)
	}
	if !(okLinBase && okEq4Base && okSumBase) {
		t.Fatalf("VerifyNIZK on original proof rejected: lin=%v eq4=%v sum=%v", okLinBase, okEq4Base, okSumBase)
	}
	tamperedVT := ctx.proof.Snapshot().Restore()
	vMat := tamperedVT.VTargetsMatrix()
	if len(vMat) == 0 || len(vMat[0]) == 0 {
		t.Fatalf("expected non-empty VTargets matrix")
	}
	vMat[0][0] ^= 1
	tamperedVT.setVTargets(vMat)
	if _, _, _, err := VerifyNIZK(tamperedVT); err == nil {
		t.Fatalf("VerifyNIZK should reject proof with tampered VTargets matrix")
	}
	tamperedBar := ctx.proof.Snapshot().Restore()
	barMat := tamperedBar.BarSetsMatrix()
	if len(barMat) == 0 || len(barMat[0]) == 0 {
		t.Fatalf("expected non-empty BarSets matrix")
	}
	barMat[0][0] ^= 1
	tamperedBar.setBarSets(barMat)
	if _, _, _, err := VerifyNIZK(tamperedBar); err == nil {
		t.Fatalf("VerifyNIZK should reject proof with tampered BarSets matrix")
	}
	ctx.proof.Gamma = [][]uint64{{1, 2}, {3, 4}}
	ctx.proof.GammaK = [][]KScalar{{KScalar{7, 8}}}
	ctx.proof.RoundCounters = [4]uint64{11, 22, 33, 44}
	snap := ctx.proof.Snapshot()
	restored := snap.Restore()
	if ctx.proof.Root != restored.Root {
		t.Fatalf("root mismatch after restore")
	}
	if !reflect.DeepEqual(restored.Digests, ctx.proof.Digests) {
		t.Fatalf("digests mismatch after restore")
	}
	if restored.RowOpening.PathBitWidth != ctx.proof.RowOpening.PathBitWidth {
		t.Fatalf("row PathBitWidth mismatch after restore")
	}
	if restored.RowOpening.PathDepth != ctx.proof.RowOpening.PathDepth {
		t.Fatalf("row PathDepth mismatch after restore")
	}
	if !reflect.DeepEqual(restored.RowOpening.PathBits, ctx.proof.RowOpening.PathBits) {
		t.Fatalf("row PathBits mismatch after restore")
	}
	if !reflect.DeepEqual(restored.RowOpening.Nodes, ctx.proof.RowOpening.Nodes) {
		t.Fatalf("row nodes mismatch after restore")
	}
	if restored.RowOpening.NonceBytes != ctx.proof.RowOpening.NonceBytes {
		t.Fatalf("row nonce length mismatch after restore")
	}
	if !bytes.Equal(restored.RowOpening.NonceSeed, ctx.proof.RowOpening.NonceSeed) {
		t.Fatalf("row nonce seed mismatch after restore")
	}
	if !reflect.DeepEqual(restored.RowOpening.PvalsBits, ctx.proof.RowOpening.PvalsBits) {
		t.Fatalf("row PvalsBits mismatch after restore")
	}
	if !reflect.DeepEqual(restored.RowOpening.MvalsBits, ctx.proof.RowOpening.MvalsBits) {
		t.Fatalf("row MvalsBits mismatch after restore")
	}
	if restored.MaskRowOffset != ctx.proof.MaskRowOffset {
		t.Fatalf("MaskRowOffset mismatch: got %d want %d", restored.MaskRowOffset, ctx.proof.MaskRowOffset)
	}
	if restored.MaskRowCount != ctx.proof.MaskRowCount {
		t.Fatalf("MaskRowCount mismatch: got %d want %d", restored.MaskRowCount, ctx.proof.MaskRowCount)
	}
	if restored.MaskDegreeBound != ctx.proof.MaskDegreeBound {
		t.Fatalf("MaskDegreeBound mismatch: got %d want %d", restored.MaskDegreeBound, ctx.proof.MaskDegreeBound)
	}
	if !reflect.DeepEqual(restored.Gamma, ctx.proof.Gamma) {
		t.Fatalf("Gamma mismatch after restore")
	}
	if !reflect.DeepEqual(restored.GammaK, ctx.proof.GammaK) {
		t.Fatalf("GammaK mismatch after restore")
	}
	if restored.RoundCounters != ctx.proof.RoundCounters {
		t.Fatalf("RoundCounters mismatch: got %v want %v", restored.RoundCounters, ctx.proof.RoundCounters)
	}
	okLinRT, okEq4RT, okSumRT, err := VerifyNIZK(restored)
	if err != nil {
		t.Fatalf("VerifyNIZK on restored proof failed: %v", err)
	}
	if !(okLinRT && okEq4RT && okSumRT) {
		t.Fatalf("VerifyNIZK on restored proof rejected: lin=%v eq4=%v sum=%v", okLinRT, okEq4RT, okSumRT)
	}
}

func TestMergedLayoutMetadata(t *testing.T) {
	opts := secureSimOpts()
	ctx, okLin, okEq4, okSum := buildSimWith(t, opts)
	if ctx == nil {
		t.Fatalf("expected simulation context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline run rejected: lin=%v eq4=%v sum=%v", okLin, okEq4, okSum)
	}
	if ctx.proof.MaskRowOffset <= 0 {
		t.Fatalf("expected positive MaskRowOffset, got %d", ctx.proof.MaskRowOffset)
	}
	if ctx.proof.MaskRowCount <= 0 {
		t.Fatalf("expected positive MaskRowCount, got %d", ctx.proof.MaskRowCount)
	}
	if ctx.maskRowOffset != ctx.proof.MaskRowOffset {
		t.Fatalf("ctx.maskRowOffset mismatch: got %d want %d", ctx.maskRowOffset, ctx.proof.MaskRowOffset)
	}
	if ctx.maskRowCount != ctx.proof.MaskRowCount {
		t.Fatalf("ctx.maskRowCount mismatch: got %d want %d", ctx.maskRowCount, ctx.proof.MaskRowCount)
	}
	if ctx.maskDegreeBound != ctx.proof.MaskDegreeBound {
		t.Fatalf("mask degree bound mismatch: ctx=%d proof=%d", ctx.maskDegreeBound, ctx.proof.MaskDegreeBound)
	}
	if ctx.maskDegreeBound == 0 {
		t.Fatalf("expected non-zero MaskDegreeBound")
	}
	assertMaskInvariants(t, ctx)
	if len(ctx.proof.VTargetsMatrix()) == 0 {
		t.Fatalf("expected non-empty VTargets matrix")
	}
	expectedVT := computeVTargets(ctx.q, ctx.rows, ctx.proof.CoeffMatrix)
	if !reflect.DeepEqual(expectedVT, ctx.proof.VTargetsMatrix()) {
		t.Fatalf("VTargets mismatch with recomputation")
	}
	barSets := ctx.proof.BarSetsMatrix()
	if len(barSets) == 0 {
		t.Fatalf("expected non-empty BarSets matrix")
	}
	if ctx.barSets == nil || !reflect.DeepEqual(barSets, ctx.barSets) {
		t.Fatalf("BarSets mismatch: proof=%v ctx=%v", barSets, ctx.barSets)
	}
}

func TestMergedLayoutProofSnapshot(t *testing.T) {
	ctx, okLin, okEq4, okSum := buildSimWith(t, secureSimOpts())
	if ctx == nil {
		t.Fatalf("expected simulation context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline run rejected: lin=%v eq4=%v sum=%v", okLin, okEq4, okSum)
	}
	snapshot := ctx.proof.Snapshot()
	if snapshot.MaskRowOffset != ctx.proof.MaskRowOffset {
		t.Fatalf("MaskRowOffset mismatch: snapshot=%d proof=%d", snapshot.MaskRowOffset, ctx.proof.MaskRowOffset)
	}
	if snapshot.MaskRowCount != ctx.proof.MaskRowCount {
		t.Fatalf("MaskRowCount mismatch: snapshot=%d proof=%d", snapshot.MaskRowCount, ctx.proof.MaskRowCount)
	}
	if snapshot.MaskDegreeBound != ctx.proof.MaskDegreeBound {
		t.Fatalf("MaskDegreeBound mismatch: snapshot=%d proof=%d", snapshot.MaskDegreeBound, ctx.proof.MaskDegreeBound)
	}
	restored := snapshot.Restore()
	if restored.MaskRowOffset != ctx.proof.MaskRowOffset || restored.MaskRowCount != ctx.proof.MaskRowCount {
		t.Fatalf("restored mask metadata mismatch: offset=%d count=%d", restored.MaskRowOffset, restored.MaskRowCount)
	}
	okLinRT, okEq4RT, okSumRT, err := VerifyNIZK(restored)
	if err != nil {
		t.Fatalf("VerifyNIZK on restored proof failed: %v", err)
	}
	if !(okLinRT && okEq4RT && okSumRT) {
		t.Fatalf("VerifyNIZK on restored proof rejected: lin=%v eq4=%v sum=%v", okLinRT, okEq4RT, okSumRT)
	}
}

func TestVerifyNIZKSmallFieldRoundTrip(t *testing.T) {
	opts := secureSimOpts()
	opts.Theta = 3
	opts.Rho = 1
	opts.EllPrime = 1
	ctx, okLin, okEq4, okSum := buildSimWith(t, opts)
	if ctx == nil {
		t.Fatalf("expected simulation context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("small-field simulation rejected: lin=%v eq4=%v sum=%v", okLin, okEq4, okSum)
	}
	assertMaskInvariants(t, ctx)
	okLinBase, okEq4Base, okSumBase, err := VerifyNIZK(ctx.proof)
	if err != nil {
		t.Fatalf("VerifyNIZK on small-field proof failed: %v", err)
	}
	if !(okLinBase && okEq4Base && okSumBase) {
		t.Fatalf("VerifyNIZK on small-field proof rejected: lin=%v eq4=%v sum=%v", okLinBase, okEq4Base, okSumBase)
	}
	snap := ctx.proof.Snapshot()
	restored := snap.Restore()
	okLinRT, okEq4RT, okSumRT, err := VerifyNIZK(restored)
	if err != nil {
		t.Fatalf("VerifyNIZK on restored small-field proof failed: %v", err)
	}
	if !(okLinRT && okEq4RT && okSumRT) {
		t.Fatalf("VerifyNIZK on restored small-field proof rejected: lin=%v eq4=%v sum=%v", okLinRT, okEq4RT, okSumRT)
	}
}

func TestMergedLayoutSmallFieldMaskRows(t *testing.T) {
	opts := secureSimOpts()
	opts.Theta = 3
	opts.Rho = 1
	opts.EllPrime = 1
	ctx, okLin, okEq4, okSum := buildSimWith(t, opts)
	if ctx == nil {
		t.Fatalf("expected context for small-field run")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("small-field run rejected: lin=%v eq4=%v sum=%v", okLin, okEq4, okSum)
	}
	if ctx.theta <= 1 {
		t.Fatalf("expected theta>1 for small-field test, got %d", ctx.theta)
	}
	assertMaskRowsMatch(t, ctx)
	assertMaskInvariants(t, ctx)
}

func linfChainFixtureWithVals(t *testing.T, vals []uint64, beta uint64) (*ring.Ring, []uint64, int, LinfChainAux, []*ring.Poly, error) {
	t.Helper()
	N := 128
	q := linfChainTestQ
	ringQ, err := ring.NewRing(N, []uint64{q})
	if err != nil {
		return nil, nil, 0, LinfChainAux{}, nil, fmt.Errorf("ring.NewRing: %w", err)
	}
	ell := 1
	omega := []uint64{1, 2, 3, 4}
	if err := checkOmega(omega, q); err != nil {
		return nil, nil, 0, LinfChainAux{}, nil, fmt.Errorf("omega invalid: %w", err)
	}
	if len(vals) != len(omega) {
		return nil, nil, 0, LinfChainAux{}, nil, fmt.Errorf("vals length %d != |omega|=%d", len(vals), len(omega))
	}
	spec := NewLinfChainSpec(q, linfChainWindowBits, linfChainDigits, ell, beta)
	for _, v := range vals {
		if v > spec.MaxAbs {
			return nil, nil, 0, LinfChainAux{}, nil, fmt.Errorf("value %d exceeds linf-chain bound %d", v, spec.MaxAbs)
		}
	}
	P0 := buildValueRow(ringQ, vals, omega, ell)
	w1 := []*ring.Poly{P0}
	newW1, _, aux, err := makeNormConstraintsLinfChain(ringQ, q, omega, ell, 1, w1, beta, linfChainWindowBits, linfChainDigits, nil)
	if err != nil {
		return nil, nil, 0, LinfChainAux{}, nil, err
	}
	return ringQ, omega, ell, aux, newW1[:1], nil
}

func linfChainFixture(t *testing.T) (*ring.Ring, []uint64, int, LinfChainAux, []*ring.Poly) {
	vals := []uint64{10, 42, 128, 256}
	ringQ, omega, ell, aux, rows, err := linfChainFixtureWithVals(t, vals, 6000)
	if err != nil {
		t.Fatalf("linfChainFixture: %v", err)
	}
	return ringQ, omega, ell, aux, rows
}

func TestLinfChainMembership(t *testing.T) {
	ringQ, omega, ell, aux, P := linfChainFixture(t)
	cd := aux.Rows
	baseline := buildFparLinfChain(ringQ, P, cd, aux.Spec)
	for i, poly := range baseline {
		for _, w := range omega {
			if evalAt(ringQ, poly, w) != 0 {
				digitIdx := i - 2
				coeffDigit := ringQ.NewPoly()
				if digitIdx >= 0 && digitIdx < len(cd.D[0]) {
					ringQ.InvNTT(cd.D[0][digitIdx], coeffDigit)
					evalDigit := EvalPoly(coeffDigit.Coeffs[0], w%ringQ.Modulus[0], ringQ.Modulus[0])
					expected := EvalPoly(aux.Spec.PDi[digitIdx], evalDigit, ringQ.Modulus[0])
					t.Fatalf("constraint %d non-zero before tamper: digit=%d eval=%d expected=%d", i, digitIdx, evalDigit, expected)
				}
				t.Fatalf("constraint %d non-zero before tamper", i)
			}
		}
	}
	digitIdx := aux.Spec.L - 1
	tamperVal := uint64(aux.Spec.DMax[digitIdx]+1) % ringQ.Modulus[0]
	setRowValue(ringQ, omega, ell, cd.D[0][digitIdx], 0, tamperVal)
	tampered := buildFparLinfChain(ringQ, P, cd, aux.Spec)
	memConstraintIdx := 2 + digitIdx
	if evalAt(ringQ, tampered[memConstraintIdx], omega[0]) == 0 {
		t.Fatalf("membership polynomial should detect D%d outside range", digitIdx)
	}
}

func TestRangeMembershipMessageDetectsTamper(t *testing.T) {
	ctx, okLin, okEq4, okSum := buildSimWith(t, defaultSimOpts())
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline simulation rejected: OkLin=%v OkEq4=%v OkSum=%v", okLin, okEq4, okSum)
	}
	spec := ctx.rangeSpec
	if ctx.proof.RowLayout.MsgCount == 0 {
		t.Skip("no message rows in layout")
	}
	uStart := ctx.proof.RowLayout.SigCount
	uEnd := uStart + ctx.proof.RowLayout.MsgCount
	source := ctx.msgSource
	if len(source) == 0 {
		source = ctx.w1[uStart:uEnd]
	}
	sourceCopy := clonePolySlice(source)
	baseline := buildFparRangeMembership(ctx.ringQ, sourceCopy, spec)
	for idx, poly := range baseline {
		if poly == nil {
			t.Fatalf("baseline membership polynomial %d is nil", idx)
		}
		zero := ctx.ringQ.NewPoly()
		ctx.ringQ.InvNTT(poly, zero)
		for cIdx, coeff := range zero.Coeffs[0] {
			if coeff%ctx.q != 0 {
				t.Fatalf("baseline message membership coefficient[%d][%d]=%d", idx, cIdx, coeff%ctx.q)
			}
		}
	}
	tamperSource := clonePolySlice(source)
	if len(tamperSource) == 0 {
		t.Fatalf("no message polynomials to tamper")
	}
	coeff := ctx.ringQ.NewPoly()
	ctx.ringQ.InvNTT(tamperSource[0], coeff)
	coeff.Coeffs[0][0] = liftIntToField(ctx.q, int64(spec.B+1))
	ctx.ringQ.NTT(coeff, coeff)
	tamperSource[0] = coeff
	tampered := buildFparRangeMembership(ctx.ringQ, tamperSource, spec)
	if len(tampered) == 0 {
		t.Fatalf("expected membership constraints for message block")
	}
	viol := ctx.ringQ.NewPoly()
	ctx.ringQ.InvNTT(tampered[0], viol)
	allZero := true
	for _, v := range viol.Coeffs[0] {
		if v%ctx.q != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("message membership constraint remained zero after tamper")
	}
}

func TestRangeMembershipRandomBlockDetectsTamper(t *testing.T) {
	ctx, okLin, okEq4, okSum := buildSimWith(t, defaultSimOpts())
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline simulation rejected: OkLin=%v OkEq4=%v OkSum=%v", okLin, okEq4, okSum)
	}
	spec := ctx.rangeSpec
	if ctx.proof.RowLayout.RndCount == 0 {
		t.Skip("no randomness rows in layout")
	}
	x0Start := ctx.proof.RowLayout.SigCount + ctx.proof.RowLayout.MsgCount
	x0End := x0Start + ctx.proof.RowLayout.RndCount
	source := ctx.rndSource
	if len(source) == 0 {
		source = ctx.w1[x0Start:x0End]
	}
	sourceCopy := clonePolySlice(source)
	baseline := buildFparRangeMembership(ctx.ringQ, sourceCopy, spec)
	for idx, poly := range baseline {
		if poly == nil {
			t.Fatalf("baseline randomness membership polynomial %d is nil", idx)
		}
		zero := ctx.ringQ.NewPoly()
		ctx.ringQ.InvNTT(poly, zero)
		for cIdx, coeff := range zero.Coeffs[0] {
			if coeff%ctx.q != 0 {
				t.Fatalf("baseline randomness membership coefficient[%d][%d]=%d", idx, cIdx, coeff%ctx.q)
			}
		}
	}
	tamperSource := clonePolySlice(source)
	if len(tamperSource) == 0 {
		t.Fatalf("no randomness polynomials to tamper")
	}
	coeff := ctx.ringQ.NewPoly()
	ctx.ringQ.InvNTT(tamperSource[0], coeff)
	coeff.Coeffs[0][0] = liftIntToField(ctx.q, int64(spec.B+1))
	ctx.ringQ.NTT(coeff, coeff)
	tamperSource[0] = coeff
	tampered := buildFparRangeMembership(ctx.ringQ, tamperSource, spec)
	if len(tampered) == 0 {
		t.Fatalf("expected membership constraints for randomness block")
	}
	viol := ctx.ringQ.NewPoly()
	ctx.ringQ.InvNTT(tampered[0], viol)
	allZero := true
	for _, v := range viol.Coeffs[0] {
		if v%ctx.q != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("randomness membership constraint remained zero after tamper")
	}
}

func TestRangeMembershipX1DetectsTamper(t *testing.T) {
	ctx, okLin, okEq4, okSum := buildSimWith(t, defaultSimOpts())
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline simulation rejected: OkLin=%v OkEq4=%v OkSum=%v", okLin, okEq4, okSum)
	}
	spec := ctx.rangeSpec
	source := []*ring.Poly{ctx.w2.CopyNew()}
	baseline := buildFparRangeMembership(ctx.ringQ, source, spec)
	for _, poly := range baseline {
		zero := ctx.ringQ.NewPoly()
		ctx.ringQ.InvNTT(poly, zero)
		for cIdx, coeff := range zero.Coeffs[0] {
			if coeff%ctx.q != 0 {
				t.Fatalf("baseline x1 membership coefficient[%d]=%d", cIdx, coeff%ctx.q)
			}
		}
	}
	tamperPoly := ctx.w2.CopyNew()
	coeff := ctx.ringQ.NewPoly()
	ctx.ringQ.InvNTT(tamperPoly, coeff)
	coeff.Coeffs[0][0] = liftIntToField(ctx.q, int64(spec.B+1))
	ctx.ringQ.NTT(coeff, coeff)
	tampered := buildFparRangeMembership(ctx.ringQ, []*ring.Poly{coeff}, spec)
	if len(tampered) == 0 {
		t.Fatalf("expected membership constraint for x1")
	}
	viol := ctx.ringQ.NewPoly()
	ctx.ringQ.InvNTT(tampered[0], viol)
	allZero := true
	for _, coeff := range viol.Coeffs[0] {
		if coeff%ctx.q != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatalf("x1 membership constraint remained zero after tamper")
	}
}

func TestLinfChainAssembly(t *testing.T) {
	ringQ, omega, ell, aux, P := linfChainFixture(t)
	cd := aux.Rows
	baseline := buildFparLinfChain(ringQ, P, cd, aux.Spec)
	for i, poly := range baseline {
		for _, w := range omega {
			if evalAt(ringQ, poly, w) != 0 {
				t.Fatalf("constraint %d non-zero before tamper", i)
			}
		}
	}
	orig := evalAt(ringQ, cd.D[0][0], omega[0])
	setRowValue(ringQ, omega, ell, cd.D[0][0], 0, modAdd(orig, 1, ringQ.Modulus[0]))
	tampered := buildFparLinfChain(ringQ, P, cd, aux.Spec)
	if evalAt(ringQ, tampered[1], omega[0]) == 0 {
		t.Fatalf("assembly constraint should detect mismatched digits")
	}
}

func TestLinfChainTie(t *testing.T) {
	ringQ, omega, ell, aux, P := linfChainFixture(t)
	cd := aux.Rows
	baseline := buildFparLinfChain(ringQ, P, cd, aux.Spec)
	for i, poly := range baseline {
		for _, w := range omega {
			if evalAt(ringQ, poly, w) != 0 {
				t.Fatalf("constraint %d non-zero before tamper", i)
			}
		}
	}
	origM := evalAt(ringQ, cd.M[0], omega[0])
	origD0 := evalAt(ringQ, cd.D[0][0], omega[0])
	setRowValue(ringQ, omega, ell, cd.M[0], 0, modAdd(origM, 1, ringQ.Modulus[0]))
	setRowValue(ringQ, omega, ell, cd.D[0][0], 0, modAdd(origD0, 1, ringQ.Modulus[0]))
	tampered := buildFparLinfChain(ringQ, P, cd, aux.Spec)
	if evalAt(ringQ, tampered[0], omega[0]) == 0 {
		t.Fatalf("tie constraint should detect mismatched magnitude vs witness")
	}
}

func TestLinfChainUpperEdgeInlier(t *testing.T) {
	beta := uint64(10000)
	q := linfChainTestQ
	spec := NewLinfChainSpec(q, linfChainWindowBits, linfChainDigits, 1, beta)
	top := spec.MaxAbs % q
	vals := []uint64{top, 0, 0, 0}
	ringQ, omega, _, aux, P, err := linfChainFixtureWithVals(t, vals, beta)
	if err != nil {
		t.Fatalf("upper-edge inlier rejected: %v", err)
	}
	baseline := buildFparLinfChain(ringQ, P, aux.Rows, aux.Spec)
	for i, poly := range baseline {
		for _, w := range omega {
			if evalAt(ringQ, poly, w) != 0 {
				t.Fatalf("constraint %d non-zero at upper edge", i)
			}
		}
	}
}

func TestLinfChainJustOverBoundFails(t *testing.T) {
	beta := uint64(10000)
	q := linfChainTestQ
	spec := NewLinfChainSpec(q, linfChainWindowBits, linfChainDigits, 1, beta)
	over := spec.MaxAbs + 1
	_, _, _, _, _, err := linfChainFixtureWithVals(t, []uint64{over, 0, 0, 0}, beta)
	if err == nil {
		t.Fatalf("expected failure for value %d above bound", over)
	}
}

func TestLinfChainRandomSoak(t *testing.T) {
	beta := uint64(10000)
	q := linfChainTestQ
	spec := NewLinfChainSpec(q, linfChainWindowBits, linfChainDigits, 1, beta)
	top := spec.MaxAbs
	rnd := mrand.New(mrand.NewSource(42))
	for i := 0; i < 64; i++ {
		val := uint64(rnd.Int63n(int64(top) + 1))
		if _, _, _, _, _, err := linfChainFixtureWithVals(t, []uint64{val, 0, 0, 0}, beta); err != nil {
			t.Fatalf("soak iteration %d failed for val=%d: %v", i, val, err)
		}
	}
}

func TestVerifierRejectsTightLinfBound(t *testing.T) {
	ctx, okLin, okEq4, okSum := buildSimWith(t, secureSimOpts())
	if ctx == nil {
		t.Skip("simulation context unavailable")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline verification failed: okLin=%v okEq4=%v okSum=%v", okLin, okEq4, okSum)
	}
	betaTight := uint64(3000)
	mSig := ctx.origW1Len - len(ctx.B0m) - len(ctx.B0r)
	if mSig <= 0 {
		t.Fatalf("unexpected mSig=%d", mSig)
	}
	specTight := NewLinfChainSpec(ctx.q, linfChainWindowBits, linfChainDigits, ctx.ell, betaTight)
	cd := ChainDecomp{
		M: make([]*ring.Poly, mSig),
		D: make([][]*ring.Poly, mSig),
	}
	rowBase := ctx.proof.RowLayout.ChainBase
	rowsPerSig := ctx.proof.RowLayout.ChainRowsPerSig
	if rowsPerSig < 1 {
		t.Fatalf("invalid chain rows per signature: %d", rowsPerSig)
	}
	digitCount := rowsPerSig - 1
	for tIdx := 0; tIdx < mSig; tIdx++ {
		base := rowBase + rowsPerSig*tIdx
		if base+rowsPerSig-1 >= len(ctx.w1) {
			t.Fatalf("insufficient chain rows for index %d", tIdx)
		}
		cd.M[tIdx] = ctx.w1[base]
		cd.D[tIdx] = make([]*ring.Poly, digitCount)
		for j := 0; j < digitCount; j++ {
			cd.D[tIdx][j] = ctx.w1[base+1+j]
		}
	}
	tightFpar := buildFparLinfChain(ctx.ringQ, ctx.w1[:mSig], cd, specTight)
	foundViolation := false
	for i := 0; i < len(tightFpar); i++ {
		for _, w := range ctx.omega {
			if evalAt(ctx.ringQ, tightFpar[i], w) != 0 {
				foundViolation = true
				break
			}
		}
		if foundViolation {
			break
		}
	}
	if !foundViolation {
		t.Skip("witness already satisfies tighter β∞=3000 bound; cannot exercise verifier rejection")
	}
	normLen := len(tightFpar)
	normStart := len(ctx.Fpar) - normLen
	if normStart < 0 {
		t.Fatalf("norm constraint length mismatch: total=%d norm=%d", len(ctx.Fpar), normLen)
	}
	tamperedFpar := append([]*ring.Poly(nil), ctx.Fpar...)
	copy(tamperedFpar[normStart:], tightFpar)
	if checkEq4OnOpening(ctx.ringQ, ctx.Q, ctx.M, ctx.maskOpen, tamperedFpar, ctx.Fagg, ctx.GammaPrimePoly, ctx.GammaPrimeScalars, ctx.omega, ctx.Eprime) {
		t.Fatalf("Eq.(4) verifier accepted chain with tightened β∞=%d", betaTight)
	}
}

func TestPACS_Integer_Alignment(t *testing.T) {
	ctx, okLin, okEq4, okSum := buildSimWith(t, secureSimOpts())
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline simulation failed: OkLin=%v OkEq4=%v OkSum=%v", okLin, okEq4, okSum)
	}
	for i := range ctx.w3[0].Coeffs[0] {
		ctx.w3[0].Coeffs[0][i] = 0
	}
	prod := makeProductConstraint(ctx.ringQ, ctx.w1[0], ctx.w2, ctx.w3[0])
	if evalAt(ctx.ringQ, prod, ctx.omega[0]) == 0 {
		t.Fatalf("expected product constraint to detect tampered w3")
	}
}

func TestPACSTampering(t *testing.T) {
	t.Run("LVCS/linear-map: tamper bar", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		ctx.bar[0][0] = (ctx.bar[0][0] + 1) % ctx.q
		if ctx.vrf.EvalStep2(ctx.bar, ctx.E, ctx.combinedOpen, ctx.C, ctx.vTargets) {
			t.Fatalf("expected LVCS linear-map check to fail")
		}
	})
	t.Run("LVCS/tail-only: reject head index in E", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		Ehead := append([]int(nil), ctx.E...)
		Ehead[0] = 0
		openHeadTail := lvcs.EvalFinish(ctx.pk, Ehead)
		combinedHead := combineOpenings(ctx.open.DECSOpen, openHeadTail.DECSOpen)
		if ctx.vrf.EvalStep2(ctx.bar, Ehead, combinedHead, ctx.C, ctx.vTargets) {
			t.Fatalf("expected EvalStep2 to reject head index")
		}
	})
	t.Run("LVCS/tail-only: reject randomness-support index", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		Erand := append([]int(nil), ctx.E...)
		Erand[0] = ctx.maskIdx[0]
		openRandTail := lvcs.EvalFinish(ctx.pk, Erand)
		combinedRand := combineOpenings(ctx.open.DECSOpen, openRandTail.DECSOpen)
		if ctx.vrf.EvalStep2(ctx.bar, Erand, combinedRand, ctx.C, ctx.vTargets) {
			t.Fatalf("expected EvalStep2 to reject randomness-slot index in E")
		}
	})
	t.Run("LVCS/binding: mismatch between E and open.Indices", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		bad := deepCopyOpen(ctx.combinedOpen)
		allIdx := bad.AllIndices()
		switch {
		case len(allIdx) == 0:
			t.Fatalf("opening has no indices to tamper")
		case len(allIdx) > bad.MaskCount:
			tail := append([]int(nil), allIdx[bad.MaskCount:]...)
			tail[0]++
			bad.Indices = tail
			bad.IndexBits = nil
			bad.TailCount = len(tail)
		default:
			bad.MaskBase++
		}
		if ctx.vrf.EvalStep2(ctx.bar, ctx.E, bad, ctx.C, ctx.vTargets) {
			t.Fatalf("expected EvalStep2 to reject mismatched E vs open.Indices")
		}
	})
	t.Run("DECS/Merkle: tamper Pvals in opening", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		bad := deepCopyOpen(ctx.combinedOpen)
		bad.Pvals[0][0] = (bad.Pvals[0][0] + 1) % ctx.q
		if ctx.vrf.EvalStep2(ctx.bar, ctx.E, bad, ctx.C, ctx.vTargets) {
			t.Fatalf("expected Merkle/masked check to fail")
		}
	})
	t.Run("DECS/Merkle: tamper Merkle path bytes", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		if len(ctx.combinedOpen.Nodes) == 0 {
			t.Skip("no nodes to tamper")
		}
		bad := deepCopyOpen(ctx.combinedOpen)
		bad.Nodes[0][0] ^= 0x01
		if ctx.vrf.EvalStep2(ctx.bar, ctx.E, bad, ctx.C, ctx.vTargets) {
			t.Fatalf("expected Merkle verification to fail")
		}
	})
	t.Run("Eq4: tamper Q", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		bumpConst(ctx.ringQ, ctx.Q[0], ctx.q)
		ok := checkEq4OnOpening(ctx.ringQ, ctx.Q, ctx.M, ctx.open, ctx.Fpar, ctx.Fagg, ctx.GammaPrimePoly, ctx.gammaP, ctx.omega, ctx.Eprime)
		if ok {
			t.Fatalf("expected Eq.(4) check to fail")
		}
	})
	t.Run("Eq4: tamper gammaPrime", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		ctx.gammaP[0][0] = (ctx.gammaP[0][0] + 1) % ctx.q
		ok := checkEq4OnOpening(ctx.ringQ, ctx.Q, ctx.M, ctx.open, ctx.Fpar, ctx.Fagg, ctx.GammaPrimePoly, ctx.gammaP, ctx.omega, ctx.Eprime)
		if ok {
			t.Fatalf("expected Eq.(4) check to fail")
		}
	})
	t.Run("SumΩ: tamper Q constant", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		bumpConst(ctx.ringQ, ctx.Q[0], ctx.q)
		if VerifyQ(ctx.ringQ, ctx.Q, ctx.omega) {
			t.Fatalf("expected ΣΩ check to fail")
		}
	})
	t.Run("LVCS/degree: tamper R_k degree", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		if ctx.ringQ.N-1 <= decs.DefaultParams.Degree {
			t.Skip("ring dimension too small to exceed degree bound")
		}
		R := make([]*ring.Poly, len(ctx.vrf.R))
		for i, p := range ctx.vrf.R {
			R[i] = p.CopyNew()
		}
		coeff := ctx.ringQ.NewPoly()
		ctx.ringQ.InvNTT(R[0], coeff)
		idx := decs.DefaultParams.Degree + 1
		coeff.Coeffs[0][idx] = (coeff.Coeffs[0][idx] + 1) % ctx.q
		ctx.ringQ.NTT(coeff, R[0])
		if ctx.vrf.CommitStep2(R) {
			t.Fatalf("expected degree bound to fail")
		}
	})
	t.Run("FullPACS: w3 != w1*w2", func(t *testing.T) {
		ctx, _, _, _ := buildSim(t)
		bumpConst(ctx.ringQ, ctx.w3[0], ctx.q)
		if VerifyFullPACS(ctx.ringQ, ctx.w1, ctx.w2, ctx.w3, ctx.A, ctx.b1, ctx.B0c, ctx.B0m, ctx.B0r) {
			t.Fatalf("expected FullPACS to fail on w3≠w1·w2")
		}
	})
}

func TestPACSParamGrid(t *testing.T) {
	cases := []SimOpts{secureSimOpts()}
	for i, o := range cases {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			_, okLin, okEq4, okSum := buildSimWith(t, o)
			if !(okLin && okEq4 && okSum) {
				t.Fatalf("verifier rejected for opts %+v", o)
			}
		})
	}
}

func TestEq4TamperMaskOnly(t *testing.T) {
	ctx, _, _, _ := buildSim(t)
	bumpConst(ctx.ringQ, ctx.M[0], ctx.q)
	if checkEq4OnOpening(ctx.ringQ, ctx.Q, ctx.M, ctx.open, ctx.Fpar, ctx.Fagg, ctx.GammaPrimePoly, ctx.gammaP, ctx.omega, ctx.Eprime) {
		t.Fatalf("Eq.(4) should fail when M is tampered")
	}
}

func TestOmegaRejectsDuplicates(t *testing.T) {
	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
	if err != nil {
		t.Skip("missing parameters: " + err.Error())
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		t.Fatalf("ring.NewRing: %v", err)
	}
	q := ringQ.Modulus[0]
	omega := []uint64{1 % q, 2 % q, 1 % q}
	if err := checkOmega(omega, q); err == nil {
		t.Fatalf("checkOmega must reject duplicates")
	}
}

func TestPACSDeterminism(t *testing.T) {
	_, a1, b1, c1 := buildSim(t)
	_, a2, b2, c2 := buildSim(t)
	if a1 != a2 || b1 != b2 || c1 != c2 {
		t.Fatalf("verdicts changed")
	}
}

func BenchmarkBuildSim(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buildSimWith(nil, secureSimOpts())
	}
}

func TestSmallFieldRowLayoutAndQueries(t *testing.T) {
	opts := defaultSimOpts()
	opts.Theta = 3
	opts.EllPrime = 1
	opts.Rho = 1
	ctx, okLin, okEq4, okSum := buildSimWith(t, opts)
	if ctx == nil {
		t.Fatalf("buildSimWith returned nil context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("verifier rejected in small-field mode: lin=%v eq4=%v sum=%v", okLin, okEq4, okSum)
	}
	assertMaskInvariants(t, ctx)
	if ctx.pk == nil {
		t.Fatalf("nil prover key")
	}
	layerSize := len(ctx.omega) + opts.Theta
	witnessRows := ctx.maskRowOffset
	if witnessRows <= 0 {
		t.Fatalf("expected positive maskRowOffset")
	}
	if ctx.maskRowOffset+ctx.maskRowCount != len(ctx.pk.Rows) {
		t.Fatalf("mask rows mismatch: offset=%d count=%d total=%d", ctx.maskRowOffset, ctx.maskRowCount, len(ctx.pk.Rows))
	}
	if witnessRows%layerSize != 0 {
		t.Fatalf("witness rows %d not a multiple of layer size %d", witnessRows, layerSize)
	}
	if got := len(ctx.EvalReqs); got != opts.Theta {
		t.Fatalf("unexpected eval request count: got %d want %d", got, opts.Theta)
	}
	if len(ctx.KPoint) != 1 {
		t.Fatalf("expected a single stored K-point, got %d", len(ctx.KPoint))
	}
	if ctx.theta != opts.Theta {
		t.Fatalf("ctx.theta mismatch: got %d want %d", ctx.theta, opts.Theta)
	}
	if len(ctx.chi) != ctx.theta+1 {
		t.Fatalf("chi length mismatch: got %d want %d", len(ctx.chi), ctx.theta+1)
	}
	if len(ctx.zeta) != ctx.theta {
		t.Fatalf("zeta limb count mismatch: got %d want %d", len(ctx.zeta), ctx.theta)
	}
}

func TestSmallFieldCoefficientMismatchDetection(t *testing.T) {
	opts := defaultSimOpts()
	opts.Theta = 3
	opts.EllPrime = 1
	opts.Rho = 1
	ctx, okLin, okEq4, okSum := buildSimWith(t, opts)
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("verifier rejected baseline small-field run")
	}
	if ctx.theta <= 1 {
		t.Fatalf("test requires theta>1")
	}
	assertMaskInvariants(t, ctx)
	K, err := kf.New(ctx.q, ctx.theta, ctx.chi)
	if err != nil {
		t.Fatalf("kfield.New: %v", err)
	}
	zeta := K.Phi(ctx.zeta)
	elem := K.Phi(ctx.KPoint[0])
	muInv := computeMuDenomInv(K, ctx.omega, zeta)
	expected := buildKPointCoeffMatrix(ctx.ringQ, K, ctx.omega, ctx.rows, elem, muInv, ctx.maskRowOffset, ctx.maskRowCount)
	if !matrixEqual(ctx.CoeffMatrix, expected) {
		t.Fatalf("expected coefficient matrix mismatch")
	}
	tampered := copyMatrix(ctx.CoeffMatrix)
	tampered[0][0] = (tampered[0][0] + 1) % ctx.q
	if matrixEqual(tampered, expected) {
		t.Fatalf("tampering with coefficient matrix went undetected")
	}
}

func TestPACSMaskOpeningTamper(t *testing.T) {
	ctx, okLin, okEq4, okSum := buildSimWith(t, secureSimOpts())
	if ctx == nil {
		t.Fatalf("expected simulation context")
	}
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline PACS run rejected: lin=%v eq4=%v sum=%v", okLin, okEq4, okSum)
	}
	snapshot := ctx.proof.Snapshot()
	tampered := snapshot.Restore()
	open := expandPackedOpening(tampered.MOpening)
	if open == nil || len(open.Pvals) == 0 || len(open.Pvals[0]) == 0 {
		t.Skip("no mask opening values to tamper")
	}
	open.Pvals[0][0] = (open.Pvals[0][0] + 1) % ctx.q
	tampered.MOpening = cloneDECSOpening(open)
	okLinBase, okEq4Base, okSumBase, err := VerifyNIZK(tampered)
	if err == nil && okLinBase && okEq4Base && okSumBase {
		t.Fatalf("VerifyNIZK should reject tampered mask opening")
	}
}
