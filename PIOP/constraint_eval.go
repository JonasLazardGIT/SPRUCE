package PIOP

import (
	"fmt"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// EvalInput bundles the material needed to replay Eq.(4) on explicit
// evaluations. Matrices are stored row-major: |EvalPoints| rows, varying
// number of columns (rows/masks/Q etc.).
type EvalInput struct {
	EvalPoints []uint64
	Pvals      [][]uint64
	MaskVals   [][]uint64
	Q          []*ring.Poly
	GammaPrime [][]uint64
	GammaAgg   [][]uint64
	Ring       *ring.Ring
	Omega      []uint64
}

// EvalKInput bundles the K-point material needed to replay Eq.(4) in θ>1 mode.
// RowEvals, if provided, should be a |K'| x (witnessCount*theta) matrix of row
// evaluations at each K-point. If absent, VTargets is used to reconstruct rows.
type EvalKInput struct {
	K            *kf.Field
	KPoints      [][]uint64
	RowEvals     [][]uint64
	VTargets     [][]uint64
	QK           []*KPoly
	MK           []*KPoly
	GammaPrimeK  [][]KScalar
	GammaAggK    [][]KScalar
	WitnessCount int
	Ring         *ring.Ring
	Fpar         []*ring.Poly
	Fagg         []*ring.Poly
	FparOverrideIdxs []int
	BoundRows    []int
	CarryRows    []int
	BoundB       int64
	CarryBound   int64
}

// EvalTailInput bundles the tail-opening material needed to replay Eq.(4)
// using a constraint evaluator on row openings.
type EvalTailInput struct {
	Tail     []int
	RowOpen  *decs.DECSOpening
	MaskOpen *decs.DECSOpening
	Q        []*ring.Poly
	GammaPrime [][]uint64
	GammaAgg   [][]uint64
	Ring       *ring.Ring
	RowCount   int
}

// ConstraintEvaluator evaluates all constraint residuals at the provided
// evaluation point (indexed into EvalPoints) using the row values observed
// at that point. It returns the parallel and aggregated residual slices.
type ConstraintEvaluator func(evalIdx uint64, rowVals []uint64) (fpar []uint64, fagg []uint64, err error)

// KConstraintEvaluator evaluates constraints at a K-point using row evaluations
// in K. It returns residuals in K, matching the θ>1 Eq.(4) replay.
type KConstraintEvaluator func(e kf.Elem, rowVals []kf.Elem) (fpar []kf.Elem, fagg []kf.Elem, err error)

// ConstraintReplay bundles evaluator hooks for verifier-side Eq.(4) replay.
// When provided to the verifier, precomputed F-polys are ignored and residuals
// are recomputed directly from row openings.
type ConstraintReplay struct {
	Eval     ConstraintEvaluator
	EvalK    KConstraintEvaluator
	RowCount int
	BoundRows  []int
	CarryRows  []int
	BoundB     int64
	CarryBound int64
}

func composeEvaluators(a, b ConstraintEvaluator) ConstraintEvaluator {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		fparA, faggA, err := a(evalIdx, rows)
		if err != nil {
			return nil, nil, err
		}
		fparB, faggB, err := b(evalIdx, rows)
		if err != nil {
			return nil, nil, err
		}
		fpar := append(append([]uint64{}, fparA...), fparB...)
		fagg := append(append([]uint64{}, faggA...), faggB...)
		return fpar, fagg, nil
	}
}

func composeKEvaluators(a, b KConstraintEvaluator) KConstraintEvaluator {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		fparA, faggA, err := a(e, rows)
		if err != nil {
			return nil, nil, err
		}
		fparB, faggB, err := b(e, rows)
		if err != nil {
			return nil, nil, err
		}
		fpar := append(append([]kf.Elem{}, fparA...), fparB...)
		fagg := append(append([]kf.Elem{}, faggA...), faggB...)
		return fpar, fagg, nil
	}
}

// EvaluateConstraintsOnEvals replays Eq.(4) on the supplied evaluations using
// the provided constraint evaluator. This is a theta==1 helper; the caller
// should ensure EvalPoints map directly to indices into Q/Mask polys.
func EvaluateConstraintsOnEvals(eval ConstraintEvaluator, in EvalInput) (bool, error) {
	if eval == nil {
		return false, fmt.Errorf("nil evaluator")
	}
	if in.Ring == nil {
		return false, fmt.Errorf("nil ring")
	}
	if len(in.EvalPoints) == 0 {
		return false, fmt.Errorf("no eval points")
	}
	q := in.Ring.Modulus[0]
	rho := len(in.Q)
	if rho == 0 {
		return false, fmt.Errorf("no Q polynomials")
	}
	for col, idx := range in.EvalPoints {
		if col >= len(in.Pvals) {
			return false, fmt.Errorf("missing Pvals row %d", col)
		}
		if col >= len(in.MaskVals) && len(in.MaskVals) > 0 {
			return false, fmt.Errorf("missing MaskVals row %d", col)
		}
		rowVals := in.Pvals[col]
		fpar, fagg, err := eval(idx, rowVals)
		if err != nil {
			return false, err
		}
		for i := 0; i < rho; i++ {
			if i >= len(in.Q) || in.Q[i] == nil || int(idx) >= len(in.Q[i].Coeffs[0]) {
				return false, fmt.Errorf("invalid Q at i=%d idx=%d", i, idx)
			}
			lhs := in.Q[i].Coeffs[0][idx] % q
			var rhs uint64
			if i < len(in.MaskVals) && col < len(in.MaskVals[i]) {
				rhs = in.MaskVals[i][col] % q
			}
			if i < len(in.GammaPrime) {
				rowGamma := in.GammaPrime[i]
				for j, val := range fpar {
					if j >= len(rowGamma) {
						continue
					}
					rhs = lvcs.MulAddMod64(rhs, rowGamma[j]%q, val%q, q)
				}
			}
			if i < len(in.GammaAgg) {
				rowGamma := in.GammaAgg[i]
				for j, val := range fagg {
					if j >= len(rowGamma) {
						continue
					}
					rhs = lvcs.MulAddMod64(rhs, rowGamma[j]%q, val%q, q)
				}
			}
			if lhs != rhs {
				return false, fmt.Errorf("eq4 replay mismatch at eval %d (idx=%d) row %d: lhs=%d rhs=%d", col, idx, i, lhs, rhs)
			}
		}
	}
	return true, nil
}

// EvaluateConstraintsOnKPoints replays Eq.(4) at K-points using row values
// reconstructed from VTargets and the provided constraint evaluator.
func EvaluateConstraintsOnKPoints(eval KConstraintEvaluator, in EvalKInput) (bool, error) {
	if eval == nil {
		return false, fmt.Errorf("nil K evaluator")
	}
	if in.K == nil {
		return false, fmt.Errorf("nil K field")
	}
	if len(in.KPoints) == 0 {
		return false, fmt.Errorf("no K points")
	}
	if in.WitnessCount <= 0 {
		return false, fmt.Errorf("invalid witness count")
	}
	if len(in.QK) == 0 || len(in.MK) == 0 {
		return false, fmt.Errorf("missing QK/MK")
	}
	rho := len(in.QK)
	for kpIdx, limbs := range in.KPoints {
		e := in.K.Phi(limbs)
		var rowVals []kf.Elem
		var err error
		if len(in.RowEvals) > 0 {
			rowVals, err = buildRowValsFromKEvals(in.K, in.RowEvals, kpIdx, in.WitnessCount)
		} else {
			if len(in.VTargets) == 0 || len(in.VTargets[0]) == 0 {
				return false, fmt.Errorf("missing VTargets for K replay")
			}
			if in.WitnessCount > len(in.VTargets[0]) {
				return false, fmt.Errorf("vTargets cols %d < witness count %d", len(in.VTargets[0]), in.WitnessCount)
			}
			rowVals, err = buildRowValsFromVTargets(in.K, in.VTargets, kpIdx, in.WitnessCount)
		}
		if err != nil {
			return false, err
		}
		fpar, fagg, err := eval(e, rowVals)
		if err != nil {
			return false, err
		}
		if len(in.FparOverrideIdxs) > 0 && in.Ring != nil && len(in.Fpar) > 0 {
			tmp := in.Ring.NewPoly()
			for _, idx := range in.FparOverrideIdxs {
				if idx < 0 || idx >= len(fpar) || idx >= len(in.Fpar) || in.Fpar[idx] == nil {
					continue
				}
				in.Ring.InvNTT(in.Fpar[idx], tmp)
				fpar[idx] = in.K.EvalFPolyAtK(tmp.Coeffs[0], e)
			}
		}
		for i := 0; i < rho; i++ {
			if i >= len(in.MK) || in.QK[i] == nil || in.MK[i] == nil {
				return false, fmt.Errorf("missing K polys at row %d", i)
			}
			lhs := evalKPolyAtK(in.K, in.QK[i], e)
			rhs := evalKPolyAtK(in.K, in.MK[i], e)
			if i < len(in.GammaPrimeK) {
				rowGamma := in.GammaPrimeK[i]
				for j, val := range fpar {
					if j >= len(rowGamma) {
						continue
					}
					g := in.K.Phi(rowGamma[j])
					rhs = in.K.Add(rhs, in.K.Mul(g, val))
				}
			}
			if i < len(in.GammaAggK) {
				rowGamma := in.GammaAggK[i]
				for j, val := range fagg {
					if j >= len(rowGamma) {
						continue
					}
					g := in.K.Phi(rowGamma[j])
					rhs = in.K.Add(rhs, in.K.Mul(g, val))
				}
			}
			if !elemEqual(in.K, lhs, rhs) {
				return false, fmt.Errorf("eq4 K-point mismatch at kp=%d row=%d", kpIdx, i)
			}
		}
	}
	return true, nil
}

// EvaluateConstraintsOnTailOpen replays Eq.(4) at the tail indices using row
// openings and a constraint evaluator. It uses mask evaluations from MaskOpen.
func EvaluateConstraintsOnTailOpen(eval ConstraintEvaluator, in EvalTailInput) (bool, error) {
	if eval == nil {
		return false, fmt.Errorf("nil evaluator")
	}
	if in.Ring == nil {
		return false, fmt.Errorf("nil ring")
	}
	if in.RowOpen == nil {
		return false, fmt.Errorf("nil row opening")
	}
	if in.MaskOpen == nil {
		return false, fmt.Errorf("nil mask opening")
	}
	if len(in.Tail) == 0 {
		return false, fmt.Errorf("no tail indices")
	}
	if len(in.Q) == 0 {
		return false, fmt.Errorf("no Q polynomials")
	}
	q := in.Ring.Modulus[0]
	N := int(in.Ring.N)
	rowCount := in.RowCount
	if rowCount <= 0 {
		if in.RowOpen.R > 0 {
			rowCount = in.RowOpen.R
		} else if len(in.RowOpen.Pvals) > 0 {
			rowCount = len(in.RowOpen.Pvals[0])
		}
	}
	if rowCount <= 0 {
		return false, fmt.Errorf("invalid row count")
	}
	posByIdxRow := make(map[int]int, in.RowOpen.EntryCount())
	for pos := 0; pos < in.RowOpen.EntryCount(); pos++ {
		posByIdxRow[in.RowOpen.IndexAt(pos)] = pos
	}
	posByIdxMask := make(map[int]int, in.MaskOpen.EntryCount())
	for pos := 0; pos < in.MaskOpen.EntryCount(); pos++ {
		posByIdxMask[in.MaskOpen.IndexAt(pos)] = pos
	}
	rho := len(in.Q)
	for _, idx := range in.Tail {
		posRow, ok := posByIdxRow[idx]
		if !ok {
			return false, fmt.Errorf("row opening missing idx %d", idx)
		}
		posMask, ok := posByIdxMask[idx]
		if !ok {
			return false, fmt.Errorf("mask opening missing idx %d", idx)
		}
		rowVals := make([]uint64, rowCount)
		for j := 0; j < rowCount; j++ {
			rowVals[j] = decs.GetOpeningPval(in.RowOpen, posRow, j) % q
		}
		fpar, fagg, err := eval(uint64(idx), rowVals)
		if err != nil {
			return false, err
		}
		coeffPos := idx % N
		if coeffPos < 0 {
			coeffPos += N
		}
		for i := 0; i < rho; i++ {
			if i >= len(in.Q) || in.Q[i] == nil || coeffPos >= len(in.Q[i].Coeffs[0]) {
				return false, fmt.Errorf("invalid Q at row %d idx %d", i, idx)
			}
			lhs := in.Q[i].Coeffs[0][coeffPos] % q
			rhs := decs.GetOpeningPval(in.MaskOpen, posMask, i) % q
			if i < len(in.GammaPrime) {
				rowGamma := in.GammaPrime[i]
				for j, val := range fpar {
					if j >= len(rowGamma) {
						continue
					}
					rhs = lvcs.MulAddMod64(rhs, rowGamma[j]%q, val%q, q)
				}
			}
			if i < len(in.GammaAgg) {
				rowGamma := in.GammaAgg[i]
				for j, val := range fagg {
					if j >= len(rowGamma) {
						continue
					}
					rhs = lvcs.MulAddMod64(rhs, rowGamma[j]%q, val%q, q)
				}
			}
			if lhs != rhs {
				return false, fmt.Errorf("eq4 tail replay mismatch idx=%d row=%d lhs=%d rhs=%d", idx, i, lhs, rhs)
			}
		}
	}
	return true, nil
}

// CredentialConstraintConfig carries the row indices and public parameters
// needed to recompute the current credential constraints from row evaluations.
type CredentialConstraintConfig struct {
	Ring  *ring.Ring
	Ac    [][]*ring.Poly
	B     []*ring.Poly
	Com   []*ring.Poly
	RI0   []*ring.Poly
	RI1   []*ring.Poly
	Bound int64
	// CarryBound is used for K0/K1 carry rows; defaults to 1 when set.
	CarryBound int64

	TPublicNTT *ring.Poly // optional: public T in NTT domain

	// Packing selector values over the evaluation domain (NTT).
	PackingSelNTT []uint64
	PackingNCols  int

	IdxM1  int
	IdxM2  int
	IdxRU0 int
	IdxRU1 int
	IdxR   int
	IdxR0  int
	IdxR1  int
	IdxK0  int
	IdxK1  int
	IdxT   int // optional: T as witness row

	BoundRows []int
	CarryRows []int

	Omega []uint64
}

// PostSignConstraintConfig carries the row indices and public parameters
// needed to recompute the post-sign constraints (signature/hash/bounds).
type PostSignConstraintConfig struct {
	Ring  *ring.Ring
	A     [][]*ring.Poly
	B     []*ring.Poly
	Bound int64

	// Packing selector values over the evaluation domain (NTT).
	PackingSelNTT []uint64
	PackingNCols  int

	IdxM1    int
	IdxM2    int
	IdxR0    int
	IdxR1    int
	IdxT     int
	IdxUBase int
	UCount   int

	BoundRows []int

	Omega []uint64
}

// PRFConstraintConfig carries the row indices and public parameters needed to
// recompute PRF constraints from row evaluations. All PRF parameters are
// treated as public θ-polynomials; ME/MI/CExt/CInt are constant θ's, while
// Tag/Nonce are interpolated over Ω.
type PRFConstraintConfig struct {
	Ring   *ring.Ring
	Params *prf.Params

	StartIdx int
	NCols    int

	TagTheta   []*ring.Poly
	TagCoeff   [][]uint64
	NonceTheta []*ring.Poly
	NonceCoeff [][]uint64
}

// CredentialEvaluator builds a ConstraintEvaluator for the credential
// pre-sign constraints (commit, center, hash, bounds).
func (cfg CredentialConstraintConfig) CredentialEvaluator() ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil ring")
		}
		q := cfg.Ring.Modulus[0]
		getRow := func(idx int) uint64 {
			if idx < 0 || idx >= len(rows) {
				return 0
			}
			return rows[idx] % q
		}

		// Commit residuals (parallel, same ordering as BuildCredentialConstraintSetPre).
		var fpar []uint64
		ptIdx := int(evalIdx)
		if len(cfg.Ac) > 0 {
			fpar = make([]uint64, len(cfg.Ac))
			for i := range cfg.Ac {
				var sum uint64
				if cfg.Ac[i] == nil || cfg.Com == nil || i >= len(cfg.Com) {
					continue
				}
				if ptIdx >= 0 && ptIdx < len(cfg.Com[i].Coeffs[0]) {
					sum = (q + sum - cfg.Com[i].Coeffs[0][ptIdx]%q) % q
				}
				cols := len(cfg.Ac[i])
				for j := 0; j < cols; j++ {
					if cfg.Ac[i][j] == nil {
						continue
					}
					if ptIdx >= len(cfg.Ac[i][j].Coeffs[0]) {
						continue
					}
					vecIdx := []int{cfg.IdxM1, cfg.IdxM2, cfg.IdxRU0, cfg.IdxRU1, cfg.IdxR}
					if j < len(vecIdx) {
						sum = lvcs.MulAddMod64(sum, cfg.Ac[i][j].Coeffs[0][ptIdx]%q, getRow(vecIdx[j]), q)
					}
				}
				fpar[i] = sum % q
			}
		}

		// Center constraints (two residuals, paper-faithful wrap form).
		if cfg.Bound > 0 {
			delta := uint64(2*cfg.Bound + 1)
			ru0 := getRow(cfg.IdxRU0)
			ru1 := getRow(cfg.IdxRU1)
			r0 := getRow(cfg.IdxR0)
			r1 := getRow(cfg.IdxR1)
			k0 := getRow(cfg.IdxK0)
			k1 := getRow(cfg.IdxK1)
			ri0 := cfg.getRI(cfg.RI0, ptIdx)
			ri1 := cfg.getRI(cfg.RI1, ptIdx)
			res0 := (ru0 + ri0 + q - r0) % q
			res0 = (res0 + q - (delta*k0)%q) % q
			res1 := (ru1 + ri1 + q - r1) % q
			res1 = (res1 + q - (delta*k1)%q) % q
			fpar = append(fpar, res0%q, res1%q)
		}

		// Hash residual (cleared denominator form).
		if len(cfg.B) >= 4 && ptIdx >= 0 {
			b0 := cfg.B[0].Coeffs[0][ptIdx] % q
			b1 := cfg.B[1].Coeffs[0][ptIdx] % q
			b2 := cfg.B[2].Coeffs[0][ptIdx] % q
			b3 := cfg.B[3].Coeffs[0][ptIdx] % q
			m1 := getRow(cfg.IdxM1)
			m2 := getRow(cfg.IdxM2)
			r0v := getRow(cfg.IdxR0)
			r1v := getRow(cfg.IdxR1)
			t := cfg.getT(ptIdx, rows)
			// (B3 - R1)*T - (B0 + B1*(M1+M2) + B2*R0)
			res := (q + b3 - r1v) % q
			res = (res * t) % q
			mCombined := (m1 + m2) % q
			lin := b0
			lin = lvcs.MulAddMod64(lin, b1, mCombined, q)
			lin = lvcs.MulAddMod64(lin, b2, r0v, q)
			if res >= lin {
				res = (res - lin) % q
			} else {
				res = (res + q - lin) % q
			}
			fpar = append(fpar, res%q)
		}

		// Packing residuals: enforce lower/upper-half zeroing (evaluation-domain proxy).
		if len(cfg.PackingSelNTT) > 0 && ptIdx >= 0 && ptIdx < len(cfg.PackingSelNTT) {
			sel := cfg.PackingSelNTT[ptIdx] % q
			oneMinus := (1 + q - sel) % q
			fpar = append(fpar, lvcs.MulMod64(sel, getRow(cfg.IdxM1), q))
			fpar = append(fpar, lvcs.MulMod64(oneMinus, getRow(cfg.IdxM2), q))
		}

		// Bounds: P_B(row) for configured rows (evaluation-domain).
		for _, idx := range cfg.BoundRows {
			v := int64(getRow(idx))
			pb := boundPoly(v, cfg.Bound, int64(q))
			fpar = append(fpar, pb%q)
		}
		carryBound := cfg.CarryBound
		if carryBound == 0 && len(cfg.CarryRows) > 0 {
			carryBound = 1
		}
		for _, idx := range cfg.CarryRows {
			v := int64(getRow(idx))
			pb := boundPoly(v, carryBound, int64(q))
			fpar = append(fpar, pb%q)
		}

		return fpar, nil, nil
	}
}

// PostSignEvaluator builds a ConstraintEvaluator for post-sign constraints:
// A·U = T, hash cleared-denominator, packing, and bounds.
func (cfg PostSignConstraintConfig) PostSignEvaluator() ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg.Ring == nil {
			return nil, nil, fmt.Errorf("nil ring")
		}
		q := cfg.Ring.Modulus[0]
		ptIdx := int(evalIdx)
		getRow := func(idx int) uint64 {
			if idx < 0 || idx >= len(rows) {
				return 0
			}
			return rows[idx] % q
		}

		var fpar []uint64

		// Signature residuals: A·U - T.
		if len(cfg.A) > 0 {
			for i := range cfg.A {
				var sum uint64
				for j := 0; j < len(cfg.A[i]) && j < cfg.UCount; j++ {
					if cfg.A[i][j] == nil || ptIdx >= len(cfg.A[i][j].Coeffs[0]) {
						continue
					}
					aVal := cfg.A[i][j].Coeffs[0][ptIdx] % q
					uVal := getRow(cfg.IdxUBase + j)
					sum = lvcs.MulAddMod64(sum, aVal, uVal, q)
				}
				tVal := getRow(cfg.IdxT)
				if sum >= tVal {
					sum = (sum - tVal) % q
				} else {
					sum = (sum + q - tVal) % q
				}
				fpar = append(fpar, sum)
			}
		}

		// Hash residual (cleared denominator).
		if len(cfg.B) >= 4 && ptIdx >= 0 {
			b0 := cfg.B[0].Coeffs[0][ptIdx] % q
			b1 := cfg.B[1].Coeffs[0][ptIdx] % q
			b2 := cfg.B[2].Coeffs[0][ptIdx] % q
			b3 := cfg.B[3].Coeffs[0][ptIdx] % q
			m1 := getRow(cfg.IdxM1)
			m2 := getRow(cfg.IdxM2)
			r0v := getRow(cfg.IdxR0)
			r1v := getRow(cfg.IdxR1)
			t := getRow(cfg.IdxT)
			res := (q + b3 - r1v) % q
			res = (res * t) % q
			mCombined := (m1 + m2) % q
			lin := b0
			lin = lvcs.MulAddMod64(lin, b1, mCombined, q)
			lin = lvcs.MulAddMod64(lin, b2, r0v, q)
			if res >= lin {
				res = (res - lin) % q
			} else {
				res = (res + q - lin) % q
			}
			fpar = append(fpar, res%q)
		}

		// Packing residuals.
		if len(cfg.PackingSelNTT) > 0 && ptIdx >= 0 && ptIdx < len(cfg.PackingSelNTT) {
			sel := cfg.PackingSelNTT[ptIdx] % q
			oneMinus := (1 + q - sel) % q
			fpar = append(fpar, lvcs.MulMod64(sel, getRow(cfg.IdxM1), q))
			fpar = append(fpar, lvcs.MulMod64(oneMinus, getRow(cfg.IdxM2), q))
		}

		// Bounds on configured rows.
		for _, idx := range cfg.BoundRows {
			v := int64(getRow(idx))
			pb := boundPoly(v, cfg.Bound, int64(q))
			fpar = append(fpar, pb%q)
		}

		return fpar, nil, nil
	}
}

type postSignKEvalCache struct {
	ACoeff          [][][]uint64
	BCoeff          [][]uint64
	PackingSelCoeff []uint64
}

func buildPostSignKEvalCache(cfg PostSignConstraintConfig, K *kf.Field) (*postSignKEvalCache, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	ncols := cfg.PackingNCols
	if ncols <= 0 {
		if len(cfg.Omega) > 0 {
			ncols = len(cfg.Omega)
		} else {
			ncols = int(cfg.Ring.N)
		}
	}
	toCoeffTheta := func(p *ring.Poly) ([]uint64, error) {
		if p == nil {
			return nil, nil
		}
		return thetaCoeffFromNTT(cfg.Ring, p, ncols)
	}
	cache := &postSignKEvalCache{}
	if len(cfg.A) > 0 {
		cache.ACoeff = make([][][]uint64, len(cfg.A))
		for i := range cfg.A {
			cache.ACoeff[i] = make([][]uint64, len(cfg.A[i]))
			for j := range cfg.A[i] {
				coeff, err := toCoeffTheta(cfg.A[i][j])
				if err != nil {
					return nil, err
				}
				cache.ACoeff[i][j] = coeff
			}
		}
	}
	if len(cfg.B) > 0 {
		cache.BCoeff = make([][]uint64, len(cfg.B))
		for i := range cfg.B {
			coeff, err := toCoeffTheta(cfg.B[i])
			if err != nil {
				return nil, err
			}
			cache.BCoeff[i] = coeff
		}
	}
	if ncols%2 == 0 {
		selCoeff, err := buildPackingSelectorCoeff(cfg.Ring, ncols)
		if err != nil {
			return nil, err
		}
		cache.PackingSelCoeff = selCoeff
	}
	return cache, nil
}

// PostSignKEvaluator builds a K-point evaluator for post-sign constraints.
func (cfg PostSignConstraintConfig) PostSignKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	cache, err := buildPostSignKEvalCache(cfg, K)
	if err != nil {
		return nil, err
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) kf.Elem {
			if idx < 0 || idx >= len(rows) {
				return K.Zero()
			}
			return rows[idx]
		}

		var fpar []kf.Elem

		// Signature residuals: A·U - T.
		if len(cache.ACoeff) > 0 {
			for i := range cache.ACoeff {
				sum := K.Zero()
				for j := 0; j < len(cache.ACoeff[i]) && j < cfg.UCount; j++ {
					aVal := K.EvalFPolyAtK(cache.ACoeff[i][j], e)
					sum = K.Add(sum, K.Mul(aVal, getRow(cfg.IdxUBase+j)))
				}
				tVal := getRow(cfg.IdxT)
				fpar = append(fpar, K.Sub(sum, tVal))
			}
		}

		// Hash residual.
		if len(cache.BCoeff) >= 4 {
			b0 := K.EvalFPolyAtK(cache.BCoeff[0], e)
			b1 := K.EvalFPolyAtK(cache.BCoeff[1], e)
			b2 := K.EvalFPolyAtK(cache.BCoeff[2], e)
			b3 := K.EvalFPolyAtK(cache.BCoeff[3], e)
			m1 := getRow(cfg.IdxM1)
			m2 := getRow(cfg.IdxM2)
			r0v := getRow(cfg.IdxR0)
			r1v := getRow(cfg.IdxR1)
			t := getRow(cfg.IdxT)
			res := K.Sub(b3, r1v)
			res = K.Mul(res, t)
			lin := b0
			lin = K.Add(lin, K.Mul(b1, K.Add(m1, m2)))
			lin = K.Add(lin, K.Mul(b2, r0v))
			res = K.Sub(res, lin)
			fpar = append(fpar, res)
		}

		// Packing residuals.
		if len(cache.PackingSelCoeff) > 0 {
			sel := K.EvalFPolyAtK(cache.PackingSelCoeff, e)
			oneMinus := K.Sub(K.One(), sel)
			fpar = append(fpar, K.Mul(sel, getRow(cfg.IdxM1)))
			fpar = append(fpar, K.Mul(oneMinus, getRow(cfg.IdxM2)))
		}

		// Bounds.
		for _, idx := range cfg.BoundRows {
			v := getRow(idx)
			pb := boundPolyK(K, v, cfg.Bound)
			fpar = append(fpar, pb)
		}

		return fpar, nil, nil
	}, nil
}

// PostSignEvaluatorCore returns only the signature/hash/packing constraints.
// It omits bounds so callers can control ordering when composing evaluators.
func (cfg PostSignConstraintConfig) PostSignEvaluatorCore() ConstraintEvaluator {
	return func(ptIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		q := cfg.Ring.Modulus[0]
		getRow := func(idx int) uint64 {
			if idx < 0 || idx >= len(rows) {
				return 0
			}
			return rows[idx] % q
		}
		var fpar []uint64
		// Signature residuals: A·U - T.
		if len(cfg.A) > 0 {
			for i := range cfg.A {
				var sum uint64
				for j := 0; j < len(cfg.A[i]) && j < cfg.UCount; j++ {
					aVal := cfg.A[i][j].Coeffs[0][ptIdx] % q
					sum = lvcs.MulAddMod64(sum, aVal, getRow(cfg.IdxUBase+j), q)
				}
				tVal := getRow(cfg.IdxT)
				if sum >= tVal {
					sum -= tVal
				} else {
					sum += q - tVal
				}
				fpar = append(fpar, sum%q)
			}
		}
		// Hash residual.
		if len(cfg.B) >= 4 {
			b0 := cfg.B[0].Coeffs[0][ptIdx] % q
			b1 := cfg.B[1].Coeffs[0][ptIdx] % q
			b2 := cfg.B[2].Coeffs[0][ptIdx] % q
			b3 := cfg.B[3].Coeffs[0][ptIdx] % q
			m1 := getRow(cfg.IdxM1)
			m2 := getRow(cfg.IdxM2)
			r0v := getRow(cfg.IdxR0)
			r1v := getRow(cfg.IdxR1)
			t := getRow(cfg.IdxT)
			res := (b3 + q - r1v) % q
			res = lvcs.MulAddMod64(0, res, t, q)
			lin := b0
			lin = lvcs.MulAddMod64(lin, b1, (m1+m2)%q, q)
			lin = lvcs.MulAddMod64(lin, b2, r0v, q)
			if res >= lin {
				res -= lin
			} else {
				res += q - lin
			}
			fpar = append(fpar, res%q)
		}
		// Packing residuals.
		if len(cfg.PackingSelNTT) > 0 {
			sel := cfg.PackingSelNTT[ptIdx] % q
			oneMinus := (1 + q - sel) % q
			fpar = append(fpar, lvcs.MulMod64(sel, getRow(cfg.IdxM1), q))
			fpar = append(fpar, lvcs.MulMod64(oneMinus, getRow(cfg.IdxM2), q))
		}
		return fpar, nil, nil
	}
}

// PostSignEvaluatorBounds returns only the bounds constraints.
func (cfg PostSignConstraintConfig) PostSignEvaluatorBounds() ConstraintEvaluator {
	return func(ptIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		q := int64(cfg.Ring.Modulus[0])
		getRow := func(idx int) int64 {
			if idx < 0 || idx >= len(rows) {
				return 0
			}
			v := int64(rows[idx])
			if v > q/2 {
				v -= q
			}
			return v
		}
		var fpar []uint64
		for _, idx := range cfg.BoundRows {
			v := getRow(idx)
			fpar = append(fpar, boundPoly(v, cfg.Bound, q))
		}
		return fpar, nil, nil
	}
}

// PostSignKEvaluatorCore returns the K-point evaluator for signature/hash/packing only.
func (cfg PostSignConstraintConfig) PostSignKEvaluatorCore(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	cache, err := buildPostSignKEvalCache(cfg, K)
	if err != nil {
		return nil, err
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) kf.Elem {
			if idx < 0 || idx >= len(rows) {
				return K.Zero()
			}
			return rows[idx]
		}
		var fpar []kf.Elem
		if len(cache.ACoeff) > 0 {
			for i := range cache.ACoeff {
				sum := K.Zero()
				for j := 0; j < len(cache.ACoeff[i]) && j < cfg.UCount; j++ {
					aVal := K.EvalFPolyAtK(cache.ACoeff[i][j], e)
					sum = K.Add(sum, K.Mul(aVal, getRow(cfg.IdxUBase+j)))
				}
				tVal := getRow(cfg.IdxT)
				fpar = append(fpar, K.Sub(sum, tVal))
			}
		}
		if len(cache.BCoeff) >= 4 {
			b0 := K.EvalFPolyAtK(cache.BCoeff[0], e)
			b1 := K.EvalFPolyAtK(cache.BCoeff[1], e)
			b2 := K.EvalFPolyAtK(cache.BCoeff[2], e)
			b3 := K.EvalFPolyAtK(cache.BCoeff[3], e)
			m1 := getRow(cfg.IdxM1)
			m2 := getRow(cfg.IdxM2)
			r0v := getRow(cfg.IdxR0)
			r1v := getRow(cfg.IdxR1)
			t := getRow(cfg.IdxT)
			res := K.Sub(b3, r1v)
			res = K.Mul(res, t)
			lin := b0
			lin = K.Add(lin, K.Mul(b1, K.Add(m1, m2)))
			lin = K.Add(lin, K.Mul(b2, r0v))
			res = K.Sub(res, lin)
			fpar = append(fpar, res)
		}
		if len(cache.PackingSelCoeff) > 0 {
			sel := K.EvalFPolyAtK(cache.PackingSelCoeff, e)
			oneMinus := K.Sub(K.One(), sel)
			fpar = append(fpar, K.Mul(sel, getRow(cfg.IdxM1)))
			fpar = append(fpar, K.Mul(oneMinus, getRow(cfg.IdxM2)))
		}
		return fpar, nil, nil
	}, nil
}

// PostSignKEvaluatorBounds returns only the bounds residuals at K-points.
func (cfg PostSignConstraintConfig) PostSignKEvaluatorBounds(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		getRow := func(idx int) kf.Elem {
			if idx < 0 || idx >= len(rows) {
				return K.Zero()
			}
			return rows[idx]
		}
		var fpar []kf.Elem
		for _, idx := range cfg.BoundRows {
			v := getRow(idx)
			fpar = append(fpar, boundPolyK(K, v, cfg.Bound))
		}
		return fpar, nil, nil
	}, nil
}

// CredentialKEvaluator builds a K-point evaluator for the credential pre-sign constraints.
// It recomputes residuals from K-point row evaluations and public parameters.
func (cfg CredentialConstraintConfig) CredentialKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	cache, err := buildCredentialKEvalCache(cfg, K)
	if err != nil {
		return nil, err
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		q := cfg.Ring.Modulus[0]
		getRow := func(idx int) kf.Elem {
			if idx < 0 || idx >= len(rows) {
				return K.Zero()
			}
			return rows[idx]
		}

		// Commit residuals.
		var fpar []kf.Elem
		if len(cache.AcCoeff) > 0 {
			fpar = make([]kf.Elem, len(cache.AcCoeff))
			vecIdx := []int{cfg.IdxM1, cfg.IdxM2, cfg.IdxRU0, cfg.IdxRU1, cfg.IdxR}
			for i := range cache.AcCoeff {
				sum := K.Zero()
				if i < len(cache.ComCoeff) {
					comVal := K.EvalFPolyAtK(cache.ComCoeff[i], e)
					sum = K.Sub(sum, comVal)
				}
				for j := 0; j < len(cache.AcCoeff[i]) && j < len(vecIdx); j++ {
					aVal := K.EvalFPolyAtK(cache.AcCoeff[i][j], e)
					sum = K.Add(sum, K.Mul(aVal, getRow(vecIdx[j])))
				}
				fpar[i] = sum
			}
		}

		// Center residuals.
		if cfg.Bound > 0 {
			delta := uint64(2*cfg.Bound + 1)
			deltaK := K.EmbedF(delta % q)
			ru0 := getRow(cfg.IdxRU0)
			ru1 := getRow(cfg.IdxRU1)
			r0 := getRow(cfg.IdxR0)
			r1 := getRow(cfg.IdxR1)
			k0 := getRow(cfg.IdxK0)
			k1 := getRow(cfg.IdxK1)
			ri0 := K.EvalFPolyAtK(cache.RI0Coeff, e)
			ri1 := K.EvalFPolyAtK(cache.RI1Coeff, e)
			res0 := K.Sub(K.Sub(K.Add(ru0, ri0), r0), K.Mul(deltaK, k0))
			res1 := K.Sub(K.Sub(K.Add(ru1, ri1), r1), K.Mul(deltaK, k1))
			fpar = append(fpar, res0, res1)
		}

		// Hash residual.
		if len(cache.BCoeff) >= 4 {
			b0 := K.EvalFPolyAtK(cache.BCoeff[0], e)
			b1 := K.EvalFPolyAtK(cache.BCoeff[1], e)
			b2 := K.EvalFPolyAtK(cache.BCoeff[2], e)
			b3 := K.EvalFPolyAtK(cache.BCoeff[3], e)
			m1 := getRow(cfg.IdxM1)
			m2 := getRow(cfg.IdxM2)
			r0v := getRow(cfg.IdxR0)
			r1v := getRow(cfg.IdxR1)
			var t kf.Elem
			if cfg.IdxT >= 0 && cfg.IdxT < len(rows) {
				t = getRow(cfg.IdxT)
			} else if len(cache.TPublicCoeff) > 0 {
				t = K.EvalFPolyAtK(cache.TPublicCoeff, e)
			} else {
				t = K.Zero()
			}
			res := K.Sub(b3, r1v)
			res = K.Mul(res, t)
			lin := b0
			lin = K.Add(lin, K.Mul(b1, K.Add(m1, m2)))
			lin = K.Add(lin, K.Mul(b2, r0v))
			res = K.Sub(res, lin)
			fpar = append(fpar, res)
		}

		// Packing residuals via selector polynomial on Ω.
		if len(cache.PackingSelCoeff) > 0 {
			sel := K.EvalFPolyAtK(cache.PackingSelCoeff, e)
			oneMinus := K.Sub(K.One(), sel)
			fpar = append(fpar, K.Mul(sel, getRow(cfg.IdxM1)))
			fpar = append(fpar, K.Mul(oneMinus, getRow(cfg.IdxM2)))
		}

		// Bounds: P_B(row) over K.
		for _, idx := range cfg.BoundRows {
			v := getRow(idx)
			pb := boundPolyK(K, v, cfg.Bound)
			fpar = append(fpar, pb)
		}
		carryBound := cfg.CarryBound
		if carryBound == 0 && len(cfg.CarryRows) > 0 {
			carryBound = 1
		}
		for _, idx := range cfg.CarryRows {
			v := getRow(idx)
			pb := boundPolyK(K, v, carryBound)
			fpar = append(fpar, pb)
		}

		return fpar, nil, nil
	}, nil
}

func (cfg CredentialConstraintConfig) getRI(ri []*ring.Poly, pt int) uint64 {
	if pt < 0 || ri == nil {
		return 0
	}
	for _, p := range ri {
		if p == nil || pt >= len(p.Coeffs[0]) {
			continue
		}
		return p.Coeffs[0][pt]
	}
	return 0
}

func (cfg CredentialConstraintConfig) getT(ptIdx int, rows []uint64) uint64 {
	if cfg.IdxT >= 0 && cfg.IdxT < len(rows) {
		return rows[cfg.IdxT] % cfg.Ring.Modulus[0]
	}
	if cfg.TPublicNTT != nil && ptIdx < len(cfg.TPublicNTT.Coeffs[0]) {
		return cfg.TPublicNTT.Coeffs[0][ptIdx] % cfg.Ring.Modulus[0]
	}
	return 0
}

func buildPackingSelectorCoeff(ringQ *ring.Ring, ncols int) ([]uint64, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if ncols <= 0 || ncols > int(ringQ.N) {
		return nil, fmt.Errorf("invalid ncols %d", ncols)
	}
	if ncols%2 != 0 {
		return nil, fmt.Errorf("ncols %d not even for packing selector", ncols)
	}
	half := ncols / 2
	row := make([]uint64, ncols)
	for i := half; i < ncols; i++ {
		row[i] = 1 % ringQ.Modulus[0]
	}
	coeff, err := interpolateRowLocal(ringQ, row, nil, ncols, 0)
	if err != nil {
		return nil, err
	}
	out := append([]uint64(nil), coeff.Coeffs[0]...)
	return out, nil
}

// boundPoly evaluates the membership polynomial P_B(x)=∏_{i=-B}^B (x-i) mod q.
func boundPoly(x, B, q int64) uint64 {
	if B <= 0 {
		return 0
	}
	res := int64(1 % q)
	for i := -B; i <= B; i++ {
		res = (res * ((x - i) % q)) % q
		if res < 0 {
			res += q
		}
	}
	return uint64(res % q)
}

// buildRowValsFromVTargets reconstructs row evaluations at the K-point from VTargets.
// It assumes a single block (witnessCount <= ncols) so that each witness row maps
// to a single column in VTargets.
func buildRowValsFromVTargets(K *kf.Field, vTargets [][]uint64, kpIdx int, witnessCount int) ([]kf.Elem, error) {
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if len(vTargets) == 0 {
		return nil, fmt.Errorf("empty VTargets")
	}
	theta := K.Theta
	start := kpIdx * theta
	if start+theta > len(vTargets) {
		return nil, fmt.Errorf("vTargets rows %d too small for kpIdx %d (theta=%d)", len(vTargets), kpIdx, theta)
	}
	if witnessCount > len(vTargets[0]) {
		return nil, fmt.Errorf("vTargets cols %d < witness count %d", len(vTargets[0]), witnessCount)
	}
	out := make([]kf.Elem, witnessCount)
	for rowIdx := 0; rowIdx < witnessCount; rowIdx++ {
		limbs := make([]uint64, theta)
		for coord := 0; coord < theta; coord++ {
			limbs[coord] = vTargets[start+coord][rowIdx]
		}
		out[rowIdx] = K.Phi(limbs)
	}
	return out, nil
}

// buildRowValsFromKEvals reconstructs row evaluations at the K-point from a packed
// matrix where each row corresponds to a K-point and columns are concatenated limbs
// for each witness row.
func buildRowValsFromKEvals(K *kf.Field, rowEvals [][]uint64, kpIdx int, witnessCount int) ([]kf.Elem, error) {
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	if len(rowEvals) == 0 {
		return nil, fmt.Errorf("empty K row evaluations")
	}
	if kpIdx < 0 || kpIdx >= len(rowEvals) {
		return nil, fmt.Errorf("kpIdx %d out of range (rows=%d)", kpIdx, len(rowEvals))
	}
	theta := K.Theta
	row := rowEvals[kpIdx]
	if len(row) < witnessCount*theta {
		return nil, fmt.Errorf("row eval cols %d < witnessCount*theta %d", len(row), witnessCount*theta)
	}
	out := make([]kf.Elem, witnessCount)
	for rowIdx := 0; rowIdx < witnessCount; rowIdx++ {
		start := rowIdx * theta
		limbs := append([]uint64(nil), row[start:start+theta]...)
		out[rowIdx] = K.Phi(limbs)
	}
	return out, nil
}

type credentialKEvalCache struct {
	AcCoeff         [][][]uint64
	ComCoeff        [][]uint64
	BCoeff          [][]uint64
	RI0Coeff        []uint64
	RI1Coeff        []uint64
	TPublicCoeff    []uint64
	PackingSelCoeff []uint64
}

func buildCredentialKEvalCache(cfg CredentialConstraintConfig, K *kf.Field) (*credentialKEvalCache, error) {
	if cfg.Ring == nil {
		return nil, fmt.Errorf("nil ring")
	}
	ncols := cfg.PackingNCols
	if ncols <= 0 {
		if len(cfg.Omega) > 0 {
			ncols = len(cfg.Omega)
		} else {
			ncols = int(cfg.Ring.N)
		}
	}
	toCoeffTheta := func(p *ring.Poly) ([]uint64, error) {
		if p == nil {
			return nil, nil
		}
		return thetaCoeffFromNTT(cfg.Ring, p, ncols)
	}
	cache := &credentialKEvalCache{}
	if len(cfg.Ac) > 0 {
		cache.AcCoeff = make([][][]uint64, len(cfg.Ac))
		for i := range cfg.Ac {
			if cfg.Ac[i] == nil {
				continue
			}
			cache.AcCoeff[i] = make([][]uint64, len(cfg.Ac[i]))
			for j := range cfg.Ac[i] {
				coeff, err := toCoeffTheta(cfg.Ac[i][j])
				if err != nil {
					return nil, err
				}
				cache.AcCoeff[i][j] = coeff
			}
		}
	}
	if len(cfg.Com) > 0 {
		cache.ComCoeff = make([][]uint64, len(cfg.Com))
		for i := range cfg.Com {
			coeff, err := toCoeffTheta(cfg.Com[i])
			if err != nil {
				return nil, err
			}
			cache.ComCoeff[i] = coeff
		}
	}
	if len(cfg.B) > 0 {
		cache.BCoeff = make([][]uint64, len(cfg.B))
		for i := range cfg.B {
			coeff, err := toCoeffTheta(cfg.B[i])
			if err != nil {
				return nil, err
			}
			cache.BCoeff[i] = coeff
		}
	}
	if len(cfg.RI0) > 0 {
		coeff, err := toCoeffTheta(cfg.RI0[0])
		if err != nil {
			return nil, err
		}
		cache.RI0Coeff = coeff
	}
	if len(cfg.RI1) > 0 {
		coeff, err := toCoeffTheta(cfg.RI1[0])
		if err != nil {
			return nil, err
		}
		cache.RI1Coeff = coeff
	}
	if cfg.TPublicNTT != nil {
		coeff, err := toCoeffTheta(cfg.TPublicNTT)
		if err != nil {
			return nil, err
		}
		cache.TPublicCoeff = coeff
	}
	// Packing selector: interpolate over Ω of length ncols.
	if ncols%2 == 0 {
		selCoeff, err := buildPackingSelectorCoeff(cfg.Ring, ncols)
		if err != nil {
			return nil, err
		}
		cache.PackingSelCoeff = selCoeff
	}
	return cache, nil
}

func boundPolyK(K *kf.Field, x kf.Elem, B int64) kf.Elem {
	if B <= 0 {
		return K.Zero()
	}
	q := int64(K.Q)
	res := K.One()
	for i := -B; i <= B; i++ {
		val := i % q
		if val < 0 {
			val += q
		}
		res = K.Mul(res, K.Sub(x, K.EmbedF(uint64(val))))
	}
	return res
}

// buildPRFThetaPolys interpolates public lanes over Ω and returns their Θ polynomials
// (NTT) plus coefficient vectors for K evaluation. Inputs are per-lane values on Ω.
func buildPRFThetaPolys(ringQ *ring.Ring, lanes [][]int64, ncols int) ([]*ring.Poly, [][]uint64, error) {
	if ringQ == nil {
		return nil, nil, fmt.Errorf("nil ring")
	}
	if len(lanes) == 0 {
		return nil, nil, nil
	}
	if ncols <= 0 || ncols > int(ringQ.N) {
		return nil, nil, fmt.Errorf("invalid ncols %d", ncols)
	}
	q := int64(ringQ.Modulus[0])
	theta := make([]*ring.Poly, len(lanes))
	coeff := make([][]uint64, len(lanes))
	for i := range lanes {
		if len(lanes[i]) < ncols {
			return nil, nil, fmt.Errorf("lane %d len=%d < ncols=%d", i, len(lanes[i]), ncols)
		}
		pNTT := ringQ.NewPoly()
		for j := 0; j < ncols; j++ {
			v := lanes[i][j]
			if v < 0 {
				v += q
			}
			pNTT.Coeffs[0][j] = uint64(v % q)
		}
		tp, err := thetaPolyFromNTT(ringQ, pNTT, ncols)
		if err != nil {
			return nil, nil, fmt.Errorf("theta lane %d: %w", i, err)
		}
		tc, err := thetaCoeffFromNTT(ringQ, pNTT, ncols)
		if err != nil {
			return nil, nil, fmt.Errorf("theta coeff lane %d: %w", i, err)
		}
		theta[i] = tp
		coeff[i] = tc
	}
	return theta, coeff, nil
}

// NewPRFConstraintConfig builds the PRF constraint config with Θ interpolation.
func NewPRFConstraintConfig(ringQ *ring.Ring, params *prf.Params, layout *PRFLayout, tagPublic, noncePublic [][]int64, ncols int) (*PRFConstraintConfig, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if params == nil {
		return nil, fmt.Errorf("nil prf params")
	}
	if layout == nil {
		return nil, fmt.Errorf("nil prf layout")
	}
	if err := params.Validate(); err != nil {
		return nil, fmt.Errorf("prf params invalid: %w", err)
	}
	if layout.LenKey != params.LenKey || layout.LenNonce != params.LenNonce || layout.RF != params.RF || layout.RP != params.RP || layout.LenTag != params.LenTag {
		return nil, fmt.Errorf("prf layout mismatch with params")
	}
	if ncols <= 0 {
		ncols = ringQ.N
	}
	tagTheta, tagCoeff, err := buildPRFThetaPolys(ringQ, tagPublic, ncols)
	if err != nil {
		return nil, fmt.Errorf("tag theta: %w", err)
	}
	nonceTheta, nonceCoeff, err := buildPRFThetaPolys(ringQ, noncePublic, ncols)
	if err != nil {
		return nil, fmt.Errorf("nonce theta: %w", err)
	}
	return &PRFConstraintConfig{
		Ring:        ringQ,
		Params:      params,
		StartIdx:    layout.StartIdx,
		NCols:       ncols,
		TagTheta:    tagTheta,
		TagCoeff:    tagCoeff,
		NonceTheta:  nonceTheta,
		NonceCoeff:  nonceCoeff,
	}, nil
}

// PRFEvaluator returns a row-indexed evaluator for PRF constraints at eval points.
func (cfg PRFConstraintConfig) PRFEvaluator() ConstraintEvaluator {
	return func(evalIdx uint64, rows []uint64) ([]uint64, []uint64, error) {
		if cfg.Ring == nil || cfg.Params == nil {
			return nil, nil, fmt.Errorf("nil prf config")
		}
		q := cfg.Ring.Modulus[0]
		t := cfg.Params.T()
		getRow := func(r, j int) uint64 {
			idx := cfg.StartIdx + r*t + j
			if idx < 0 || idx >= len(rows) {
				return 0
			}
			return rows[idx] % q
		}
		powMod := func(v uint64, exp uint64) uint64 {
			res := uint64(1)
			base := v % q
			for exp > 0 {
				if exp&1 == 1 {
					res = (res * base) % q
				}
				base = (base * base) % q
				exp >>= 1
			}
			return res
		}
		tagAt := func(j int) uint64 {
			if j < 0 || j >= len(cfg.TagTheta) {
				return 0
			}
			pt := int(evalIdx)
			if pt < 0 || pt >= len(cfg.TagTheta[j].Coeffs[0]) {
				return 0
			}
			return cfg.TagTheta[j].Coeffs[0][pt] % q
		}
		nonceAt := func(j int) uint64 {
			if j < 0 || j >= len(cfg.NonceTheta) {
				return 0
			}
			pt := int(evalIdx)
			if pt < 0 || pt >= len(cfg.NonceTheta[j].Coeffs[0]) {
				return 0
			}
			return cfg.NonceTheta[j].Coeffs[0][pt] % q
		}

		var fpar []uint64
		rIdx := 0
		// External rounds (first half)
		for r := 0; r < cfg.Params.RF/2; r++ {
			for j := 0; j < t; j++ {
				var sum uint64
				for i := 0; i < t; i++ {
					v := (getRow(rIdx, i) + cfg.Params.CExt[r][i]) % q
					v = powMod(v, cfg.Params.D)
					sum = lvcs.MulAddMod64(sum, cfg.Params.ME[j][i]%q, v, q)
				}
				next := getRow(rIdx+1, j)
				res := (sum + q - next) % q
				fpar = append(fpar, res)
			}
			rIdx++
		}
		// Internal rounds
		for ir := 0; ir < cfg.Params.RP; ir++ {
			u1 := (getRow(rIdx, 0) + cfg.Params.CInt[ir]) % q
			u1Pow := powMod(u1, cfg.Params.D)
			for j := 0; j < t; j++ {
				sum := lvcs.MulMod64(cfg.Params.MI[j][0]%q, u1Pow, q)
				for i := 1; i < t; i++ {
					sum = lvcs.MulAddMod64(sum, cfg.Params.MI[j][i]%q, getRow(rIdx, i), q)
				}
				next := getRow(rIdx+1, j)
				res := (sum + q - next) % q
				fpar = append(fpar, res)
			}
			rIdx++
		}
		// External rounds (second half)
		for r := cfg.Params.RF / 2; r < cfg.Params.RF; r++ {
			for j := 0; j < t; j++ {
				var sum uint64
				for i := 0; i < t; i++ {
					v := (getRow(rIdx, i) + cfg.Params.CExt[r][i]) % q
					v = powMod(v, cfg.Params.D)
					sum = lvcs.MulAddMod64(sum, cfg.Params.ME[j][i]%q, v, q)
				}
				next := getRow(rIdx+1, j)
				res := (sum + q - next) % q
				fpar = append(fpar, res)
			}
			rIdx++
		}
		// Tag binding: x^(R)_j + x^(0)_j - tag_j = 0.
		finalIdx := cfg.Params.RF + cfg.Params.RP
		for j := 0; j < cfg.Params.LenTag; j++ {
			res := (getRow(finalIdx, j) + getRow(0, j)) % q
			res = (res + q - tagAt(j)) % q
			fpar = append(fpar, res)
		}
		// Nonce binding (public): x^(0)_{lenkey+j} - nonce_j.
		for j := 0; j < cfg.Params.LenNonce; j++ {
			if len(cfg.NonceTheta) == 0 {
				break
			}
			res := (getRow(0, cfg.Params.LenKey+j) + q - nonceAt(j)) % q
			fpar = append(fpar, res)
		}
		return fpar, nil, nil
	}
}

// PRFKEvaluator returns a K-point evaluator for PRF constraints in θ>1 mode.
func (cfg PRFConstraintConfig) PRFKEvaluator(K *kf.Field) (KConstraintEvaluator, error) {
	if cfg.Params == nil {
		return nil, fmt.Errorf("nil prf params")
	}
	if K == nil {
		return nil, fmt.Errorf("nil K field")
	}
	return func(e kf.Elem, rows []kf.Elem) ([]kf.Elem, []kf.Elem, error) {
		t := cfg.Params.T()
		getRow := func(r, j int) kf.Elem {
			idx := cfg.StartIdx + r*t + j
			if idx < 0 || idx >= len(rows) {
				return K.Zero()
			}
			return rows[idx]
		}
		powK := func(v kf.Elem, exp uint64) kf.Elem {
			res := K.One()
			base := v
			for exp > 0 {
				if exp&1 == 1 {
					res = K.Mul(res, base)
				}
				base = K.Mul(base, base)
				exp >>= 1
			}
			return res
		}
		tagAt := func(j int) kf.Elem {
			if j < 0 || j >= len(cfg.TagCoeff) {
				return K.Zero()
			}
			return K.EvalFPolyAtK(cfg.TagCoeff[j], e)
		}
		nonceAt := func(j int) kf.Elem {
			if j < 0 || j >= len(cfg.NonceCoeff) {
				return K.Zero()
			}
			return K.EvalFPolyAtK(cfg.NonceCoeff[j], e)
		}

		var fpar []kf.Elem
		rIdx := 0
		for r := 0; r < cfg.Params.RF/2; r++ {
			for j := 0; j < t; j++ {
				sum := K.Zero()
				for i := 0; i < t; i++ {
					v := K.Add(getRow(rIdx, i), K.EmbedF(cfg.Params.CExt[r][i]%K.Q))
					v = powK(v, cfg.Params.D)
					sum = K.Add(sum, K.Mul(K.EmbedF(cfg.Params.ME[j][i]%K.Q), v))
				}
				next := getRow(rIdx+1, j)
				fpar = append(fpar, K.Sub(sum, next))
			}
			rIdx++
		}
		for ir := 0; ir < cfg.Params.RP; ir++ {
			u1 := K.Add(getRow(rIdx, 0), K.EmbedF(cfg.Params.CInt[ir]%K.Q))
			u1Pow := powK(u1, cfg.Params.D)
			for j := 0; j < t; j++ {
				sum := K.Mul(K.EmbedF(cfg.Params.MI[j][0]%K.Q), u1Pow)
				for i := 1; i < t; i++ {
					sum = K.Add(sum, K.Mul(K.EmbedF(cfg.Params.MI[j][i]%K.Q), getRow(rIdx, i)))
				}
				next := getRow(rIdx+1, j)
				fpar = append(fpar, K.Sub(sum, next))
			}
			rIdx++
		}
		for r := cfg.Params.RF / 2; r < cfg.Params.RF; r++ {
			for j := 0; j < t; j++ {
				sum := K.Zero()
				for i := 0; i < t; i++ {
					v := K.Add(getRow(rIdx, i), K.EmbedF(cfg.Params.CExt[r][i]%K.Q))
					v = powK(v, cfg.Params.D)
					sum = K.Add(sum, K.Mul(K.EmbedF(cfg.Params.ME[j][i]%K.Q), v))
				}
				next := getRow(rIdx+1, j)
				fpar = append(fpar, K.Sub(sum, next))
			}
			rIdx++
		}
		finalIdx := cfg.Params.RF + cfg.Params.RP
		for j := 0; j < cfg.Params.LenTag; j++ {
			res := K.Add(getRow(finalIdx, j), getRow(0, j))
			res = K.Sub(res, tagAt(j))
			fpar = append(fpar, res)
		}
		for j := 0; j < cfg.Params.LenNonce; j++ {
			if len(cfg.NonceCoeff) == 0 {
				break
			}
			res := K.Sub(getRow(0, cfg.Params.LenKey+j), nonceAt(j))
			fpar = append(fpar, res)
		}
		return fpar, nil, nil
	}, nil
}
