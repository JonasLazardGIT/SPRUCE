package lvcs

import (
	"crypto/rand"
	"fmt"
	"math/big"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type Opening struct {
	DECSOpen *decs.DECSOpening
}

// RowInput specifies a single logical LVCS row. Head covers the public Ω
// coordinates and Tail holds the masked extension Ω′. When Tail is nil the
// prover samples a fresh random tail during CommitInitWithParams.
type RowInput struct {
	Head []uint64
	Tail []uint64
}

// LayoutSegment tracks a contiguous row slice within the global oracle.
type LayoutSegment struct {
	Offset int
	Count  int
}

func (s LayoutSegment) End() int {
	return s.Offset + s.Count
}

// OracleLayout partitions the LVCS oracle rows into witness and mask regions.
type OracleLayout struct {
	Witness LayoutSegment
	Mask    LayoutSegment
}

// EvalRequest encapsulates a single LVCS evaluation query. Point (or KPoint)
// binds the Fiat–Shamir transcript to the evaluation target, while Coeffs
// holds the linear form applied to the committed rows.
type EvalRequest struct {
	Point  uint64   // optional when opening over F
	KPoint []uint64 // optional when opening over K (θ limbs)
	Coeffs []uint64 // linear coefficients over F for this query
}

// OracleResponses mirrors the prover’s oracle evaluations split by layout.
type OracleResponses struct {
	Points  []uint64
	Witness [][]uint64
	Mask    [][]uint64
}

// ProverKey holds everything the prover needs between Commit and Eval.
type ProverKey struct {
	RingQ      *ring.Ring   // so we can grab q later without touching unexported decs.Prover.ringQ
	DecsProver *decs.Prover // underlying DECS prover

	Rows      []RowInput   // materialised rows including tails
	MaskPolys []*ring.Poly // the η=ℓ′ mask-polynomials  M_i(X)  (NTT domain)
	RowPolys  []*ring.Poly // one polynomial per *row*
	Gamma     [][]uint64   // gamma values for the prover
	Params    decs.Params  // DECS parameters
	TailLen   int          // ℓ
	Layout    OracleLayout // oracle segmentation metadata
}

// CommitInitWithParams – §4.1 steps 1–2:
// Lift each row vector to a degree-(N+ℓ−1) polynomial by appending ℓ random masks
// and commit all those polynomials via DECS using the provided parameters.
func CommitInitWithParams(
	ringQ *ring.Ring,
	rows []RowInput, // logical rows split into Head | Tail
	ell int, // ℓ
	params decs.Params,
) (
	root [16]byte,
	prover *ProverKey,
	err error,
) {
	if ell <= 0 {
		err = fmt.Errorf("CommitInitWithParams: ell must be > 0")
		return
	}

	nrows := len(rows)
	if nrows == 0 {
		err = fmt.Errorf("CommitInitWithParams: rows must be non-empty")
		return
	}
	q0 := ringQ.Modulus[0]

	normalised := make([]RowInput, nrows)

	// 1a) ensure tail materialisation ̄r_j ∈ F_q^ℓ
	for j, in := range rows {
		headLen := len(in.Head)
		if headLen == 0 {
			err = fmt.Errorf("CommitInitWithParams: row %d has empty head", j)
			return
		}
		if headLen+ell > int(ringQ.N) {
			err = fmt.Errorf("CommitInitWithParams: row %d (head=%d) with ell=%d exceeds ring size N=%d", j, headLen, ell, ringQ.N)
			return
		}
		headCopy := append([]uint64(nil), in.Head...)
		tailCopy := make([]uint64, ell)
		switch {
		case in.Tail == nil:
			for i := 0; i < ell; i++ {
				x, _ := rand.Int(rand.Reader, big.NewInt(int64(q0)))
				tailCopy[i] = uint64(x.Int64())
			}
		case len(in.Tail) != ell:
			err = fmt.Errorf("CommitInitWithParams: row %d tail length mismatch (got %d want %d)", j, len(in.Tail), ell)
			return
		default:
			copy(tailCopy, in.Tail)
			for i := 0; i < ell; i++ {
				tailCopy[i] %= q0
			}
		}
		normalised[j] = RowInput{
			Head: headCopy,
			Tail: tailCopy,
		}
	}

	// 1b) interpolate each (r_j, mask_j) into P_j(X)
	polys := make([]*ring.Poly, nrows)
	for j, row := range normalised {
		ncols := len(row.Head)
		if len(row.Tail) != ell {
			err = fmt.Errorf("CommitInitWithParams: tail length mismatch for row %d", j)
			return
		}
		if polys[j], err = interpolateRow(ringQ, row.Head, row.Tail, ncols, ell); err != nil {
			return
		}
	}

	// 2) DECS.CommitInit  (keeps P_j in coeff-form; we keep a *copy*
	//    in NTT domain for the PACS layer → RowPolys)
	dprover := decs.NewProverWithParams(ringQ, polys, params)
	if root, err = dprover.CommitInit(); err != nil {
		return
	}
	Gamma := decs.DeriveGamma(root, params.Eta, nrows, q0)

	// lift P_j to NTT for later reuse
	rowsNTT := make([]*ring.Poly, nrows)
	for j := range polys {
		rowsNTT[j] = ringQ.NewPoly()
		ringQ.NTT(polys[j], rowsNTT[j])
	}

	// the DECS masks are already in coeff-form inside dprover.M – take a
	// *reference* so PACS can build Q without poking into the DECS package.
	masksNTT := make([]*ring.Poly, params.Eta)
	for i := 0; i < params.Eta; i++ {
		masksNTT[i] = ringQ.NewPoly()
		ringQ.NTT(dprover.M[i], masksNTT[i])
	}
	prover = &ProverKey{
		RingQ:      ringQ,
		DecsProver: dprover,
		Rows:       normalised,
		RowPolys:   rowsNTT,
		MaskPolys:  masksNTT,
		Gamma:      Gamma,
		Params:     params,
		TailLen:    ell,
		Layout: OracleLayout{
			Witness: LayoutSegment{Offset: 0, Count: nrows},
			Mask:    LayoutSegment{Offset: nrows, Count: 0},
		},
	}
	return
}

// CommitFinish – §4.1 step 3:
// Later, open masked linear combinations on a small random subset EE of size ℓ.
func CommitFinish(
	prover *ProverKey,
	Gamma [][]uint64,
) []*ring.Poly {
	// nothing exported in decs.Prover needs ringQ here
	return prover.DecsProver.CommitStep2(Gamma)
}

// EvalInit – §4.1 step 1:
// Compute each \bar{v}_k = Σ_j C[k][j] · mask_j.
func EvalInit(
	ringQ *ring.Ring,
	prover *ProverKey,
	C [][]uint64, // C[k][j]
) [][]uint64 {
	reqs := make([]EvalRequest, len(C))
	for i := range C {
		reqs[i] = EvalRequest{Coeffs: C[i]}
	}
	return EvalInitMany(ringQ, prover, reqs)
}

// EvalInitMany – §4.1 step 1 extended to ℓ′ parallel evaluation queries.
func EvalInitMany(
	ringQ *ring.Ring,
	prover *ProverKey,
	reqs []EvalRequest,
) [][]uint64 {
	nrows := len(prover.Rows)
	m := len(reqs)
	if nrows == 0 {
		panic("EvalInitMany: prover has no rows")
	}
	ell := prover.TailLen
	q0 := ringQ.Modulus[0]

	bar := make([][]uint64, m)
	for k := 0; k < m; k++ {
		req := reqs[k]
		if len(req.Coeffs) != nrows {
			panic(fmt.Sprintf("EvalInitMany: coeff length mismatch (got %d want %d)", len(req.Coeffs), nrows))
		}
		bar[k] = make([]uint64, ell)
		for j := 0; j < nrows; j++ {
			cij := req.Coeffs[j] % q0
			row := prover.Rows[j].Tail
			for i := 0; i < ell; i++ {
				bar[k][i] = (bar[k][i] + cij*row[i]) % q0
			}
		}
	}
	return bar
}

// EvalFinish – §4.1 steps 3–4:
// Open the masked positions via DECS.EvalOpen.
func EvalFinish(
	prover *ProverKey,
	E []int,
) *Opening {
	decsOpen := prover.DecsProver.EvalOpen(E)
	return &Opening{DECSOpen: decsOpen}
}

func validateLayout(total int, layout OracleLayout) error {
	if total < 0 {
		return fmt.Errorf("validateLayout: negative total rows")
	}
	if layout.Witness.Offset < 0 || layout.Witness.Count < 0 {
		return fmt.Errorf("validateLayout: invalid witness segment %+v", layout.Witness)
	}
	if layout.Mask.Offset < 0 || layout.Mask.Count < 0 {
		return fmt.Errorf("validateLayout: invalid mask segment %+v", layout.Mask)
	}
	if layout.Witness.End() > total {
		return fmt.Errorf("validateLayout: witness segment exceeds total rows (end=%d total=%d)", layout.Witness.End(), total)
	}
	if layout.Mask.End() > total {
		return fmt.Errorf("validateLayout: mask segment exceeds total rows (end=%d total=%d)", layout.Mask.End(), total)
	}
	if overlap(layout.Witness, layout.Mask) {
		return fmt.Errorf("validateLayout: witness and mask segments overlap")
	}
	return nil
}

func overlap(a, b LayoutSegment) bool {
	if a.Count == 0 || b.Count == 0 {
		return false
	}
	return a.Offset < b.End() && b.Offset < a.End()
}

// SetLayout stores the oracle layout after validating it against the row count.
func (pk *ProverKey) SetLayout(layout OracleLayout) error {
	if pk == nil {
		return fmt.Errorf("SetLayout: nil ProverKey")
	}
	if err := validateLayout(len(pk.Rows), layout); err != nil {
		return err
	}
	pk.Layout = layout
	return nil
}

// EvalOracle evaluates the committed rows at the provided points, partitioning
// the responses according to the requested layout. If layout is the zero value,
// the prover's stored layout is used.
func EvalOracle(
	ringQ *ring.Ring,
	prover *ProverKey,
	points []uint64,
	layout OracleLayout,
) (OracleResponses, error) {
	if ringQ == nil {
		return OracleResponses{}, fmt.Errorf("EvalOracle: nil ring")
	}
	if prover == nil {
		return OracleResponses{}, fmt.Errorf("EvalOracle: nil prover")
	}
	totalRows := len(prover.Rows)
	if totalRows != len(prover.RowPolys) {
		return OracleResponses{}, fmt.Errorf("EvalOracle: row/poly length mismatch (%d vs %d)", totalRows, len(prover.RowPolys))
	}
	effective := layout
	if effective == (OracleLayout{}) {
		effective = prover.Layout
	}
	if err := validateLayout(totalRows, effective); err != nil {
		return OracleResponses{}, err
	}

	resp := OracleResponses{
		Points:  append([]uint64(nil), points...),
		Witness: make([][]uint64, effective.Witness.Count),
		Mask:    make([][]uint64, effective.Mask.Count),
	}

	q0 := ringQ.Modulus[0]
	tmp := ringQ.NewPoly()

	evalSegment := func(seg LayoutSegment, dest [][]uint64) {
		if seg.Count == 0 {
			return
		}
		for rowIdx := seg.Offset; rowIdx < seg.End(); rowIdx++ {
			ringQ.InvNTT(prover.RowPolys[rowIdx], tmp)
			rowLen := len(prover.Rows[rowIdx].Head) + prover.TailLen
			if rowLen > len(tmp.Coeffs[0]) {
				rowLen = len(tmp.Coeffs[0])
			}
			vals := make([]uint64, len(points))
			coeffs := tmp.Coeffs[0][:rowLen]
			for i, pt := range points {
				vals[i] = evalPolyCoeffs(coeffs, pt%q0, q0)
			}
			dest[rowIdx-seg.Offset] = vals
		}
	}

	evalSegment(effective.Witness, resp.Witness)
	evalSegment(effective.Mask, resp.Mask)
	return resp, nil
}

func evalPolyCoeffs(coeffs []uint64, x, mod uint64) uint64 {
	res := uint64(0)
	for i := len(coeffs) - 1; i >= 0; i-- {
		res = MulMod64(res, x%mod, mod)
		res = AddMod64(res, coeffs[i]%mod, mod)
		if i == 0 {
			break
		}
	}
	return res % mod
}
