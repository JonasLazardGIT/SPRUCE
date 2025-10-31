package PIOP

import (
	"bytes"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"runtime"
	"sort"
	"testing"
	"time"

	decs "vSIS-Signature/DECS"
	lvcs "vSIS-Signature/LVCS"
	kf "vSIS-Signature/internal/kfield"
	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	ntrukeys "vSIS-Signature/ntru/keys"
	prof "vSIS-Signature/prof"

	"github.com/tuneinsight/lattigo/v4/ring"
)

const (
	ansiReset = "\033[0m"
	ansiCyan  = "\033[36m"
	ansiRed   = "\033[31m"
	ansiPink  = "\033[95m"
	ansiGreen = "\033[32m"
)

type profileLayer uint8

const (
	layerHelper profileLayer = iota
	layerLVCS
	layerDECS
	layerPIOP
)

var timingLayerByLabel = map[string]profileLayer{
	"BuildWitness":            layerLVCS,
	"BuildWitnessFromDisk":    layerLVCS,
	"appendChainDigits":       layerLVCS,
	"ProverFillLinfChain":     layerLVCS,
	"buildFparLinfChain":      layerLVCS,
	"LVCS.CommitInit":         layerLVCS,
	"LVCS.CommitFinish":       layerLVCS,
	"LVCS.EvalInitMany":       layerLVCS,
	"LVCS.EvalFinish":         layerLVCS,
	"LVCS.EvalStep2":          layerLVCS,
	"BuildMaskPolynomials":    layerPIOP,
	"BuildRowPolynomial":      layerPIOP,
	"buildFpar":               layerPIOP,
	"buildIntegerRowsOnOmega": layerDECS,
	"BuildQ":                  layerPIOP,
	"VerifyQ":                 layerPIOP,
	"columnsToRowsSmallField": layerDECS,
	"columnsToRows":           layerDECS,
	"checkEq4OnOpening":       layerDECS,
	"loadPublicTables":        layerHelper,
	"RunPACSSimulation":       layerPIOP,
	"buildSimWith":            layerPIOP,
}

var sizeLayerByComponent = map[string]profileLayer{
	"RowOpening":    layerDECS,
	"MOpening":      layerDECS,
	"BarSets":       layerPIOP,
	"VTargets":      layerPIOP,
	"TailIndices":   layerPIOP,
	"Chi":           layerPIOP,
	"Zeta":          layerPIOP,
	"Digests":       layerPIOP,
	"Salt":          layerPIOP,
	"Ctr":           layerPIOP,
	"Root":          layerDECS,
	"Gamma":         layerHelper,
	"EvalPoints":    layerHelper,
	"ProofHeader":   layerHelper,
	"OraclePoints":  layerPIOP,
	"OracleWitness": layerPIOP,
	"OracleMask":    layerPIOP,
}

func layerName(layer profileLayer) string {
	switch layer {
	case layerLVCS:
		return "LVCS"
	case layerDECS:
		return "DECS"
	case layerPIOP:
		return "PIOP"
	default:
		return "Helper"
	}
}

func layerColor(layer profileLayer) string {
	switch layer {
	case layerLVCS:
		return ansiCyan
	case layerDECS:
		return ansiRed
	case layerPIOP:
		return ansiPink
	default:
		return ansiGreen
	}
}

func coloredLayerTag(layer profileLayer) string {
	name := layerName(layer)
	color := layerColor(layer)
	if name == "" {
		return ""
	}
	if color == "" {
		return "[" + name + "]"
	}
	return color + "[" + name + "]" + ansiReset
}

func colorizeLayerText(layer profileLayer, value string) string {
	color := layerColor(layer)
	if color == "" {
		return value
	}
	return color + value + ansiReset
}

func layerOfLabel(label string) profileLayer {
	if layer, ok := timingLayerByLabel[label]; ok {
		return layer
	}
	return layerHelper
}

func layerOfComponent(name string) profileLayer {
	if layer, ok := sizeLayerByComponent[name]; ok {
		return layer
	}
	return layerHelper
}

// simCtx holds intermediate state of the simulation.
type simCtx struct {
	ringQ             *ring.Ring
	q                 uint64
	omega             []uint64
	w1                []*ring.Poly
	w2                *ring.Poly
	w3                []*ring.Poly
	origW1Len         int
	unifiedRowPolys   []*ring.Poly
	maskRowValues     [][]uint64
	ell               int
	ncols             int
	theta             int
	KField            *kf.Field
	rows              [][]uint64
	chi               []uint64
	zeta              []uint64
	A                 [][]*ring.Poly
	b1                []*ring.Poly
	B0c               []*ring.Poly
	B0m               [][]*ring.Poly
	B0r               [][]*ring.Poly
	E                 []int
	Fpar              []*ring.Poly
	Fagg              []*ring.Poly
	FparAtE           [][]uint64
	FaggAtE           [][]uint64
	QAtE              [][]uint64
	M                 []*ring.Poly
	MK                []*KPoly
	QK                []*KPoly
	Q                 []*ring.Poly
	GammaPrimePoly    [][]*ring.Poly
	GammaPrimeScalars [][]uint64
	GammaPrimeAgg     [][]uint64
	GammaPrimeK       [][]KScalar
	GammaAggK         [][]KScalar
	bar               [][]uint64 // legacy alias
	barSets           [][]uint64
	EvalReqs          []lvcs.EvalRequest
	CoeffMatrix       [][]uint64
	KPoint            [][]uint64
	Eprime            []uint64
	maskOpenValues    *decs.DECSOpening
	vrf               *lvcs.VerifierState
	pk                *lvcs.ProverKey
	vTargets          [][]uint64
	maskIdx           []int
	open              *lvcs.Opening // legacy alias
	maskOpen          *lvcs.Opening
	tailOpen          *lvcs.Opening
	combinedOpen      *decs.DECSOpening
	proof             *Proof
	C                 [][]uint64 // legacy alias
	GammaP            [][]uint64 // legacy alias
	gammaP            [][]uint64 // legacy alias
	soundness         SoundnessBudget
	proofBytes        int
	dQ                int
	maskDegreeMax     int
	maskPolyCount     int
	maskRowOffset     int
	maskRowCount      int
	maskDegreeBound   int
	oracleLayout      lvcs.OracleLayout
	maskIndependent   []*ring.Poly
	maskIndependentK  []*KPoly
	linfAux           LinfChainAux
	parallelDeg       int
	aggregatedDeg     int
	parallelRows      int
	aggregatedRows    int
	witnessCols       int
	rangeSpec         RangeMembershipSpec
	msgSource         []*ring.Poly
	rndSource         []*ring.Poly
}

// SimOpts controls the behaviour of the PACS simulation and exposes all
// protocol knobs referenced in the SmallWood–ARK nine-round specification.
type SimOpts struct {
	Rho        int
	EllPrime   int
	Ell        int
	Eta        int
	NLeaves    int
	Theta      int
	Kappa      [4]int
	NCols      int
	DQOverride int
	Lambda     int
	ChainW     int
	ChainL     int

	// Mutate allows tests to tweak the witness (w1,w2,w3) before constraints.
	Mutate func(r *ring.Ring, omega []uint64, ell int, w1 []*ring.Poly, w2 *ring.Poly, w3 []*ring.Poly) `json:"-"`
}

func defaultSimOpts() SimOpts {
	return SimOpts{
		Rho:        7,
		EllPrime:   10,
		Ell:        26,
		Eta:        7,
		NLeaves:    0,
		Theta:      1,
		Kappa:      [4]int{0, 0, 0, 0},
		NCols:      8,
		DQOverride: 0,
		Lambda:     256,
		ChainW:     4,
		ChainL:     0, // 0 => auto-compute minimal digits for the bound
	}
}

func (o *SimOpts) applyDefaults() {
	def := defaultSimOpts()
	if o.Rho <= 0 {
		o.Rho = def.Rho
	}
	if o.EllPrime <= 0 {
		o.EllPrime = def.EllPrime
	}
	if o.Ell <= 0 {
		o.Ell = def.Ell
	}
	if o.Eta <= 0 {
		o.Eta = def.Eta
	}
	if o.NLeaves < 0 {
		o.NLeaves = 0
	}
	if o.Theta <= 0 {
		o.Theta = def.Theta
	}
	for i := 0; i < len(o.Kappa); i++ {
		if o.Kappa[i] <= 0 {
			o.Kappa[i] = def.Kappa[i]
		}
	}
	if o.NCols <= 0 {
		o.NCols = def.NCols
	}
	if o.DQOverride < 0 {
		o.DQOverride = 0
	}
	if o.Lambda <= 0 {
		o.Lambda = def.Lambda
	}
	if o.ChainW <= 0 {
		o.ChainW = def.ChainW
	}
	if o.ChainL < 0 {
		o.ChainL = 0
	}
}

// RowLayout captures the witness row partition so verifiers can recover per-row values.
type RowLayout struct {
	SigCount        int
	MsgCount        int
	RndCount        int
	ChainBase       int
	ChainRowsPerSig int
	MsgChainBase    int
	RndChainBase    int
	X1ChainBase     int
	MsgRangeBase    int
	RndRangeBase    int
	X1RangeBase     int
}

// KPolySnapshot serialises a K[X] polynomial by degree and limb coefficients.
type KPolySnapshot struct {
	Degree int
	Limbs  [][]uint64
}

// Proof captures the transcript material emitted by the prover following the
// nine-round SmallWood–ARK flow.
type Proof struct {
	Root             [16]byte
	Salt             []byte
	Ctr              [4]uint64
	Digests          [4][]byte
	Lambda           int
	Kappa            [4]int
	Theta            int
	Chi              []uint64
	Zeta             []uint64
	MOpening         *decs.DECSOpening
	Tail             []int
	VTargets         [][]uint64
	VTargetsBits     []byte
	VTargetsRows     int
	VTargetsCols     int
	VTargetsBitWidth uint8
	BarSets          [][]uint64
	BarSetsBits      []byte
	BarSetsRows      int
	BarSetsCols      int
	BarSetsBitWidth  uint8
	CoeffMatrix      [][]uint64
	KPoint           [][]uint64
	GammaPrimeK      [][]KScalar
	GammaAggK        [][]KScalar
	GammaPrime       [][]uint64
	GammaAgg         [][]uint64
	R                [][]uint64
	FparNTT          [][]uint64
	FaggNTT          [][]uint64
	QNTT             [][]uint64
	MKData           []KPolySnapshot
	QKData           []KPolySnapshot
	RowLayout        RowLayout
	MaskRowOffset    int
	MaskRowCount     int
	MaskDegreeBound  int
	Gamma            [][]uint64
	GammaK           [][]KScalar
	RoundCounters    [4]uint64 // populated once FS scaffolding lands in Phase 3

	RowOpening *decs.DECSOpening
}

type fsRoundResult struct {
	Seed []byte
	RNG  *fsRNG
}

func fsRound(fs *FS, proof *Proof, round int, label string, material ...[]byte) fsRoundResult {
	if fs == nil {
		panic("fsRound: nil FS state")
	}
	if proof == nil {
		panic("fsRound: nil proof")
	}
	h, ctr, seed := fs.GrindAndDerive(round, material, func(h []byte) []byte { return h })
	proof.Ctr[round] = ctr
	proof.RoundCounters[round] = ctr
	proof.Digests[round] = append([]byte(nil), h...)
	return fsRoundResult{
		Seed: append([]byte(nil), seed...),
		RNG:  newFSRNG(label, seed),
	}
}

func (p *Proof) setVTargets(mat [][]uint64) {
	if len(mat) == 0 {
		p.VTargets = nil
		p.VTargetsBits = nil
		p.VTargetsRows = 0
		p.VTargetsCols = 0
		p.VTargetsBitWidth = 0
		return
	}
	bits, rows, cols, width := decs.PackUintMatrix(mat)
	p.VTargetsBits = bits
	p.VTargetsRows = rows
	p.VTargetsCols = cols
	p.VTargetsBitWidth = uint8(width)
	p.VTargets = nil
}

func (p *Proof) ensureVTargetsPacked() {
	if len(p.VTargetsBits) == 0 && len(p.VTargets) > 0 {
		p.setVTargets(p.VTargets)
	}
}

func (p *Proof) VTargetsMatrix() [][]uint64 {
	if len(p.VTargets) > 0 {
		return p.VTargets
	}
	if len(p.VTargetsBits) == 0 {
		return nil
	}
	mat, rows, cols, width, err := decs.UnpackUintMatrix(p.VTargetsBits)
	if err != nil {
		return nil
	}
	p.VTargets = mat
	p.VTargetsRows = rows
	p.VTargetsCols = cols
	p.VTargetsBitWidth = uint8(width)
	return mat
}

func (p *Proof) setBarSets(mat [][]uint64) {
	if len(mat) == 0 {
		p.BarSets = nil
		p.BarSetsBits = nil
		p.BarSetsRows = 0
		p.BarSetsCols = 0
		p.BarSetsBitWidth = 0
		return
	}
	bits, rows, cols, width := decs.PackUintMatrix(mat)
	p.BarSetsBits = bits
	p.BarSetsRows = rows
	p.BarSetsCols = cols
	p.BarSetsBitWidth = uint8(width)
	p.BarSets = nil
}

func (p *Proof) ensureBarSetsPacked() {
	if len(p.BarSetsBits) == 0 && len(p.BarSets) > 0 {
		p.setBarSets(p.BarSets)
	}
}

func (p *Proof) BarSetsMatrix() [][]uint64 {
	if len(p.BarSets) > 0 {
		return p.BarSets
	}
	if len(p.BarSetsBits) == 0 {
		return nil
	}
	mat, rows, cols, width, err := decs.UnpackUintMatrix(p.BarSetsBits)
	if err != nil {
		return nil
	}
	p.BarSets = mat
	p.BarSetsRows = rows
	p.BarSetsCols = cols
	p.BarSetsBitWidth = uint8(width)
	return mat
}

// SimVerdict records the verifier outcomes for a single run.
type SimVerdict struct {
	OkLin bool
	OkEq4 bool
	OkSum bool
}

// SimReport aggregates parameters, verdicts, timings and size counters for a run.
type SimReport struct {
	Opts            SimOpts
	Verdict         SimVerdict
	Degree          int
	NCols           int
	Ell             int
	EllPrime        int
	Rho             int
	Eta             int
	NLeaves         int
	Theta           int
	QMod            uint64
	TimingsUS       map[string]int64
	TimingCounts    map[string]int
	SizesB          map[string]int64
	ProofSizeLayers map[string]int64
	PeakHeapB       uint64
	Soundness       SoundnessBudget
	ProofBytes      int
	Proof           ProofSnapshot
	Chain           ChainSpecSummary
	ParallelDeg     int
	AggregatedDeg   int
	ParallelRows    int
	AggregatedRows  int
	WitnessCols     int
	MaskLeaves      int
	TailLeaves      int
	MerkleOpens     int
}

// ChainSpecSummary captures the effective ℓ∞-chain configuration used in a run.
type ChainSpecSummary struct {
	W     int `json:"W"`
	Base  int `json:"Base"`
	L     int `json:"L"`
	LSDLo int `json:"LSDLo"`
	LSDHi int `json:"LSDHi"`
}

// SoundnessBudget captures the four error components (ε₁..ε₄), the grinding slack,
// and the size counters dictated by Eq. (10) of the SmallWood–ARK paper.
type SoundnessBudget struct {
	Eps          [4]float64
	Bits         [4]float64
	Grinding     [4]float64
	GrindingBits [4]float64
	Total        float64
	TotalBits    float64
	DQ           int
	NRows        int
	M            int
}

func maxDegreeFromCoeffs(poly []uint64) int {
	for i := len(poly) - 1; i >= 0; i-- {
		if poly[i] != 0 {
			return i
		}
	}
	return -1
}

func parallelConstraintDegree(spec *LinfSpec, rm *RangeMembershipSpec) int {
	d := 2 // product and magnitude constraints
	if spec != nil {
		for _, coeffs := range spec.PDi {
			if coeffs == nil {
				continue
			}
			deg := maxDegreeFromCoeffs(coeffs)
			if deg > d {
				d = deg
			}
		}
	}
	if rm != nil && rm.Coeffs != nil {
		if deg := maxDegreeFromCoeffs(rm.Coeffs); deg > d {
			d = deg
		}
	}
	return d
}

func aggregatedConstraintDegree() int {
	return 1
}

func computeDQFromConstraintDegrees(d, dPrime, s, ellPrime int) int {
	if s <= 0 {
		s = 1
	}
	if ellPrime <= 0 {
		ellPrime = 1
	}
	span := ellPrime + s - 1
	c1 := d*span + (s - 1)
	c2 := dPrime * span
	if c1 >= c2 {
		return c1
	}
	return c2
}

// ProofSnapshot is a JSON-friendly representation of Proof retaining protocol
// material in plain slices so it can be serialised without ring-specific types.
type ProofSnapshot struct {
	Root             []byte
	Salt             []byte
	Ctr              [4]uint64
	Digests          [][]byte
	Lambda           int
	Kappa            [4]int
	Theta            int
	Chi              []uint64
	Zeta             []uint64
	MOpening         *decs.DECSOpening
	Tail             []int
	VTargetsBits     []byte
	VTargetsRows     int
	VTargetsCols     int
	VTargetsBitWidth uint8
	BarSetsBits      []byte
	BarSetsRows      int
	BarSetsCols      int
	BarSetsBitWidth  uint8
	CoeffMatrix      [][]uint64
	KPoint           [][]uint64
	GammaPrimeK      [][][]uint64
	GammaAggK        [][][]uint64
	GammaPrime       [][]uint64
	GammaAgg         [][]uint64
	R                [][]uint64
	FparNTT          [][]uint64
	FaggNTT          [][]uint64
	QNTT             [][]uint64
	MKData           []KPolySnapshot
	QKData           []KPolySnapshot
	Gamma            [][]uint64
	GammaK           [][][]uint64
	RowLayout        RowLayout
	MaskRowOffset    int
	MaskRowCount     int
	MaskDegreeBound  int
	RoundCounters    [4]uint64
	RowOpening       *decs.DECSOpening
}

// RunOnce executes a single serialized PACS simulation and captures metrics.
func RunOnce(o SimOpts) (SimReport, error) {
	o.applyDefaults()
	runtime.GC()
	var ms0, ms1 runtime.MemStats
	runtime.ReadMemStats(&ms0)
	start := time.Now()
	ctx, okLin, okEq4, okSum := buildSimWith(nil, o)
	total := time.Since(start)
	runtime.ReadMemStats(&ms1)
	entries := prof.SnapshotAndReset()
	totalUS := total.Microseconds()
	tims := map[string]int64{}
	counts := map[string]int{}
	agg := make(map[string]int64)
	for _, e := range entries {
		dur := e.Dur.Microseconds()
		if e.Label == "buildSimWith" {
			totalUS = dur
			continue
		}
		agg[e.Label] += dur
		counts[e.Label]++
	}
	if len(agg) > 0 {
		type timingPair struct {
			label string
			dur   int64
			count int
		}
		pairs := make([]timingPair, 0, len(agg))
		for label, dur := range agg {
			pairs = append(pairs, timingPair{
				label: label,
				dur:   dur,
				count: counts[label],
			})
			tims[label] = dur
		}
		sort.Slice(pairs, func(i, j int) bool {
			if pairs[i].dur == pairs[j].dur {
				return pairs[i].label < pairs[j].label
			}
			return pairs[i].dur > pairs[j].dur
		})
		fmt.Printf("[timing] Function profile within buildSimWith (total %s):\n", time.Duration(totalUS)*time.Microsecond)
		for _, d := range pairs {
			layer := layerOfLabel(d.label)
			pct := 0.0
			if totalUS > 0 {
				pct = 100.0 * float64(d.dur) / float64(totalUS)
			}
			durStr := (time.Duration(d.dur) * time.Microsecond).String()
			fmt.Printf("[timing]   %s %s total=%s count=%d (%5.1f%%)\n",
				coloredLayerTag(layer),
				colorizeLayerText(layer, d.label),
				durStr,
				d.count,
				pct)
		}
	}
	tims["__total__"] = totalUS
	counts["__total__"] = len(entries)
	sizes := map[string]int64{}
	layerSizes := map[string]int64{}
	if ctx != nil && ctx.proof != nil {
		if sizeParts, totalBytes := proofSizeBreakdown(ctx.proof); len(sizeParts) > 0 {
			for k, v := range sizeParts {
				sizes[k] = int64(v)
				if k == "TOTAL" {
					continue
				}
				layer := layerOfComponent(k)
				name := layerName(layer)
				if name == "" {
					name = "Helper"
				}
				layerSizes[name] += int64(v)
			}
			sizes["TOTAL"] = int64(totalBytes)
			totalLayers := int64(0)
			for _, v := range layerSizes {
				totalLayers += v
			}
			if totalLayers != 0 {
				layerSizes["TOTAL"] = totalLayers
			}
		}
	}
	if ctx != nil && ctx.ringQ != nil {
		o.NLeaves = int(ctx.ringQ.N)
	}
	rep := SimReport{
		Opts:            o,
		Verdict:         SimVerdict{OkLin: okLin, OkEq4: okEq4, OkSum: okSum},
		Degree:          o.NCols + o.Ell - 1,
		NCols:           o.NCols,
		Ell:             o.Ell,
		EllPrime:        o.EllPrime,
		Rho:             o.Rho,
		Eta:             o.Eta,
		NLeaves:         o.NLeaves,
		Theta:           o.Theta,
		TimingsUS:       tims,
		TimingCounts:    counts,
		SizesB:          sizes,
		ProofSizeLayers: layerSizes,
		PeakHeapB:       ms1.TotalAlloc - ms0.TotalAlloc,
	}
	if ctx != nil {
		rep.Soundness = ctx.soundness
		rep.ProofBytes = ctx.proofBytes
		if ctx.ringQ != nil {
			rep.QMod = ctx.ringQ.Modulus[0]
		}
		rep.Proof = ctx.proof.Snapshot()
		spec := ctx.linfAux.Spec
		rep.Chain = ChainSpecSummary{
			W:     spec.W,
			Base:  int(spec.R),
			L:     spec.L,
			LSDLo: spec.LSDLo,
			LSDHi: spec.LSDHi,
		}
		rep.ParallelDeg = ctx.parallelDeg
		rep.AggregatedDeg = ctx.aggregatedDeg
		rep.ParallelRows = ctx.parallelRows
		rep.AggregatedRows = ctx.aggregatedRows
		rep.WitnessCols = ctx.witnessCols
		rep.MaskLeaves = len(ctx.maskIdx)
		rep.TailLeaves = len(ctx.E)
		rep.MerkleOpens = rep.MaskLeaves + rep.TailLeaves
	} else {
		return rep, fmt.Errorf("simulation aborted: missing fixtures or parameters")
	}
	return rep, nil
}

func computeVTargets(mod uint64, rows [][]uint64, C [][]uint64) [][]uint64 {
	if len(rows) == 0 {
		return nil
	}
	ncols := len(rows[0])
	m := len(C)
	res := make([][]uint64, m)
	for k := 0; k < m; k++ {
		res[k] = make([]uint64, ncols)
		for i := 0; i < ncols; i++ {
			sum := uint64(0)
			for j := 0; j < len(rows); j++ {
				sum = lvcs.MulAddMod64(sum, C[k][j], rows[j][i], mod)
			}
			res[k][i] = sum
		}
	}
	return res
}

func copyMatrix(src [][]uint64) [][]uint64 {
	if src == nil {
		return nil
	}
	out := make([][]uint64, len(src))
	for i := range src {
		out[i] = append([]uint64(nil), src[i]...)
	}
	return out
}

func clonePolys(src []*ring.Poly) []*ring.Poly {
	if src == nil {
		return nil
	}
	out := make([]*ring.Poly, len(src))
	for i := range src {
		if src[i] != nil {
			out[i] = src[i].CopyNew()
		}
	}
	return out
}

func polysToNTTMatrix(polys []*ring.Poly) [][]uint64 {
	if polys == nil {
		return nil
	}
	out := make([][]uint64, len(polys))
	for i, p := range polys {
		if p == nil {
			continue
		}
		row := make([]uint64, len(p.Coeffs[0]))
		copy(row, p.Coeffs[0])
		out[i] = row
	}
	return out
}

func nttMatrixToPolys(r *ring.Ring, mat [][]uint64) []*ring.Poly {
	if mat == nil {
		return nil
	}
	out := make([]*ring.Poly, len(mat))
	for i := range mat {
		if mat[i] == nil {
			continue
		}
		p := r.NewPoly()
		copy(p.Coeffs[0], mat[i])
		out[i] = p
	}
	return out
}

func matrixEqual(a, b [][]uint64) bool {
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

func copyKMatrix(src [][]KScalar) [][]KScalar {
	if src == nil {
		return nil
	}
	out := make([][]KScalar, len(src))
	for i := range src {
		if src[i] == nil {
			continue
		}
		row := make([]KScalar, len(src[i]))
		for j := range src[i] {
			if src[i][j] == nil {
				continue
			}
			scalar := make(KScalar, len(src[i][j]))
			copy(scalar, src[i][j])
			row[j] = scalar
		}
		out[i] = row
	}
	return out
}

func snapshotKPolys(polys []*KPoly) []KPolySnapshot {
	if polys == nil {
		return nil
	}
	out := make([]KPolySnapshot, len(polys))
	for i, kp := range polys {
		if kp == nil {
			continue
		}
		limbs := make([][]uint64, len(kp.Limbs))
		for j := range kp.Limbs {
			limbs[j] = append([]uint64(nil), kp.Limbs[j]...)
		}
		out[i] = KPolySnapshot{Degree: kp.Degree, Limbs: limbs}
	}
	return out
}

func restoreKPolys(data []KPolySnapshot) []*KPoly {
	if data == nil {
		return nil
	}
	out := make([]*KPoly, len(data))
	for i := range data {
		kp := &KPoly{Degree: data[i].Degree}
		if len(data[i].Limbs) > 0 {
			kp.Limbs = make([][]uint64, len(data[i].Limbs))
			for j := range data[i].Limbs {
				kp.Limbs[j] = append([]uint64(nil), data[i].Limbs[j]...)
			}
		}
		out[i] = kp
	}
	return out
}

func copyKPolySnapshots(src []KPolySnapshot) []KPolySnapshot {
	if src == nil {
		return nil
	}
	out := make([]KPolySnapshot, len(src))
	for i := range src {
		out[i].Degree = src[i].Degree
		out[i].Limbs = copyMatrix(src[i].Limbs)
	}
	return out
}

func kMatrixTo3D(src [][]KScalar) [][][]uint64 {
	if src == nil {
		return nil
	}
	out := make([][][]uint64, len(src))
	for i := range src {
		row := make([][]uint64, len(src[i]))
		for j := range src[i] {
			scalar := append([]uint64(nil), src[i][j]...)
			row[j] = scalar
		}
		out[i] = row
	}
	return out
}

func k3DToMatrix(src [][][]uint64) [][]KScalar {
	if src == nil {
		return nil
	}
	out := make([][]KScalar, len(src))
	for i := range src {
		row := make([]KScalar, len(src[i]))
		for j := range src[i] {
			scalar := append([]uint64(nil), src[i][j]...)
			row[j] = KScalar(scalar)
		}
		out[i] = row
	}
	return out
}

func kMatrixFirstLimb(mat [][]KScalar) [][]uint64 {
	if mat == nil {
		return nil
	}
	out := make([][]uint64, len(mat))
	for i := range mat {
		row := make([]uint64, len(mat[i]))
		for j := range mat[i] {
			scalar := mat[i][j]
			if len(scalar) > 0 {
				row[j] = scalar[0]
			}
		}
		out[i] = row
	}
	return out
}

func kScalarToElem(K *kf.Field, scalar KScalar) kf.Elem {
	if K == nil {
		return kf.Elem{}
	}
	return K.Phi(scalar)
}

func coeffsFromPolys(polys []*ring.Poly) [][]uint64 {
	if polys == nil {
		return nil
	}
	out := make([][]uint64, len(polys))
	for i, p := range polys {
		out[i] = append([]uint64(nil), p.Coeffs[0]...)
	}
	return out
}

// coeffsFromPolysTrunc copies the first limit coefficients of each poly (coeff domain).
func coeffsFromPolysTrunc(polys []*ring.Poly, limit int) [][]uint64 {
	if polys == nil {
		return nil
	}
	out := make([][]uint64, len(polys))
	for i, p := range polys {
		src := p.Coeffs[0]
		if limit > len(src) {
			limit = len(src)
		}
		row := make([]uint64, limit)
		copy(row, src[:limit])
		out[i] = row
	}
	return out
}

func coeffsToPolys(r *ring.Ring, coeffs [][]uint64) []*ring.Poly {
	if coeffs == nil {
		return nil
	}
	out := make([]*ring.Poly, len(coeffs))
	for i := range coeffs {
		poly := r.NewPoly()
		copy(poly.Coeffs[0], coeffs[i])
		out[i] = poly
	}
	return out
}

func computeMuDenomInv(K *kf.Field, omega []uint64, omegaS1 kf.Elem) kf.Elem {
	denom := K.One()
	q := K.Q
	for _, w := range omega {
		diff := K.Sub(omegaS1, K.EmbedF(w%q))
		denom = K.Mul(denom, diff)
	}
	return K.Inv(denom)
}

func encodeUint64Slice(vals []uint64) []byte {
	if len(vals) == 0 {
		return nil
	}
	out := make([]byte, len(vals)*8)
	for i, v := range vals {
		binary.LittleEndian.PutUint64(out[i*8:], v)
	}
	return out
}

func cloneDECSOpening(op *decs.DECSOpening) *decs.DECSOpening {
	if op == nil {
		return nil
	}
	clone := &decs.DECSOpening{
		MaskBase:  op.MaskBase,
		MaskCount: op.MaskCount,
		Indices:   append([]int(nil), op.Indices...),
	}
	clone.TailCount = op.TailCount
	if len(op.IndexBits) > 0 {
		clone.IndexBits = append([]byte(nil), op.IndexBits...)
	}
	// copy metadata and packed buffers if present
	clone.R = op.R
	clone.Eta = op.Eta
	clone.NonceBytes = op.NonceBytes
	if len(op.NonceSeed) > 0 {
		clone.NonceSeed = append([]byte(nil), op.NonceSeed...)
	}
	if op.PvalsBits != nil {
		clone.PvalsBits = append([]byte(nil), op.PvalsBits...)
	}
	if op.MvalsBits != nil {
		clone.MvalsBits = append([]byte(nil), op.MvalsBits...)
	}
	if len(op.Pvals) > 0 {
		clone.Pvals = make([][]uint64, len(op.Pvals))
		for i := range op.Pvals {
			clone.Pvals[i] = append([]uint64(nil), op.Pvals[i]...)
		}
	}
	if len(op.Mvals) > 0 {
		clone.Mvals = make([][]uint64, len(op.Mvals))
		for i := range op.Mvals {
			clone.Mvals[i] = append([]uint64(nil), op.Mvals[i]...)
		}
	}
	if len(op.Nodes) > 0 {
		clone.Nodes = make([][]byte, len(op.Nodes))
		for i := range op.Nodes {
			clone.Nodes[i] = append([]byte(nil), op.Nodes[i]...)
		}
	}
	if len(op.PathIndex) > 0 {
		clone.PathIndex = make([][]int, len(op.PathIndex))
		for i := range op.PathIndex {
			clone.PathIndex[i] = append([]int(nil), op.PathIndex[i]...)
		}
	}
	if len(op.PathBits) > 0 {
		clone.PathBits = append([]byte(nil), op.PathBits...)
	}
	clone.PathBitWidth = op.PathBitWidth
	clone.PathDepth = op.PathDepth
	if len(op.FrontierRefsBits) > 0 {
		clone.FrontierRefsBits = append([]byte(nil), op.FrontierRefsBits...)
	}
	clone.FrontierRefWidth = op.FrontierRefWidth
	if len(op.Nonces) > 0 {
		clone.Nonces = make([][]byte, len(op.Nonces))
		for i := range op.Nonces {
			clone.Nonces[i] = append([]byte(nil), op.Nonces[i]...)
		}
	}
	if len(op.FrontierNodes) > 0 {
		clone.FrontierNodes = make([][]byte, len(op.FrontierNodes))
		for i := range op.FrontierNodes {
			clone.FrontierNodes[i] = append([]byte(nil), op.FrontierNodes[i]...)
		}
	}
	if len(op.FrontierProof) > 0 {
		clone.FrontierProof = append([]byte(nil), op.FrontierProof...)
	}
	if len(op.FrontierLR) > 0 {
		clone.FrontierLR = append([]byte(nil), op.FrontierLR...)
	}
	clone.FrontierDepth = op.FrontierDepth
	clone.FrontierRefCount = op.FrontierRefCount
	return clone
}

func makeGammaPrimePolys(r *ring.Ring, gamma [][]uint64) [][]*ring.Poly {
	if gamma == nil {
		return nil
	}
	out := make([][]*ring.Poly, len(gamma))
	for i := range gamma {
		out[i] = make([]*ring.Poly, len(gamma[i]))
		for j := range gamma[i] {
			p := r.NewPoly()
			p.Coeffs[0][0] = gamma[i][j]
			r.NTT(p, p)
			out[i][j] = p
		}
	}
	return out
}

func evalRequestsToMatrix(reqs []lvcs.EvalRequest) [][]uint64 {
	out := make([][]uint64, len(reqs))
	for i, req := range reqs {
		row := make([]uint64, len(req.Coeffs))
		copy(row, req.Coeffs)
		out[i] = row
	}
	return out
}

func bytesFromUint64Matrix(mat [][]uint64) []byte {
	return bytesU64Mat(mat)
}

func sampleDistinctFieldElemsAvoid(count int, q uint64, rng *fsRNG, forbid []uint64) []uint64 {
	res := make([]uint64, 0, count)
	seen := make(map[uint64]struct{}, count+len(forbid))
	for _, w := range forbid {
		seen[w%q] = struct{}{}
	}
	for len(res) < count {
		candidate := rng.nextU64() % q
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		res = append(res, candidate)
	}
	return res
}

func sampleDistinctFieldElems(count int, q uint64, rng *fsRNG) []uint64 {
	res := make([]uint64, 0, count)
	seen := make(map[uint64]struct{}, count)
	for len(res) < count {
		candidate := rng.nextU64() % q
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		res = append(res, candidate)
	}
	return res
}

func sampleDistinctIndices(start, length, count int, rng *fsRNG) []int {
	if count > length {
		panic("sampleDistinctIndices: count exceeds range")
	}
	res := make([]int, 0, count)
	seen := make(map[int]struct{}, count)
	for len(res) < count {
		candidate := int(rng.nextU64()%uint64(length)) + start
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		res = append(res, candidate)
	}
	return res
}

func ceilDiv(a, b int) int {
	if b == 0 {
		return 0
	}
	return (a + b - 1) / b
}

func logComb2(n float64, k int) float64 {
	if k < 0 || n <= 0 {
		return math.Inf(-1)
	}
	if float64(k) > n {
		return math.Inf(-1)
	}
	if k == 0 || n == 0 {
		return 0
	}
	// symmetry: C(n,k) == C(n,n-k)
	if float64(k) > n/2 {
		k = int(n) - k
	}
	if k <= 32 {
		var sum float64
		nf := n
		for i := 0; i < k; i++ {
			sum += math.Log2(nf - float64(i))
			sum -= math.Log2(float64(i + 1))
		}
		return sum
	}
	nPlus, _ := math.Lgamma(n + 1)
	kPlus, _ := math.Lgamma(float64(k) + 1)
	nMinusKPlus, _ := math.Lgamma(n - float64(k) + 1)
	return (nPlus - kPlus - nMinusKPlus) / math.Ln2
}

func computeSoundnessBudget(o SimOpts, q uint64, fieldSize float64, dQ int, ncols int, ell int, ellPrime int, eta int, nLeaves int, witnessCols int) SoundnessBudget {
	sb := SoundnessBudget{DQ: dQ}
	ddecs := ncols + ell - 1
	qf := float64(q)

	// ε1 = binom(N, d_decs+2) / |F|^η  (expressed in bits for stability)
	bits1 := float64(eta)*math.Log2(qf) - logComb2(float64(nLeaves), ddecs+2)
	if math.IsInf(bits1, -1) {
		bits1 = 0
	}
	if bits1 < 0 {
		bits1 = 0
	}
	eps1 := math.Pow(2, -bits1)
	sb.Eps[0] = eps1
	sb.Bits[0] = bits1

	var eps2 float64
	rhoEff := o.Rho
	if rhoEff < 1 {
		rhoEff = 1
	}
	if o.Theta > 1 {
		exponent := float64(o.Theta * rhoEff)
		eps2 = math.Pow(qf, -exponent)
	} else {
		eps2 = math.Pow(qf, float64(-rhoEff))
	}
	if eps2 <= 0 {
		eps2 = math.SmallestNonzeroFloat64
	}
	sb.Eps[1] = eps2
	sb.Bits[1] = -math.Log2(eps2)

	if ellPrime < 1 {
		ellPrime = 1
	}
	if fieldSize <= 0 {
		fieldSize = qf
	}
	Ssize := fieldSize - float64(ncols)
	if Ssize < 1 {
		Ssize = 1
	}
	var bits3 float64
	if dQ < ellPrime {
		bits3 = math.Inf(1)
	} else {
		bits3 = logComb2(Ssize, ellPrime) - logComb2(float64(dQ), ellPrime)
		if math.IsInf(bits3, -1) {
			bits3 = math.Inf(1)
		}
		if bits3 < 0 {
			bits3 = 0
		}
	}
	eps3 := math.Pow(2, -bits3)
	sb.Eps[2] = eps3
	sb.Bits[2] = bits3

	logCombCols := logComb2(float64(ncols+ell-1), ell)
	logCombLeaves := logComb2(float64(nLeaves), ell)
	bits4 := logCombLeaves - logCombCols
	if bits4 < 0 {
		bits4 = 0
	}
	sb.Bits[3] = bits4
	sb.Eps[3] = math.Pow(2, -bits4)

	for i := 0; i < 4; i++ {
		diff := float64(o.Lambda - o.Kappa[i])
		sb.GrindingBits[i] = diff
		sb.Grinding[i] = math.Pow(2, -diff)
	}

	sb.Total = sb.Eps[0] + sb.Eps[1] + sb.Eps[2] + sb.Eps[3] + sb.Grinding[0] + sb.Grinding[1] + sb.Grinding[2] + sb.Grinding[3]
	if sb.Total <= 0 {
		sb.Total = math.SmallestNonzeroFloat64
	}
	sb.TotalBits = -math.Log2(sb.Total)

	rowsBlock := ceilDiv(witnessCols, ncols)
	sb.NRows = rowsBlock * (ncols + o.Theta)
	if o.Theta > 1 {
		maskLayers := ceilDiv(dQ, ncols)
		sb.NRows += (maskLayers + 1) * o.Theta * rhoEff
		sb.M = (rowsBlock + 1) * o.Theta * ellPrime
	} else {
		sb.M = rowsBlock * ellPrime
	}
	return sb
}

func logSoundnessBudget(o SimOpts, q uint64, fieldSize float64, dQ int, ncols int, ell int, ellPrime int, eta int, nLeaves int, witnessCols int) SoundnessBudget {
	sb := computeSoundnessBudget(o, q, fieldSize, dQ, ncols, ell, ellPrime, eta, nLeaves, witnessCols)
	fmt.Printf("[soundness] eps1≤2^{-%0.2f}, eps2≤2^{-%0.2f}, eps3≤2^{-%0.2f}, eps4≤2^{-%0.2f}, eps_fs≤{2^{-%0.2f},2^{-%0.2f},2^{-%0.2f},2^{-%0.2f}}, total≈2^{-%0.2f}\n",
		sb.Bits[0], sb.Bits[1], sb.Bits[2], sb.Bits[3], sb.GrindingBits[0], sb.GrindingBits[1], sb.GrindingBits[2], sb.GrindingBits[3], sb.TotalBits)
	fmt.Printf("[size] nrows=%d, m=%d, dQ=%d\n", sb.NRows, sb.M, sb.DQ)
	return sb
}

func sizeUint64Matrix(mat [][]uint64) int {
	sum := 0
	for _, row := range mat {
		sum += len(row) * 8
	}
	return sum
}

func varintSize(x int) int {
	if x < 0 {
		x = -x
	}
	ux := uint64(x)
	size := 1
	for ux >= 0x80 {
		size++
		ux >>= 7
	}
	return size
}

func sizeDECSOpening(open *decs.DECSOpening) int {
	if open == nil {
		return 0
	}
	sum := 0
	if open.MaskCount > 0 {
		sum += varintSize(open.MaskBase)
		sum += varintSize(open.MaskCount)
	}
	if len(open.IndexBits) > 0 && open.TailCount > 0 && len(open.Indices) == 0 {
		sum += len(open.IndexBits)
		sum += varintSize(open.TailCount)
	} else {
		for _, idx := range open.Indices {
			sum += varintSize(idx)
		}
	}
	if open.PvalsBits != nil {
		sum += len(open.PvalsBits)
	} else {
		sum += sizeUint64Matrix(open.Pvals)
	}
	if open.MvalsBits != nil {
		sum += len(open.MvalsBits)
	} else {
		sum += sizeUint64Matrix(open.Mvals)
	}
	// Nodes bytes (unique siblings)
	for _, node := range open.Nodes {
		sum += len(node)
	}
	for _, node := range open.FrontierNodes {
		sum += len(node)
	}
	if len(open.FrontierRefsBits) > 0 && open.FrontierRefWidth > 0 && open.FrontierRefCount > 0 {
		sum += len(open.FrontierRefsBits)
		sum += 1 // width byte
		sum += varintSize(open.FrontierRefCount)
	}
	sum += len(open.FrontierProof)
	sum += len(open.FrontierLR)
	if open.FrontierDepth > 0 {
		sum += 4
	}
	// PathIndex encoding (either packed bits or explicit ints)
	if len(open.PathBits) > 0 && open.PathDepth > 0 && open.PathBitWidth > 0 && len(open.PathIndex) == 0 {
		sum += len(open.PathBits)
		sum += 1 // bit width
		sum += varintSize(open.PathDepth)
	} else {
		for _, pi := range open.PathIndex {
			sum += len(pi) * 4
		}
	}
	if len(open.Nonces) > 0 {
		for _, nonce := range open.Nonces {
			sum += len(nonce)
		}
	} else if len(open.NonceSeed) > 0 {
		sum += len(open.NonceSeed)
	}
	if open.NonceBytes > 0 {
		sum += varintSize(open.NonceBytes)
	}
	return sum
}

func estimateProofSize(proof *Proof) int {
	if proof == nil {
		return 0
	}
	proof.ensureVTargetsPacked()
	proof.ensureBarSetsPacked()
	sum := 0
	sum += len(proof.Salt)
	sum += 16 // Merkle root
	sum += len(proof.Ctr) * 8
	for _, d := range proof.Digests {
		sum += len(d)
	}
	// EvalPoints and KPoint are re-derived on verifier
	sum += len(proof.Chi) * 8
	sum += len(proof.Zeta) * 8
	sum += sizeDECSOpening(proof.MOpening)
	sum += len(proof.Tail) * 4
	// CoeffMatrix (C) re-derived on verifier
	sum += len(proof.VTargetsBits)
	sum += len(proof.BarSetsBits)
	sum += sizeDECSOpening(proof.RowOpening)
	return sum
}

// proofSizeBreakdown computes a per-component size accounting matching estimateProofSize.
func proofSizeBreakdown(proof *Proof) (map[string]int, int) {
	if proof == nil {
		return map[string]int{}, 0
	}
	proof.ensureVTargetsPacked()
	proof.ensureBarSetsPacked()
	sizes := make(map[string]int)
	sizes["Salt"] = len(proof.Salt)
	sizes["Root"] = 16
	sizes["Ctr"] = len(proof.Ctr) * 8
	digSum := 0
	for _, d := range proof.Digests {
		digSum += len(d)
	}
	sizes["Digests"] = digSum
	// EvalPoints and KPoint re-derived on verifier; not serialized
	sizes["Chi"] = len(proof.Chi) * 8
	sizes["Zeta"] = len(proof.Zeta) * 8
	sizes["MOpening"] = sizeDECSOpening(proof.MOpening)
	sizes["TailIndices"] = len(proof.Tail) * 4
	// C re-derived on verifier
	sizes["VTargets"] = len(proof.VTargetsBits)
	sizes["BarSets"] = len(proof.BarSetsBits)
	sizes["RowOpening"] = sizeDECSOpening(proof.RowOpening)
	total := 0
	for _, v := range sizes {
		total += v
	}
	return sizes, total
}

// ProofSizeReport summarises the byte footprint of a proof as consumed by the verifier.
type ProofSizeReport struct {
	Total int
	Parts map[string]int
}

// MeasureProofSize returns a copy of the breakdown used by VerifyNIZK to reconstruct the proof.
func MeasureProofSize(proof *Proof) ProofSizeReport {
	parts, total := proofSizeBreakdown(proof)
	copyParts := make(map[string]int, len(parts))
	for k, v := range parts {
		copyParts[k] = v
	}
	return ProofSizeReport{Total: total, Parts: copyParts}
}

// MeasureProofSnapshotSize restores the proof snapshot and computes its size breakdown.
func MeasureProofSnapshotSize(ps ProofSnapshot) ProofSizeReport {
	return MeasureProofSize(ps.Restore())
}

// printProofSizeBreakdown prints a human-readable breakdown of proof sizes.
func printProofSizeBreakdown(proof *Proof) {
	sizes, total := proofSizeBreakdown(proof)
	if total == 0 {
		fmt.Println("[proof-size] empty or nil proof")
		return
	}
	// sort by descending size
	keys := make([]string, 0, len(sizes))
	for k := range sizes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return sizes[keys[i]] > sizes[keys[j]] })
	fmt.Println("[proof-size] Breakdown (bytes and percent of total):")
	for _, k := range keys {
		v := sizes[k]
		pct := 100.0 * float64(v) / float64(total)
		layer := layerOfComponent(k)
		fmt.Printf("[proof-size] %s %s %8d  (%5.1f%%)\n",
			coloredLayerTag(layer),
			colorizeLayerText(layer, k),
			v,
			pct)
	}
	fmt.Printf("[proof-size] %-16s %8d  (%5.1f%%)\n", "TOTAL", total, 100.0)
}

// Snapshot converts the proof into a serialisable representation.
func (p *Proof) Snapshot() ProofSnapshot {
	p.ensureVTargetsPacked()
	p.ensureBarSetsPacked()
	var rootCopy []byte
	rootCopy = append(rootCopy, p.Root[:]...)
	digests := make([][]byte, len(p.Digests))
	for i, d := range p.Digests {
		digests[i] = append([]byte(nil), d...)
	}
	return ProofSnapshot{
		Root:             rootCopy,
		Salt:             append([]byte(nil), p.Salt...),
		Ctr:              p.Ctr,
		Digests:          digests,
		Lambda:           p.Lambda,
		Kappa:            p.Kappa,
		Theta:            p.Theta,
		Chi:              append([]uint64(nil), p.Chi...),
		Zeta:             append([]uint64(nil), p.Zeta...),
		MOpening:         cloneDECSOpening(p.MOpening),
		Tail:             append([]int(nil), p.Tail...),
		VTargetsBits:     append([]byte(nil), p.VTargetsBits...),
		VTargetsRows:     p.VTargetsRows,
		VTargetsCols:     p.VTargetsCols,
		VTargetsBitWidth: p.VTargetsBitWidth,
		BarSetsBits:      append([]byte(nil), p.BarSetsBits...),
		BarSetsRows:      p.BarSetsRows,
		BarSetsCols:      p.BarSetsCols,
		BarSetsBitWidth:  p.BarSetsBitWidth,
		CoeffMatrix:      copyMatrix(p.CoeffMatrix),
		KPoint:           copyMatrix(p.KPoint),
		GammaPrimeK:      kMatrixTo3D(p.GammaPrimeK),
		GammaAggK:        kMatrixTo3D(p.GammaAggK),
		GammaPrime:       copyMatrix(p.GammaPrime),
		GammaAgg:         copyMatrix(p.GammaAgg),
		R:                copyMatrix(p.R),
		FparNTT:          copyMatrix(p.FparNTT),
		FaggNTT:          copyMatrix(p.FaggNTT),
		QNTT:             copyMatrix(p.QNTT),
		MKData:           copyKPolySnapshots(p.MKData),
		QKData:           copyKPolySnapshots(p.QKData),
		Gamma:            copyMatrix(p.Gamma),
		GammaK:           kMatrixTo3D(p.GammaK),
		RowLayout:        p.RowLayout,
		MaskRowOffset:    p.MaskRowOffset,
		MaskRowCount:     p.MaskRowCount,
		MaskDegreeBound:  p.MaskDegreeBound,
		RoundCounters:    p.RoundCounters,
		RowOpening:       cloneDECSOpening(p.RowOpening),
	}
}

// Restore rebuilds a proof from its snapshot.
func (ps ProofSnapshot) Restore() *Proof {
	var root [16]byte
	copy(root[:], ps.Root)
	proof := &Proof{
		Root:            root,
		Salt:            append([]byte(nil), ps.Salt...),
		Ctr:             ps.Ctr,
		Lambda:          ps.Lambda,
		Kappa:           ps.Kappa,
		Theta:           ps.Theta,
		Chi:             append([]uint64(nil), ps.Chi...),
		Zeta:            append([]uint64(nil), ps.Zeta...),
		Tail:            append([]int(nil), ps.Tail...),
		CoeffMatrix:     copyMatrix(ps.CoeffMatrix),
		KPoint:          copyMatrix(ps.KPoint),
		RowOpening:      cloneDECSOpening(ps.RowOpening),
		MOpening:        cloneDECSOpening(ps.MOpening),
		GammaPrimeK:     k3DToMatrix(ps.GammaPrimeK),
		GammaAggK:       k3DToMatrix(ps.GammaAggK),
		GammaPrime:      copyMatrix(ps.GammaPrime),
		GammaAgg:        copyMatrix(ps.GammaAgg),
		R:               copyMatrix(ps.R),
		FparNTT:         copyMatrix(ps.FparNTT),
		FaggNTT:         copyMatrix(ps.FaggNTT),
		QNTT:            copyMatrix(ps.QNTT),
		MKData:          copyKPolySnapshots(ps.MKData),
		QKData:          copyKPolySnapshots(ps.QKData),
		Gamma:           copyMatrix(ps.Gamma),
		GammaK:          k3DToMatrix(ps.GammaK),
		RowLayout:       ps.RowLayout,
		MaskRowOffset:   ps.MaskRowOffset,
		MaskRowCount:    ps.MaskRowCount,
		MaskDegreeBound: ps.MaskDegreeBound,
		RoundCounters:   ps.RoundCounters,
	}
	proof.VTargetsBits = append([]byte(nil), ps.VTargetsBits...)
	proof.VTargetsRows = ps.VTargetsRows
	proof.VTargetsCols = ps.VTargetsCols
	proof.VTargetsBitWidth = ps.VTargetsBitWidth
	proof.BarSetsBits = append([]byte(nil), ps.BarSetsBits...)
	proof.BarSetsRows = ps.BarSetsRows
	proof.BarSetsCols = ps.BarSetsCols
	proof.BarSetsBitWidth = ps.BarSetsBitWidth
	for i := range ps.Digests {
		proof.Digests[i] = append([]byte(nil), ps.Digests[i]...)
	}
	return proof
}

func combineOpenings(mask, tail *decs.DECSOpening) *decs.DECSOpening {
	combined := &decs.DECSOpening{}
	nodeMap := make(map[string]int)
	addNode := func(b []byte) int {
		key := string(b)
		if id, ok := nodeMap[key]; ok {
			return id
		}
		id := len(combined.Nodes)
		combined.Nodes = append(combined.Nodes, append([]byte(nil), b...))
		nodeMap[key] = id
		return id
	}
	// helper to append per-entry data and remap path indices
	appendOpen := func(src *decs.DECSOpening, storeIndices bool) {
		if src == nil {
			return
		}
		if err := decs.EnsureMerkleDecoded(src); err != nil {
			panic(err)
		}
		for _, b := range src.Nodes {
			_ = addNode(b)
		}
		for _, row := range src.Pvals {
			combined.Pvals = append(combined.Pvals, append([]uint64(nil), row...))
		}
		for _, row := range src.Mvals {
			combined.Mvals = append(combined.Mvals, append([]uint64(nil), row...))
		}
		for _, pi := range src.PathIndex {
			mapped := make([]int, len(pi))
			for i, id := range pi {
				if id < 0 || id >= len(src.Nodes) {
					mapped[i] = -1
					continue
				}
				mapped[i] = addNode(src.Nodes[id])
			}
			combined.PathIndex = append(combined.PathIndex, mapped)
		}
		if storeIndices {
			combined.Indices = append(combined.Indices, src.AllIndices()...)
		}
	}

	if mask != nil {
		maskIndices := mask.AllIndices()
		if len(maskIndices) > 0 {
			base := maskIndices[0]
			for i := 1; i < len(maskIndices); i++ {
				if maskIndices[i] != base+i {
					panic("mask indices not contiguous")
				}
			}
			combined.MaskBase = base
			combined.MaskCount = len(maskIndices)
		}
		combined.R = mask.R
		combined.Eta = mask.Eta
		if len(combined.NonceSeed) == 0 && len(mask.NonceSeed) > 0 {
			combined.NonceSeed = append([]byte(nil), mask.NonceSeed...)
			combined.NonceBytes = mask.NonceBytes
		}
		appendOpen(mask, false)
	}
	if tail != nil {
		if combined.R == 0 {
			combined.R = tail.R
		}
		if combined.Eta == 0 {
			combined.Eta = tail.Eta
		}
		if len(tail.NonceSeed) > 0 {
			if len(combined.NonceSeed) == 0 {
				combined.NonceSeed = append([]byte(nil), tail.NonceSeed...)
				combined.NonceBytes = tail.NonceBytes
			} else if !bytes.Equal(combined.NonceSeed, tail.NonceSeed) {
				panic("tail opening nonce seed mismatch")
			}
		}
		appendOpen(tail, true)
	}
	if len(combined.PathIndex) > 0 && len(combined.PathIndex[0]) > 0 {
		combined.PathDepth = len(combined.PathIndex[0])
	}
	return combined
}

// RunPACSSimulation executes the PACS workflow used in tests and returns whether
// all verifier checks passed.
func RunPACSSimulation() bool {
	defer prof.Track(time.Now(), "RunPACSSimulation")
	_, okLin, okEq4, okSum := buildSimWith(nil, defaultSimOpts())
	if !(okLin && okEq4 && okSum) {
		fmt.Printf("PACS simulation failed: OkLin=%v, OkEq4=%v, OkSum=%v\n", okLin, okEq4, okSum)
		return false
	}
	fmt.Printf("PACS simulation passed: OkLin=%v, OkEq4=%v, OkSum=%v\n", okLin, okEq4, okSum)
	return true
}

func buildSim(t *testing.T) (*simCtx, bool, bool, bool) {
	return buildSimWith(t, defaultSimOpts())
}

func buildSimWith(t *testing.T, o SimOpts) (*simCtx, bool, bool, bool) {
	defer prof.Track(time.Now(), "buildSimWith")
	o.applyDefaults()
	maskRowOffset := 0
	maskRowCount := 0
	maskDegreeBound := 0
	var oracleLayout lvcs.OracleLayout
	var (
		parallelDeg       int
		aggDeg            int
		dQ                int
		maskDegreeBase    int
		maskDegreeTarget  int
		maxMaskDegree     int
		maskDegreeClipped bool
	)
	var rho int
	var independentMasks []*ring.Poly
	var independentMasksK []*KPoly
	if o.Theta > 1 {
		if o.Rho <= 0 {
			o.Rho = 1
		}
		if o.EllPrime <= 0 {
			o.EllPrime = 1
		}
	}
	rho = o.Rho
	// ------------------------------------------------------------- parameters
	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true /* allowMismatch */)
	if err != nil {
		if t != nil {
			t.Skip("missing parameters: " + err.Error())
		}
		return nil, false, false, false
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		if t != nil {
			t.Fatalf("ring.NewRing: %v", err)
		}
		return nil, false, false, false
	}
	q := ringQ.Modulus[0]
	ringDimension := int(ringQ.N)
	if o.NLeaves <= 0 {
		o.NLeaves = ringDimension
	} else if o.NLeaves != ringDimension {
		msg := fmt.Sprintf("SimOpts.NLeaves=%d mismatch ring dimension %d", o.NLeaves, ringDimension)
		if t != nil {
			t.Fatalf(msg)
		}
		panic(msg)
	}

	// ------------------------------------------------------------- witnesses
	w1, w2, w3, err := BuildWitnessFromDisk() // helper in another PIOP file
	if err != nil {
		if t != nil {
			t.Skip("missing witness fixtures: " + err.Error())
		}
		return nil, false, false, false
	}
	A, b1, B0c, B0m, B0r, err := loadPublicTables(ringQ)
	if err != nil {
		if t != nil {
			t.Skip("missing public tables: " + err.Error())
		}
		return nil, false, false, false
	}

	// --- NEW: remake signature rows as coefficient-packing rows over Ω -------------
	ell := o.Ell
	// build the evaluation grid Ω (size ncols used below)
	ncols := o.NCols
	px := ringQ.NewPoly()
	px.Coeffs[0][1] = 1
	pts := ringQ.NewPoly()
	ringQ.NTT(px, pts)
	omega := pts.Coeffs[0][:ncols]
	if err := checkOmega(omega, q); err != nil {
		fmt.Println("[Ω-check] ", err)
		return nil, false, false, false
	}
	// length of signature block
	mSig := len(w1) - len(B0m) - len(B0r)
	uStart := mSig
	uEnd := uStart + len(B0m)
	x0Start := uEnd
	x0End := x0Start + len(B0r)

	// Rebuild top mSig rows: P_t(ω_j) = a_{t,j} (coefficient packing + blinding)
	for t := 0; t < mSig; t++ {
		coeff := ringQ.NewPoly()
		ringQ.InvNTT(w1[t], coeff) // coefficient vector of the ring poly
		vals := make([]uint64, len(omega))
		for j := 0; j < len(omega); j++ {
			// **Coefficient packing**: per-column value is the coefficient a_{t,j}
			vals[j] = coeff.Coeffs[0][j] % q
		}
		w1[t] = buildValueRow(ringQ, vals, omega, ell) // deg ≤ s+ell-1 row poly
	}
	msgCount := uEnd - uStart
	rndCount := x0End - x0Start

	msgSource := make([]*ring.Poly, msgCount)
	for i := 0; i < msgCount; i++ {
		msgSource[i] = w1[uStart+i].CopyNew()
	}
	rndSource := make([]*ring.Poly, rndCount)
	for i := 0; i < rndCount; i++ {
		rndSource[i] = w1[x0Start+i].CopyNew()
	}

	// Rebuild message and x0 rows as **column-constant** packing rows.
	for i := 0; i < len(B0m); i++ {
		tmp := ringQ.NewPoly()
		ringQ.InvNTT(w1[uStart+i], tmp)
		c := tmp.Coeffs[0][0] % q
		vals := make([]uint64, len(omega))
		for j := range vals {
			vals[j] = c
		}
		w1[uStart+i] = buildValueRow(ringQ, vals, omega, ell)
	}
	off := x0Start
	for i := 0; i < len(B0r); i++ {
		tmp := ringQ.NewPoly()
		ringQ.InvNTT(w1[off+i], tmp)
		c := tmp.Coeffs[0][0] % q
		vals := make([]uint64, len(omega))
		for j := range vals {
			vals[j] = c
		}
		w1[off+i] = buildValueRow(ringQ, vals, omega, ell)
	}

	// Recompute w3 = w1 * w2 using the updated packing rows.
	for i := 0; i < len(w1); i++ {
		ringQ.MulCoeffs(w1[i], w2, w3[i])
	}
	origW1Len := len(w1)
	rowLayout := RowLayout{SigCount: mSig, MsgCount: msgCount, RndCount: rndCount}
	if o.Mutate != nil {
		o.Mutate(ringQ, omega, ell, w1[:origW1Len], w2, w3[:origW1Len])
	}
	bounds := ntru.CurrentSeedPolyBounds()
	maxAbs := bounds.Max
	if maxAbs < 0 {
		maxAbs = -maxAbs
	}
	minAbs := bounds.Min
	if minAbs < 0 {
		minAbs = -minAbs
	}
	if minAbs > maxAbs {
		maxAbs = minAbs
	}
	if maxAbs < 0 {
		maxAbs = -maxAbs
	}
	span := uint64(maxAbs)*2 + 1
	if span >= q {
		panic(fmt.Sprintf("range membership span %d exceeds modulus %d", span, q))
	}
	maxInt := int64(^uint(0) >> 1)
	if maxAbs > maxInt {
		panic("range membership bound exceeds Go int capacity")
	}
	beta := uint64(maxAbs)
	var (
		FparNorm []*ring.Poly
		linfAux  LinfChainAux
	)
	var (
		rangeSpecVal   RangeMembershipSpec
		msgRangeOffset = -1
		rndRangeOffset = -1
		x1RangeOffset  = -1
	)
	w1, FparNorm, linfAux, err = makeNormConstraintsLinfChain(ringQ, q, omega, ell, mSig, w1, beta, o.ChainW, o.ChainL, []*ring.Poly{w2})
	if err != nil {
		panic(err)
	}
	rowLayout.ChainRowsPerSig = 1 + linfAux.Spec.L
	rowLayout.ChainBase = linfAux.RowBase
	rowLayout.MsgChainBase = -1
	rowLayout.RndChainBase = -1
	rowLayout.X1ChainBase = -1
	rowLayout.MsgRangeBase = -1
	rowLayout.RndRangeBase = -1
	rowLayout.X1RangeBase = -1
	seedBound := int(maxAbs)
	rangeSpecVal = NewRangeMembershipSpec(q, seedBound)
	if msgCount > 0 {
		msgRangeOffset = len(FparNorm)
		msgFpar := buildFparRangeMembership(ringQ, msgSource, rangeSpecVal)
		FparNorm = append(FparNorm, msgFpar...)
	}
	if rndCount > 0 {
		rndRangeOffset = len(FparNorm)
		rndFpar := buildFparRangeMembership(ringQ, rndSource, rangeSpecVal)
		FparNorm = append(FparNorm, rndFpar...)
	}
	x1RangeOffset = len(FparNorm)
	x1Fpar := buildFparRangeMembership(ringQ, []*ring.Poly{w2}, rangeSpecVal)
	FparNorm = append(FparNorm, x1Fpar...)
	FaggNorm := []*ring.Poly{}

	parallelDeg = parallelConstraintDegree(&linfAux.Spec, &rangeSpecVal)
	aggDeg = aggregatedConstraintDegree()
	dQ = o.DQOverride
	if dQ <= 0 {
		dQ = computeDQFromConstraintDegrees(parallelDeg, aggDeg, len(omega), o.EllPrime)
	}
	maskDegreeBase = dQ
	maxMaskDegree = int(ringQ.N) - 1
	maskDegreeTarget = maskDegreeBase
	if maskDegreeTarget > maxMaskDegree {
		maskDegreeTarget = maxMaskDegree
		maskDegreeClipped = true
	}
	maskDegreeBound = maskDegreeTarget
	independentMasks = SampleIndependentMaskPolynomials(ringQ, rho, maskDegreeTarget, omega)

	// ---------------------------------------------------------- LVCS.Commit
	maxDegree := o.DQOverride
	if maxDegree <= 0 || maxDegree >= int(ringQ.N) {
		maxDegree = ncols + ell - 1
		if maxDegree >= int(ringQ.N) {
			maxDegree = int(ringQ.N) - 1
		}
	}
	if o.Eta <= 0 {
		if t != nil {
			t.Fatalf("invalid Eta: %d", o.Eta)
		} else {
			panic(fmt.Sprintf("invalid Eta: %d", o.Eta))
		}
	}
	decsParams := decs.Params{Degree: maxDegree, Eta: o.Eta, NonceBytes: 16}
	var rows [][]uint64
	var smallFieldK *kf.Field
	var smallFieldChi []uint64
	var smallFieldOmegaS1 kf.Elem
	var smallFieldMuInv kf.Elem
	var maskRowValues [][]uint64
	if o.Theta > 1 {
		chi, chiErr := kf.FindIrreducible(q, o.Theta, nil)
		if chiErr != nil {
			if t != nil {
				t.Fatalf("FindIrreducible: %v", chiErr)
			}
			panic(fmt.Sprintf("FindIrreducible: %v", chiErr))
		}
		var newErr error
		smallFieldK, newErr = kf.New(q, o.Theta, chi)
		if newErr != nil {
			if t != nil {
				t.Fatalf("kfield.New: %v", newErr)
			}
			panic(fmt.Sprintf("kfield.New: %v", newErr))
		}
		smallFieldChi = append([]uint64(nil), chi...)
		independentMasksK = SampleIndependentMaskPolynomialsK(ringQ, smallFieldK, rho, maskDegreeTarget, omega)
		rows, smallFieldOmegaS1, smallFieldMuInv, err = columnsToRowsSmallField(ringQ, w1, w2, w3, ell, omega, ncols, smallFieldK)
		if err != nil {
			if t != nil {
				t.Fatalf("columnsToRowsSmallField: %v", err)
			}
			panic(fmt.Sprintf("columnsToRowsSmallField: %v", err))
		}
	} else {
		rows = columnsToRows(ringQ, w1, w2, w3, ell, omega)
	}
	witnessRowCount := len(rows)
	maskRowOffset = witnessRowCount
	maskRows := evalPolysOnOmega(ringQ, independentMasks, omega)
	rows = append(rows, maskRows...)
	maskRowCount = len(maskRows)
	maskRowValues = copyMatrix(maskRows)
	unifiedRowPolys := clonePolys(w1[:origW1Len])
	unifiedRowPolys = append(unifiedRowPolys, clonePolys(independentMasks)...)
	rowInputs := make([]lvcs.RowInput, len(rows))
	for i := range rows {
		rowInputs[i] = lvcs.RowInput{Head: rows[i]}
	}
	commitInitStart := time.Now()
	root, pk, err := lvcs.CommitInitWithParams(ringQ, rowInputs, ell, decsParams)
	prof.Track(commitInitStart, "LVCS.CommitInit")
	if err != nil {
		if t != nil {
			t.Fatalf("CommitInitWithParams: %v", err)
		} else {
			panic(fmt.Sprintf("CommitInitWithParams: %v", err))
		}
	}
	oracleLayout.Witness = lvcs.LayoutSegment{Offset: 0, Count: witnessRowCount}
	oracleLayout.Mask = lvcs.LayoutSegment{Offset: maskRowOffset, Count: maskRowCount}
	if err := pk.SetLayout(oracleLayout); err != nil {
		if t != nil {
			t.Fatalf("SetLayout: %v", err)
		} else {
			panic(fmt.Sprintf("SetLayout: %v", err))
		}
	}

	proof := &Proof{Root: root, Lambda: o.Lambda, Theta: o.Theta, Kappa: o.Kappa, RowLayout: rowLayout}
	proof.MaskRowOffset = maskRowOffset
	proof.MaskRowCount = maskRowCount
	proof.MaskDegreeBound = maskDegreeBound
	if o.Theta > 1 {
		proof.Chi = append([]uint64(nil), smallFieldChi...)
		proof.Zeta = append([]uint64(nil), smallFieldOmegaS1.Limb...)
	}
	vrf := lvcs.NewVerifierWithParams(ringQ, len(rows), decsParams, ncols)
	vrf.Root = root
	baseXOF := NewShake256XOF(64)
	salt := make([]byte, 32)
	if _, err := cryptoRand.Read(salt); err != nil {
		if t != nil {
			t.Fatalf("rand salt: %v", err)
		} else {
			panic(err)
		}
	}
	proof.Salt = append([]byte(nil), salt...)
	fs := NewFS(baseXOF, salt, FSParams{Lambda: o.Lambda, Kappa: o.Kappa})

	round1 := fsRound(fs, proof, 0, "Gamma", root[:])
	gammaRNG := round1.RNG
	Gamma := sampleFSMatrix(o.Eta, len(rows), q, gammaRNG)
	gammaBytes := bytesFromUint64Matrix(Gamma)
	vrf.AcceptGamma(Gamma)
	commitFinishStart := time.Now()
	Rpolys := lvcs.CommitFinish(pk, Gamma)
	prof.Track(commitFinishStart, "LVCS.CommitFinish")
	proof.R = coeffsFromPolysTrunc(Rpolys, decsParams.Degree+1)
	if !vrf.CommitStep2(Rpolys) {
		fmt.Println("[deg‑chk] R failed")
		return nil, false, false, false
	}

	// ------------------------------------------------------- PACS batching
	FparProd := buildFpar(ringQ, w1[:origW1Len], w2, w3)
	theta := BuildThetaPrimeSet(ringQ, A, b1, B0c, B0m, B0r, omega)
	integerRows := buildFparInteger(ringQ, w1[:origW1Len], w2, theta, mSig)

	FparInt := append([]*ring.Poly{}, integerRows...)
	FparInt = append(FparInt, FparProd...)
	FaggInt := append([]*ring.Poly{}, integerRows...)

	FparAll := append([]*ring.Poly{}, FparInt...)
	FparAll = append(FparAll, FparNorm...)
	FaggAll := append([]*ring.Poly{}, FaggInt...)
	FaggAll = append(FaggAll, FaggNorm...)
	if msgRangeOffset >= 0 {
		rowLayout.MsgRangeBase = len(FparInt) + msgRangeOffset
	}
	if rndRangeOffset >= 0 {
		rowLayout.RndRangeBase = len(FparInt) + rndRangeOffset
	}
	rowLayout.X1RangeBase = len(FparInt) + x1RangeOffset
	proof.RowLayout = rowLayout
	proof.FparNTT = polysToNTTMatrix(FparAll)
	proof.FaggNTT = polysToNTTMatrix(FaggAll)

	totalParallel := len(FparAll)
	totalAgg := len(FaggAll)

	transcript2 := [][]byte{root[:], gammaBytes, polysToBytes(Rpolys)}
	if o.Theta > 1 {
		transcript2 = append(transcript2, encodeUint64Slice(proof.Chi), encodeUint64Slice(proof.Zeta))
	}
	round2 := fsRound(fs, proof, 1, "GammaPrime", transcript2...)
	seed2 := round2.Seed
	gammaPrimeRNG := round2.RNG
	gammaAggRNG := newFSRNG("GammaPrimeAgg", seed2, []byte{1})
	var (
		GammaPrime      [][]uint64
		GammaAgg        [][]uint64
		GammaPrimeK     [][]KScalar
		GammaAggK       [][]KScalar
		gammaPrimeBytes []byte
		gammaAggBytes   []byte
	)
	if o.Theta > 1 {
		GammaPrimeK = sampleFSMatrixK(rho, totalParallel, o.Theta, q, gammaPrimeRNG)
		GammaAggK = sampleFSVectorK(rho, totalAgg, o.Theta, q, gammaAggRNG)
		gammaPrimeBytes = bytesFromKScalarMat(GammaPrimeK)
		gammaAggBytes = bytesFromKScalarMat(GammaAggK)
		GammaPrime = kMatrixFirstLimb(GammaPrimeK)
		GammaAgg = kMatrixFirstLimb(GammaAggK)
	} else {
		GammaPrime = sampleFSMatrix(rho, totalParallel, q, gammaPrimeRNG)
		GammaAgg = sampleFSMatrix(rho, totalAgg, q, gammaAggRNG)
		gammaPrimeBytes = bytesFromUint64Matrix(GammaPrime)
		gammaAggBytes = bytesFromUint64Matrix(GammaAgg)
	}
	proof.GammaPrime = copyMatrix(GammaPrime)
	proof.GammaAgg = copyMatrix(GammaAgg)
	GammaPrimePoly := makeGammaPrimePolys(ringQ, GammaPrime)
	proof.GammaPrimeK = copyKMatrix(GammaPrimeK)
	proof.GammaAggK = copyKMatrix(GammaAggK)

	fmt.Printf("→ parallel rows: %d; aggregated rows: %d; witness cols: %d\n", totalParallel, totalAgg, len(w1))

	fmt.Printf("[degree] d=%d, d'=%d, dQ=%d\n", parallelDeg, aggDeg, dQ)
	if maskDegreeClipped {
		fmt.Printf("[mask] clipping mask degree from %d to %d due to ring size\n", maskDegreeBase, maskDegreeTarget)
	}
	sumFpar := sumPolyList(ringQ, FparAll, omega)
	sumFagg := sumPolyList(ringQ, FaggAll, omega)

	var (
		M  []*ring.Poly
		MK []*KPoly
		QK []*KPoly
	)
	if o.Theta > 1 {
		MK = BuildMaskPolynomialsK(ringQ, smallFieldK, rho, maskDegreeTarget, omega, GammaPrimeK, GammaAggK, sumFpar, sumFagg)
		M = make([]*ring.Poly, rho)
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
	} else {
		M = BuildMaskPolynomials(ringQ, rho, maskDegreeTarget, omega, GammaPrime, GammaAgg, sumFpar, sumFagg)
	}

	maskDegreeMax := -1
	if o.Theta > 1 {
		for _, kp := range MK {
			if kp != nil && kp.Degree > maskDegreeMax {
				maskDegreeMax = kp.Degree
			}
		}
	} else {
		for _, poly := range M {
			deg := maxPolyDegree(ringQ, poly)
			if deg > maskDegreeMax {
				maskDegreeMax = deg
			}
		}
	}
	if maskDegreeMax > maskDegreeTarget {
		panic(fmt.Sprintf("mask degree %d exceeds target=%d", maskDegreeMax, maskDegreeTarget))
	}
	fmt.Printf("[mask] max-degree=%d (target=%d, dQ=%d)\n", maskDegreeMax, maskDegreeTarget, dQ)

	witnessPolyCount := origW1Len
	if witnessPolyCount < 0 || witnessPolyCount > len(unifiedRowPolys) {
		panic(fmt.Sprintf("invalid witnessPolyCount=%d unifiedRowPolys=%d", witnessPolyCount, len(unifiedRowPolys)))
	}
	layoutWitness := clonePolys(w1[:origW1Len])
	layoutMasks := clonePolys(M)
	unifiedRowPolys = append(append([]*ring.Poly{}, layoutWitness...), layoutMasks...)
	maskRowValues = evalPolysOnOmega(ringQ, layoutMasks, omega)
	qLayout := BuildQLayout{
		WitnessPolys: layoutWitness,
		MaskPolys:    layoutMasks,
	}

	Q := BuildQ(ringQ, qLayout, FparInt, FparNorm, FaggInt, FaggNorm, GammaPrime, GammaAgg)
	if o.Theta > 1 {
		QK = BuildQK(ringQ, smallFieldK, MK, FparAll, FaggAll, GammaPrimeK, GammaAggK)
		proof.MKData = snapshotKPolys(MK)
		proof.QKData = snapshotKPolys(QK)
	} else {
		proof.MKData = nil
		proof.QKData = nil
	}
	proof.QNTT = polysToNTTMatrix(Q)

	maskPolyCount := len(layoutMasks)

	transcript3 := [][]byte{
		root[:],
		gammaBytes,
		gammaPrimeBytes,
		gammaAggBytes,
		polysToBytes(Q),
	}
	round3Label := "EvalPoints"
	if o.Theta > 1 {
		round3Label = "EvalKPoint"
	}
	round3 := fsRound(fs, proof, 2, round3Label, transcript3...)
	seed3 := round3.Seed

	ellPrime := o.EllPrime
	if ellPrime <= 0 {
		ellPrime = 1
	}
	var points []uint64
	var coeffMatrix [][]uint64
	var barSets [][]uint64
	var vTargets [][]uint64
	var evalReqs []lvcs.EvalRequest
	var evalPointBytes []byte
	var kPointLimbs [][]uint64
	smallFieldEvals := make([]kf.Elem, 0, ellPrime)

	if o.Theta > 1 {
		kPointRNG := round3.RNG
		coeffMatrix = make([][]uint64, 0, ellPrime*o.Theta)
		evalReqs = make([]lvcs.EvalRequest, 0, ellPrime*o.Theta)
		kPointLimbs = make([][]uint64, 0, ellPrime)
		for len(smallFieldEvals) < ellPrime {
			limbs := make([]uint64, o.Theta)
			for i := 0; i < o.Theta; i++ {
				limbs[i] = kPointRNG.nextU64() % q
			}
			zeroTail := true
			for i := 1; i < len(limbs); i++ {
				if limbs[i]%q != 0 {
					zeroTail = false
					break
				}
			}
			candidate := smallFieldK.Phi(limbs)
			conflict := false
			for _, w := range omega {
				if elemEqual(smallFieldK, candidate, smallFieldK.EmbedF(w%q)) {
					conflict = true
					break
				}
			}
			if !conflict {
				for _, prev := range smallFieldEvals {
					if elemEqual(smallFieldK, candidate, prev) {
						conflict = true
						break
					}
				}
			}
			if zeroTail || conflict {
				continue
			}
			coeffBlock := buildKPointCoeffMatrix(ringQ, smallFieldK, omega, rows, candidate, smallFieldMuInv, maskRowOffset, maskRowCount)
			for i := range coeffBlock {
				rowCopy := append([]uint64(nil), coeffBlock[i]...)
				evalReqs = append(evalReqs, lvcs.EvalRequest{
					Coeffs: rowCopy,
					KPoint: append([]uint64(nil), candidate.Limb...),
				})
				coeffMatrix = append(coeffMatrix, rowCopy)
			}
			smallFieldEvals = append(smallFieldEvals, candidate)
			kPointLimbs = append(kPointLimbs, append([]uint64(nil), candidate.Limb...))
		}
		evalInitStart := time.Now()
		barSets = lvcs.EvalInitMany(ringQ, pk, evalReqs)
		prof.Track(evalInitStart, "LVCS.EvalInitMany")
		vTargets = computeVTargets(q, rows, coeffMatrix)
		evalPointBytes = nil
	} else {
		evalPointRNG := round3.RNG
		points = sampleDistinctFieldElemsAvoid(ellPrime, q, evalPointRNG, omega)
		coeffRNG := newFSRNG("EvalCoeffs", seed3, []byte{1})
		evalReqs = make([]lvcs.EvalRequest, ellPrime)
		for i := 0; i < ellPrime; i++ {
			coeffs := make([]uint64, len(rows))
			for j := 0; j < len(rows); j++ {
				coeffs[j] = coeffRNG.nextU64() % q
			}
			evalReqs[i] = lvcs.EvalRequest{Point: points[i], Coeffs: coeffs}
		}
		coeffMatrix = evalRequestsToMatrix(evalReqs)
		evalInitStart := time.Now()
		barSets = lvcs.EvalInitMany(ringQ, pk, evalReqs)
		prof.Track(evalInitStart, "LVCS.EvalInitMany")
		vTargets = computeVTargets(q, rows, coeffMatrix)
		evalPointBytes = encodeUint64Slice(points)
	}

	// Eval points and KPoint are re-derived on verifier (matrix retained for replay)
	proof.setBarSets(barSets)
	proof.setVTargets(vTargets)
	proof.CoeffMatrix = copyMatrix(coeffMatrix)
	if o.Theta > 1 {
		proof.KPoint = copyMatrix(kPointLimbs)
	} else {
		proof.KPoint = nil
	}

	var transcript4 [][]byte
	if o.Theta > 1 {
		transcript4 = [][]byte{
			root[:],
			gammaBytes,
			gammaPrimeBytes,
			bytesFromUint64Matrix(kPointLimbs),
			bytesFromUint64Matrix(coeffMatrix),
			bytesFromUint64Matrix(barSets),
			bytesFromUint64Matrix(vTargets),
		}
	} else {
		transcript4 = [][]byte{
			root[:],
			gammaBytes,
			gammaPrimeBytes,
			evalPointBytes,
			bytesFromUint64Matrix(coeffMatrix),
			bytesFromUint64Matrix(barSets),
			bytesFromUint64Matrix(vTargets),
		}
	}
	round4 := fsRound(fs, proof, 3, "TailPoints", transcript4...)
	tailStart := ncols + ell
	tailLen := int(ringQ.N) - tailStart
	if tailLen < ell {
		if t != nil {
			t.Fatalf("insufficient tail: tailLen=%d ell=%d", tailLen, ell)
		} else {
			panic(fmt.Sprintf("insufficient tail: tailLen=%d ell=%d", tailLen, ell))
		}
	}
	tailRNG := round4.RNG
	E := sampleDistinctIndices(tailStart, tailLen, ell, tailRNG)
	proof.Tail = append([]int(nil), E...)

	maskIdx := make([]int, ell)
	for i := 0; i < ell; i++ {
		maskIdx[i] = ncols + i
	}
	evalFinishStart := time.Now()
	openMask := lvcs.EvalFinish(pk, maskIdx)
	prof.Track(evalFinishStart, "LVCS.EvalFinish")
	evalTailStart := time.Now()
	openTail := lvcs.EvalFinish(pk, E)
	prof.Track(evalTailStart, "LVCS.EvalFinish")
	combinedOpen := combineOpenings(openMask.DECSOpen, openTail.DECSOpen)
	proof.RowOpening = cloneDECSOpening(combinedOpen)
	// Pack row opening for compact serialization
	decs.PackOpening(proof.RowOpening)

	maskEval := evalPolySetAtIndices(ringQ, layoutMasks, E)
	maskOpen := makeMaskTailOpening(E, maskEval)
	verifyMaskOpen := cloneDECSOpening(maskOpen)
	proof.MOpening = cloneDECSOpening(maskOpen)
	decs.PackOpening(proof.MOpening)

	for _, idx := range E {
		if idx < tailStart || idx >= int(ringQ.N) {
			if t != nil {
				t.Fatalf("bad E: idx=%d not in tail [tailStart=%d, N=%d)", idx, tailStart, ringQ.N)
			} else {
				panic(fmt.Sprintf("bad E: idx=%d not in tail [tailStart=%d, N=%d)", idx, tailStart, ringQ.N))
			}
		}
	}
	FparAtE := evalPolySetAtIndices(ringQ, FparAll, E)
	FaggAtE := evalPolySetAtIndices(ringQ, FaggAll, E)
	QAtE := evalPolySetAtIndices(ringQ, Q, E)
	okEq4Tail := checkEq4OnTailOpen(ringQ, smallFieldK, o.Theta, E, Q, QK, MK, FparAll, FaggAll, GammaPrime, GammaAgg, GammaPrimeK, GammaAggK, proof.MOpening)

	proofSize := estimateProofSize(proof)
	// Print a detailed proof size breakdown to help identify large components.
	printProofSizeBreakdown(proof)
	msgSourceCopy := make([]*ring.Poly, len(msgSource))
	for i := range msgSource {
		msgSourceCopy[i] = msgSource[i].CopyNew()
	}
	rndSourceCopy := make([]*ring.Poly, len(rndSource))
	for i := range rndSource {
		rndSourceCopy[i] = rndSource[i].CopyNew()
	}
	ctx := &simCtx{
		ringQ:             ringQ,
		q:                 q,
		omega:             omega,
		w1:                w1,
		w2:                w2,
		w3:                w3,
		origW1Len:         origW1Len,
		unifiedRowPolys:   unifiedRowPolys,
		maskRowValues:     maskRowValues,
		ell:               ell,
		ncols:             ncols,
		theta:             o.Theta,
		rows:              copyMatrix(rows),
		A:                 A,
		b1:                b1,
		B0c:               B0c,
		B0m:               B0m,
		B0r:               B0r,
		E:                 E,
		Fpar:              FparAll,
		Fagg:              FaggAll,
		M:                 M,
		MK:                MK,
		QK:                QK,
		maskPolyCount:     maskPolyCount,
		maskRowOffset:     maskRowOffset,
		maskRowCount:      maskRowCount,
		maskDegreeBound:   maskDegreeBound,
		oracleLayout:      oracleLayout,
		maskIndependent:   independentMasks,
		maskIndependentK:  independentMasksK,
		Q:                 Q,
		GammaPrimePoly:    GammaPrimePoly,
		GammaPrimeScalars: GammaPrime,
		GammaPrimeAgg:     GammaAgg,
		GammaPrimeK:       copyKMatrix(GammaPrimeK),
		GammaAggK:         copyKMatrix(GammaAggK),
		FparAtE:           copyMatrix(FparAtE),
		FaggAtE:           copyMatrix(FaggAtE),
		QAtE:              copyMatrix(QAtE),
		GammaP:            GammaPrime,
		gammaP:            GammaAgg,
		barSets:           barSets,
		EvalReqs:          evalReqs,
		CoeffMatrix:       coeffMatrix,
		KPoint:            kPointLimbs,
		Eprime:            points,
		maskOpenValues:    cloneDECSOpening(verifyMaskOpen),
		vrf:               vrf,
		pk:                pk,
		vTargets:          vTargets,
		maskIdx:           maskIdx,
		maskOpen:          openMask,
		tailOpen:          openTail,
		combinedOpen:      combinedOpen,
		proof:             proof,
		bar:               barSets,
		C:                 coeffMatrix,
		open:              openMask,
		proofBytes:        proofSize,
		dQ:                dQ,
		maskDegreeMax:     maskDegreeMax,
		linfAux:           linfAux,
		parallelDeg:       parallelDeg,
		aggregatedDeg:     aggDeg,
		parallelRows:      totalParallel,
		aggregatedRows:    totalAgg,
		witnessCols:       len(w1),
		msgSource:         msgSourceCopy,
		rndSource:         rndSourceCopy,
		rangeSpec:         rangeSpecVal,
	}
	if o.Theta > 1 {
		ctx.chi = append([]uint64(nil), smallFieldChi...)
		ctx.zeta = append([]uint64(nil), smallFieldOmegaS1.Limb...)
		ctx.KField = smallFieldK
	}

	coeffMatch := true
	if o.Theta > 1 {
		omegaS1Elem := smallFieldK.Phi(proof.Zeta)
		muInv := computeMuDenomInv(smallFieldK, omega, omegaS1Elem)
		expected := make([][]uint64, 0, len(smallFieldEvals)*o.Theta)
		for _, eval := range smallFieldEvals {
			block := buildKPointCoeffMatrix(ringQ, smallFieldK, omega, rows, eval, muInv, maskRowOffset, maskRowCount)
			expected = append(expected, block...)
		}
		coeffMatch = matrixEqual(coeffMatrix, expected)
	}
	evalStepStart := time.Now()
	okLin := coeffMatch && vrf.EvalStep2(barSets, E, combinedOpen, coeffMatrix, vTargets)
	prof.Track(evalStepStart, "LVCS.EvalStep2")
	var okEq4Omega bool
	if o.Theta > 1 {
		okEq4Omega = checkEq4OnOmegaK_QK(ringQ, smallFieldK, omega, QK, MK, FparAll, FaggAll, GammaPrimeK, GammaAggK)
	} else {
		okEq4Omega = checkEq4OnOpening(ringQ, Q, M, openMask, FparAll, FaggAll, GammaPrimePoly, GammaAgg, omega, points)
	}
	okEq4K := true
	if o.Theta > 1 {
		okEq4K = coeffMatch
		for _, eval := range smallFieldEvals {
			if !checkEq4AtK_K_QK(ringQ, smallFieldK, eval, QK, MK, FparAll, FaggAll, GammaPrimeK, GammaAggK) {
				okEq4K = false
				break
			}
		}
	}
	okFirstLimbOmega := true
	if o.Theta > 1 {
		okFirstLimbOmega = checkFirstLimbConsistencyOmega(ringQ, smallFieldK, omega, Q, QK)
	}
	okEq4 := okEq4Omega && okEq4K && okEq4Tail && okFirstLimbOmega
	var okSum bool
	if o.Theta > 1 {
		okSum = VerifyQK_QK(ringQ, smallFieldK, omega, QK)
	} else {
		okSum = VerifyQ(ringQ, Q, omega)
	}
	leafCount := o.NLeaves
	if leafCount <= 0 {
		leafCount = int(ringQ.N)
	}
	fieldSize := float64(q)
	if smallFieldK != nil {
		fieldSize = math.Pow(float64(q), float64(smallFieldK.Theta))
	}
	ctx.soundness = logSoundnessBudget(o, q, fieldSize, dQ, ncols, ell, ellPrime, o.Eta, leafCount, origW1Len)

	return ctx, okLin, okEq4, okSum
}

func columnsToRowsSmallField(r *ring.Ring,
	w1 []*ring.Poly, _ *ring.Poly, _ []*ring.Poly,
	_ int, omega []uint64, ncols int, K *kf.Field,
) (rows [][]uint64, omegaS1 kf.Elem, muDenomInv kf.Elem, err error) {
	defer prof.Track(time.Now(), "columnsToRowsSmallField")
	if K == nil {
		return nil, kf.Elem{}, kf.Elem{}, fmt.Errorf("columnsToRowsSmallField: nil extension field")
	}
	q := r.Modulus[0]
	s := len(omega)
	if s == 0 {
		return nil, kf.Elem{}, kf.Elem{}, fmt.Errorf("columnsToRowsSmallField: empty omega")
	}
	if ncols != s {
		return nil, kf.Elem{}, kf.Elem{}, fmt.Errorf("columnsToRowsSmallField: ncols=%d must equal |Ω|=%d", ncols, s)
	}
	theta := K.Theta
	blocks := ceilDiv(len(w1), ncols)
	if blocks == 0 {
		blocks = 1
	}
	rows = make([][]uint64, 0, blocks*(s+theta))

	coeffs := make([][]uint64, len(w1))
	tmp := r.NewPoly()
	for i := range w1 {
		r.InvNTT(w1[i], tmp)
		coeffs[i] = append([]uint64(nil), tmp.Coeffs[0]...)
	}

	const maxAttempts = 1 << 12
	for attempt := 0; attempt < maxAttempts; attempt++ {
		candidate, randErr := K.RandomElement(nil)
		if randErr != nil {
			return nil, kf.Elem{}, kf.Elem{}, fmt.Errorf("columnsToRowsSmallField: %v", randErr)
		}
		conflict := false
		for _, w := range omega {
			if elemEqual(K, candidate, K.EmbedF(w%q)) {
				conflict = true
				break
			}
		}
		if conflict {
			continue
		}
		denom := K.One()
		zeroDiff := false
		for _, w := range omega {
			diff := K.Sub(candidate, K.EmbedF(w%q))
			if K.IsZero(diff) {
				zeroDiff = true
				break
			}
			denom = K.Mul(denom, diff)
		}
		if zeroDiff || K.IsZero(denom) {
			continue
		}
		muDenomInv = K.Inv(denom)
		omegaS1 = candidate
		break
	}
	if len(muDenomInv.Limb) == 0 {
		return nil, kf.Elem{}, kf.Elem{}, fmt.Errorf("columnsToRowsSmallField: failed to sample ω_{s+1}")
	}

	Yvals := make([]kf.Elem, len(w1))
	for idx := range w1 {
		Yvals[idx] = K.EvalFPolyAtK(coeffs[idx], omegaS1)
	}

	for block := 0; block < blocks; block++ {
		for j := 0; j < s; j++ {
			row := make([]uint64, ncols)
			for t := 0; t < ncols; t++ {
				col := block*ncols + t
				if col < len(w1) {
					row[t] = EvalPoly(coeffs[col], omega[j]%q, q)
				}
			}
			rows = append(rows, row)
		}
		for coord := 0; coord < theta; coord++ {
			row := make([]uint64, ncols)
			for t := 0; t < ncols; t++ {
				col := block*ncols + t
				if col < len(Yvals) {
					row[t] = Yvals[col].Limb[coord] % q
				}
			}
			rows = append(rows, row)
		}
	}

	return rows, omegaS1, muDenomInv, nil
}

func evalPolysOnOmega(r *ring.Ring, polys []*ring.Poly, omega []uint64) [][]uint64 {
	if len(polys) == 0 || len(omega) == 0 {
		return nil
	}
	rows := make([][]uint64, len(polys))
	q := r.Modulus[0]
	tmp := r.NewPoly()
	for i, poly := range polys {
		rows[i] = make([]uint64, len(omega))
		r.InvNTT(poly, tmp)
		coeffs := tmp.Coeffs[0]
		for j, w := range omega {
			rows[i][j] = EvalPoly(coeffs, w%q, q)
		}
	}
	return rows
}

func buildKPointCoeffMatrix(
	r *ring.Ring, K *kf.Field, omega []uint64, rows [][]uint64, e kf.Elem, muDenomInv kf.Elem,
	maskRowOffset, maskRowCount int,
) [][]uint64 {
	if K == nil {
		panic("buildKPointCoeffMatrix: nil field")
	}
	q := r.Modulus[0]
	s := len(omega)
	theta := K.Theta
	layerSize := s + theta
	if layerSize == 0 {
		return nil
	}
	totalRows := len(rows)
	witnessRowCount := totalRows
	if maskRowCount > 0 {
		if maskRowOffset < 0 || maskRowOffset > totalRows {
			panic(fmt.Sprintf("buildKPointCoeffMatrix: mask offset %d out of bounds (total=%d)", maskRowOffset, totalRows))
		}
		if maskRowOffset+maskRowCount != totalRows {
			panic(fmt.Sprintf("buildKPointCoeffMatrix: mask segment [%d,%d) inconsistent with total rows %d", maskRowOffset, maskRowOffset+maskRowCount, totalRows))
		}
		witnessRowCount = maskRowOffset
	}
	if witnessRowCount%layerSize != 0 {
		panic(fmt.Sprintf("buildKPointCoeffMatrix: inconsistent row count %d (layer size %d)", witnessRowCount, layerSize))
	}
	layerCount := witnessRowCount / layerSize

	lagNum := make([][]uint64, s)
	lagDenInv := make([]uint64, s)
	for k := 0; k < s; k++ {
		lagNum[k] = lagrangeBasisNumerator(omega, k, q)
		den := uint64(1)
		for j := 0; j < s; j++ {
			if j == k {
				continue
			}
			den = modMul(den, modSub(omega[k]%q, omega[j]%q, q), q)
		}
		lagDenInv[k] = modInv(den, q)
	}

	lambdas := make([]kf.Elem, s)
	for k := 0; k < s; k++ {
		numK := K.EvalFPolyAtK(lagNum[k], e)
		lambdas[k] = K.Mul(numK, K.EmbedF(lagDenInv[k]))
	}

	prod := K.One()
	for _, w := range omega {
		diff := K.Sub(e, K.EmbedF(w%q))
		prod = K.Mul(prod, diff)
	}
	mu := K.Mul(prod, muDenomInv)
	Mmu := K.MulMatrix(mu)

	coeffs := make([][]uint64, theta)
	for coord := 0; coord < theta; coord++ {
		coeffs[coord] = make([]uint64, totalRows)
	}

	for layer := 0; layer < layerCount; layer++ {
		base := layer * layerSize
		for k := 0; k < s; k++ {
			for coord := 0; coord < theta; coord++ {
				coeffs[coord][base+k] = lambdas[k].Limb[coord] % q
			}
		}
		for coord := 0; coord < theta; coord++ {
			for rowIdx := 0; rowIdx < theta; rowIdx++ {
				coeffs[coord][base+s+rowIdx] = Mmu[coord][rowIdx] % q
			}
		}
	}

	return coeffs
}

func elemEqual(f *kf.Field, a, b kf.Elem) bool {
	if len(a.Limb) != len(b.Limb) {
		return false
	}
	for i := range a.Limb {
		if a.Limb[i]%f.Q != b.Limb[i]%f.Q {
			return false
		}
	}
	return true
}

func columnsToRows(r *ring.Ring, w1 []*ring.Poly, w2 *ring.Poly, w3 []*ring.Poly, ell int, omega []uint64) [][]uint64 {
	defer prof.Track(time.Now(), "columnsToRows")
	s := len(w1)
	ncols := len(omega)
	rows := make([][]uint64, s+2)
	q := r.Modulus[0]

	// Row 0..s-1: for each witness column k, evaluate w1[k](ω_j) for all j.
	tmp := r.NewPoly()
	for k := 0; k < s; k++ {
		rows[k] = make([]uint64, ncols)
		r.InvNTT(w1[k], tmp) // coeff domain of w1[k]
		for j := 0; j < ncols; j++ {
			rows[k][j] = EvalPoly(tmp.Coeffs[0], omega[j]%q, q)
		}
	}

	// Row s: w2(ω_j)
	r.InvNTT(w2, tmp)
	rows[s] = make([]uint64, ncols)
	for j := 0; j < ncols; j++ {
		rows[s][j] = EvalPoly(tmp.Coeffs[0], omega[j]%q, q)
	}

	// Row s+1: per‑column product w3[col](ω_col) on the diagonal; 0 elsewhere.
	rows[s+1] = make([]uint64, ncols)
	for col := 0; col < ncols && col < len(w3); col++ {
		r.InvNTT(w3[col], tmp)
		rows[s+1][col] = EvalPoly(tmp.Coeffs[0], omega[col]%q, q)
	}

	return rows
}

func evalAt(r *ring.Ring, p *ring.Poly, x uint64) uint64 {
	coeff := r.NewPoly()
	r.InvNTT(p, coeff)
	return EvalPoly(coeff.Coeffs[0], x%r.Modulus[0], r.Modulus[0])
}

func evalAtIndexF(r *ring.Ring, p *ring.Poly, idx int) uint64 {
	coeff := r.NewPoly()
	r.InvNTT(p, coeff)
	q := r.Modulus[0]
	if len(coeff.Coeffs) == 0 || len(coeff.Coeffs[0]) == 0 {
		return 0
	}
	n := len(coeff.Coeffs[0])
	pos := idx % n
	if pos < 0 {
		pos += n
	}
	return coeff.Coeffs[0][pos] % q
}

func evalAtIndexK(r *ring.Ring, K *kf.Field, p *ring.Poly, idx int) kf.Elem {
	if K == nil {
		return kf.Elem{}
	}
	val := evalAtIndexF(r, p, idx)
	return K.EmbedF(val % K.Q)
}

func evalPolySetAtIndices(r *ring.Ring, polys []*ring.Poly, indices []int) [][]uint64 {
	if len(polys) == 0 || len(indices) == 0 {
		return nil
	}
	N := int(r.N)
	q := r.Modulus[0]
	out := make([][]uint64, len(polys))
	for i := range polys {
		row := make([]uint64, len(indices))
		coeffs := polys[i].Coeffs[0]
		for j, idx := range indices {
			pos := idx % N
			if pos < 0 {
				pos += N
			}
			row[j] = coeffs[pos] % q
		}
		out[i] = row
	}
	return out
}

func makeMaskTailOpening(indices []int, values [][]uint64) *decs.DECSOpening {
	open := &decs.DECSOpening{}
	if len(indices) == 0 {
		return open
	}
	polyCount := len(values)
	tailCount := len(indices)
	pvals := make([][]uint64, tailCount)
	for t := 0; t < tailCount; t++ {
		row := make([]uint64, polyCount)
		for i := 0; i < polyCount; i++ {
			if t < len(values[i]) {
				row[i] = values[i][t]
			}
		}
		pvals[t] = row
	}
	open.Indices = append([]int(nil), indices...)
	open.TailCount = tailCount
	open.MaskBase = 0
	open.MaskCount = 0
	open.Pvals = pvals
	open.R = polyCount
	return open
}

func maxPolyDegree(r *ring.Ring, p *ring.Poly) int {
	coeff := r.NewPoly()
	r.InvNTT(p, coeff)
	for i := len(coeff.Coeffs[0]) - 1; i >= 0; i-- {
		if coeff.Coeffs[0][i]%r.Modulus[0] != 0 {
			return i
		}
	}
	return -1
}

func checkEq4AtK(
	r *ring.Ring, K *kf.Field, e kf.Elem,
	Q, M []*ring.Poly, Fpar, Fagg []*ring.Poly,
	gammaPoly [][]*ring.Poly, gammaAgg [][]uint64,
) bool {
	q := r.Modulus[0]
	evalAtK := func(p *ring.Poly) kf.Elem {
		coeff := r.NewPoly()
		r.InvNTT(p, coeff)
		return K.EvalFPolyAtK(coeff.Coeffs[0], e)
	}
	for i := range Q {
		lhs := evalAtK(Q[i])
		rhs := evalAtK(M[i])
		for j := range Fpar {
			g := evalAtK(gammaPoly[i][j])
			f := evalAtK(Fpar[j])
			rhs = K.Add(rhs, K.Mul(g, f))
		}
		for j := range Fagg {
			g := K.EmbedF(gammaAgg[i][j] % q)
			f := evalAtK(Fagg[j])
			rhs = K.Add(rhs, K.Mul(g, f))
		}
		if !elemEqual(K, lhs, rhs) {
			return false
		}
	}
	return true
}

func checkEq4AtK_K(
	r *ring.Ring, K *kf.Field, e kf.Elem,
	Q []*ring.Poly, MK []*KPoly, Fpar, Fagg []*ring.Poly,
	gammaK [][]KScalar, gammaAggK [][]KScalar,
) bool {
	if K == nil {
		return false
	}
	evalAtK := func(p *ring.Poly) kf.Elem {
		coeff := r.NewPoly()
		r.InvNTT(p, coeff)
		return K.EvalFPolyAtK(coeff.Coeffs[0], e)
	}
	for i := range Q {
		lhs := evalAtK(Q[i])
		rhs := evalKPolyAtK(K, MK[i], e)
		for j := range Fpar {
			g := K.Phi(gammaK[i][j])
			f := evalAtK(Fpar[j])
			rhs = K.Add(rhs, K.Mul(g, f))
		}
		for j := range Fagg {
			g := K.Phi(gammaAggK[i][j])
			f := evalAtK(Fagg[j])
			rhs = K.Add(rhs, K.Mul(g, f))
		}
		if !elemEqual(K, lhs, rhs) {
			return false
		}
	}
	return true
}

func checkEq4OnOmegaK(
	r *ring.Ring, K *kf.Field, omega []uint64,
	Q []*ring.Poly, MK []*KPoly, Fpar, Fagg []*ring.Poly,
	gammaK [][]KScalar, gammaAggK [][]KScalar,
) bool {
	if K == nil {
		return false
	}
	q := r.Modulus[0]
	evalAtF := func(p *ring.Poly, w uint64) kf.Elem {
		coeff := r.NewPoly()
		r.InvNTT(p, coeff)
		return K.EvalFPolyAtK(coeff.Coeffs[0], K.EmbedF(w%q))
	}
	for i := range Q {
		for _, w := range omega {
			lhs := evalAtF(Q[i], w)
			rhs := evalKPolyAtF(K, MK[i], w)
			for j := range Fpar {
				rhs = K.Add(rhs, K.Mul(K.Phi(gammaK[i][j]), evalAtF(Fpar[j], w)))
			}
			for j := range Fagg {
				rhs = K.Add(rhs, K.Mul(K.Phi(gammaAggK[i][j]), evalAtF(Fagg[j], w)))
			}
			if !elemEqual(K, lhs, rhs) {
				return false
			}
		}
	}
	return true
}

func VerifyQK(r *ring.Ring, K *kf.Field, omega []uint64, Q []*ring.Poly) bool {
	if K == nil {
		return false
	}
	coeff := r.NewPoly()
	q := r.Modulus[0]
	for _, Qi := range Q {
		r.InvNTT(Qi, coeff)
		sum := K.Zero()
		for _, w := range omega {
			sum = K.Add(sum, K.EvalFPolyAtK(coeff.Coeffs[0], K.EmbedF(w%q)))
		}
		if !K.IsZero(sum) {
			return false
		}
	}
	return true
}

func checkEq4AtK_K_QK(
	r *ring.Ring, K *kf.Field, e kf.Elem,
	QK, MK []*KPoly, Fpar, Fagg []*ring.Poly,
	gammaK [][]KScalar, gammaAggK [][]KScalar,
) bool {
	if K == nil {
		return false
	}
	coeff := r.NewPoly()
	evalAtK := func(p *ring.Poly) kf.Elem {
		if p == nil {
			return K.Zero()
		}
		r.InvNTT(p, coeff)
		return K.EvalFPolyAtK(coeff.Coeffs[0], e)
	}
	for i := range QK {
		if i >= len(MK) || QK[i] == nil || MK[i] == nil {
			return false
		}
		lhs := evalKPolyAtK(K, QK[i], e)
		rhs := evalKPolyAtK(K, MK[i], e)
		if i < len(gammaK) {
			row := gammaK[i]
			for j := range Fpar {
				if j >= len(row) || Fpar[j] == nil {
					continue
				}
				g := K.Phi(row[j])
				rhs = K.Add(rhs, K.Mul(g, evalAtK(Fpar[j])))
			}
		}
		if i < len(gammaAggK) {
			row := gammaAggK[i]
			for j := range Fagg {
				if j >= len(row) || Fagg[j] == nil {
					continue
				}
				g := K.Phi(row[j])
				rhs = K.Add(rhs, K.Mul(g, evalAtK(Fagg[j])))
			}
		}
		if !elemEqual(K, lhs, rhs) {
			return false
		}
	}
	return true
}

func checkEq4OnOmegaK_QK(
	r *ring.Ring, K *kf.Field, omega []uint64,
	QK, MK []*KPoly, Fpar, Fagg []*ring.Poly,
	gammaK [][]KScalar, gammaAggK [][]KScalar,
) bool {
	if K == nil {
		return false
	}
	if len(QK) != len(MK) {
		return false
	}
	q := r.Modulus[0]
	coeff := r.NewPoly()
	evalAtF := func(p *ring.Poly, w uint64) kf.Elem {
		if p == nil {
			return K.Zero()
		}
		r.InvNTT(p, coeff)
		return K.EvalFPolyAtK(coeff.Coeffs[0], K.EmbedF(w%q))
	}
	for i := range QK {
		if QK[i] == nil || MK[i] == nil {
			return false
		}
		for _, w := range omega {
			lhs := evalKPolyAtF(K, QK[i], w)
			rhs := evalKPolyAtF(K, MK[i], w)
			if i < len(gammaK) {
				row := gammaK[i]
				for j := range Fpar {
					if j >= len(row) || Fpar[j] == nil {
						continue
					}
					g := K.Phi(row[j])
					rhs = K.Add(rhs, K.Mul(g, evalAtF(Fpar[j], w)))
				}
			}
			if i < len(gammaAggK) {
				row := gammaAggK[i]
				for j := range Fagg {
					if j >= len(row) || Fagg[j] == nil {
						continue
					}
					g := K.Phi(row[j])
					rhs = K.Add(rhs, K.Mul(g, evalAtF(Fagg[j], w)))
				}
			}
			if !elemEqual(K, lhs, rhs) {
				return false
			}
		}
	}
	return true
}

func VerifyQK_QK(r *ring.Ring, K *kf.Field, omega []uint64, QK []*KPoly) bool {
	if K == nil {
		return false
	}
	for _, QKi := range QK {
		if QKi == nil {
			return false
		}
		sum := K.Zero()
		for _, w := range omega {
			sum = K.Add(sum, evalKPolyAtF(K, QKi, w))
		}
		if !K.IsZero(sum) {
			return false
		}
	}
	return true
}

func checkFirstLimbConsistencyOmega(r *ring.Ring, K *kf.Field, omega []uint64, Q []*ring.Poly, QK []*KPoly) bool {
	if K == nil {
		return false
	}
	if len(Q) != len(QK) {
		return false
	}
	q := r.Modulus[0]
	coeff := r.NewPoly()
	for i := range Q {
		if Q[i] == nil || QK[i] == nil || len(QK[i].Limbs) == 0 {
			return false
		}
		first := firstLimbToFPoly(r, QK[i])
		if first == nil {
			return false
		}
		r.InvNTT(Q[i], coeff)
		qCoeffs := coeff.Coeffs[0]
		firstCoeffs := first.Coeffs[0]
		if len(qCoeffs) != len(firstCoeffs) {
			return false
		}
		for idx := range qCoeffs {
			if qCoeffs[idx]%q != firstCoeffs[idx]%q {
				return false
			}
		}
		for _, w := range omega {
			expected := EvalPoly(qCoeffs, w%q, q) % q
			kEval := evalKPolyAtF(K, QK[i], w)
			if len(kEval.Limb) == 0 || kEval.Limb[0]%q != expected {
				return false
			}
		}
	}
	return true
}

func checkEq4OnOpening(r *ring.Ring, Q, M []*ring.Poly, _ *lvcs.Opening,
	Fpar []*ring.Poly, Fagg []*ring.Poly, gammaPoly [][]*ring.Poly, gammaAgg [][]uint64, omega []uint64, evalPoints []uint64) bool {
	defer prof.Track(time.Now(), "checkEq4OnOpening")

	q := r.Modulus[0]
	for i := range Q {
		for _, w := range omega {
			lhs := evalAt(r, Q[i], w)
			rhs := evalAt(r, M[i], w)
			for j := range Fpar {
				g := evalAt(r, gammaPoly[i][j], w)
				f := evalAt(r, Fpar[j], w)
				rhs = modAdd(rhs, modMul(g, f, q), q)
			}
			for j := range Fagg {
				g := gammaAgg[i][j]
				f := evalAt(r, Fagg[j], w)
				rhs = modAdd(rhs, modMul(g, f, q), q)
			}
			if lhs != rhs {
				return false
			}
		}
		for _, e := range evalPoints {
			lhs := evalAt(r, Q[i], e)
			rhs := evalAt(r, M[i], e)
			for j := range Fpar {
				g := evalAt(r, gammaPoly[i][j], e)
				f := evalAt(r, Fpar[j], e)
				rhs = modAdd(rhs, modMul(g, f, q), q)
			}
			for j := range Fagg {
				g := gammaAgg[i][j]
				f := evalAt(r, Fagg[j], e)
				rhs = modAdd(rhs, modMul(g, f, q), q)
			}
			if lhs != rhs {
				return false
			}
		}
	}
	return true
}

func checkEq4OnTailOpen(
	r *ring.Ring,
	K *kf.Field,
	theta int,
	tail []int,
	Q []*ring.Poly,
	QK []*KPoly,
	MK []*KPoly,
	Fpar []*ring.Poly,
	Fagg []*ring.Poly,
	gammaF [][]uint64,
	gammaAggF [][]uint64,
	gammaK [][]KScalar,
	gammaAggK [][]KScalar,
	maskOpen *decs.DECSOpening,
) bool {
	if maskOpen == nil {
		return false
	}
	q := r.Modulus[0]
	N := int(r.N)
	posByIdx := make(map[int]int, maskOpen.EntryCount())
	for pos := 0; pos < maskOpen.EntryCount(); pos++ {
		idx := maskOpen.IndexAt(pos)
		posByIdx[idx] = pos
	}
	for _, idx := range tail {
		if _, ok := posByIdx[idx]; !ok {
			return false
		}
	}
	rho := len(Q)
	for i := 0; i < rho; i++ {
		var limbCoeff []*ring.Poly
		var lhsLimbs []uint64
		var maskLimbs []uint64
		if theta > 1 {
			if K == nil || i >= len(QK) || QK[i] == nil {
				return false
			}
			limbCoeff = kpolyToCoeffPolys(r, QK[i])
			lhsLimbs = make([]uint64, theta)
			maskLimbs = make([]uint64, theta)
		}
		for _, idx := range tail {
			pos := posByIdx[idx]
			coeffPos := idx % N
			if coeffPos < 0 {
				coeffPos += N
			}
			if theta > 1 && K != nil {
				for j := 0; j < theta; j++ {
					coeffs := limbCoeff[j].Coeffs[0]
					if coeffPos >= len(coeffs) {
						return false
					}
					lhsLimbs[j] = coeffs[coeffPos] % q
					if i >= len(MK) || MK[i] == nil || coeffPos >= len(MK[i].Limbs[j]) {
						return false
					}
					maskLimbs[j] = MK[i].Limbs[j][coeffPos] % q
				}
				lhs := K.Phi(lhsLimbs)
				rhs := K.Phi(maskLimbs)
				if i < len(gammaK) {
					row := gammaK[i]
					for j := range Fpar {
						if j >= len(row) || Fpar[j] == nil {
							continue
						}
						fval := evalAtIndexF(r, Fpar[j], coeffPos)
						rhs = K.Add(rhs, K.Mul(K.Phi(row[j]), K.EmbedF(fval%q)))
					}
				}
				if i < len(gammaAggK) {
					row := gammaAggK[i]
					for j := range Fagg {
						if j >= len(row) || Fagg[j] == nil {
							continue
						}
						fval := evalAtIndexF(r, Fagg[j], coeffPos)
						rhs = K.Add(rhs, K.Mul(K.Phi(row[j]), K.EmbedF(fval%q)))
					}
				}
				if !elemEqual(K, lhs, rhs) {
					return false
				}
			} else {
				lhs := Q[i].Coeffs[0][coeffPos] % q
				rhs := decs.GetOpeningPval(maskOpen, pos, i) % q
				for j := range Fpar {
					fval := Fpar[j].Coeffs[0][coeffPos] % q
					var g uint64
					if len(gammaF) > i && len(gammaF[i]) > j {
						g = gammaF[i][j] % q
					}
					rhs = modAdd(rhs, modMul(g, fval, q), q)
				}
				for j := range Fagg {
					fval := Fagg[j].Coeffs[0][coeffPos] % q
					var g uint64
					if len(gammaAggF) > i && len(gammaAggF[i]) > j {
						g = gammaAggF[i][j] % q
					}
					rhs = modAdd(rhs, modMul(g, fval, q), q)
				}
				if lhs != rhs {
					return false
				}
			}
		}
	}
	return true
}

func polysToBytes(pp []*ring.Poly) []byte {
	var out []byte
	for _, p := range pp {
		for _, c := range p.Coeffs[0] {
			buf := make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, c)
			out = append(out, buf...)
		}
	}
	return out
}

// Public-data loader (A, b₁, B₀, …) – all NTT‑lifted on return.
func loadPublicTables(ringQ *ring.Ring) (A [][]*ring.Poly, b1, B0Const []*ring.Poly,
	B0Msg, B0Rnd [][]*ring.Poly, err error) {
	defer prof.Track(time.Now(), "loadPublicTables")

	// Build A = [1, -h] from root ntru_keys/public.json
	pk, err := ntrukeys.LoadPublic()
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("ntru_keys/public.json: %w", err)
	}
	A = [][]*ring.Poly{make([]*ring.Poly, 2)}
	one := ringQ.NewPoly()
	one.Coeffs[0][0] = 1
	ringQ.NTT(one, one)
	negHCoeff := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i, v := range pk.HCoeffs {
		vv := v % q
		if vv < 0 {
			vv += q
		}
		if vv == 0 {
			negHCoeff.Coeffs[0][i] = 0
		} else {
			negHCoeff.Coeffs[0][i] = uint64((q - vv) % q)
		}
	}
	ringQ.NTT(negHCoeff, negHCoeff)
	A[0][0], A[0][1] = one, negHCoeff

	rawB, err := ntrurio.LoadBMatrixCoeffs(resolve("Parameters/Bmatrix.json"))
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("Bmatrix.json: %w", err)
	}
	toNTT := func(coeffs []uint64) *ring.Poly {
		p := ringQ.NewPoly()
		copy(p.Coeffs[0], coeffs)
		ringQ.NTT(p, p)
		return p
	}
	B0Const = []*ring.Poly{toNTT(rawB[0])}
	B0Msg = [][]*ring.Poly{{toNTT(rawB[1])}}
	B0Rnd = [][]*ring.Poly{{toNTT(rawB[2])}}
	b1 = []*ring.Poly{toNTT(rawB[3])}

	return A, b1, B0Const, B0Msg, B0Rnd, nil
}
