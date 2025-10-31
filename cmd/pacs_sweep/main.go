package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	P "vSIS-Signature/PIOP"
	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
)

const (
	degreeCap         = 1023
	defaultMinBitsPer = 100.0
	defaultMinBitsTot = 120.0
	defaultBitsSpread = 64.0
	defaultEstSeconds = 0.5
	progressBarWidth  = 40
)

const (
	defaultJSONLPath      = "Additionnals/general_sweep.jsonl"
	defaultCSVPath        = "Additionnals/general_sweep.csv"
	defaultNcolsSpec      = "4,6,8,10,12,14,16"
	defaultEllSpec        = "16,18,20,22,24,26,28,30"
	defaultEllPrimeSpec   = "2,3,4,6,8"
	defaultRhoSpec        = "1,2,3,4"
	defaultThetaSpec      = "1,2,3,4,6,8"
	defaultEtaSpec        = "7,9,11,13,15,17"
	defaultChainWSpec     = "2,3,4,5,6"
	preset192JSONLPath    = "Additionnals/general_sweep_192.jsonl"
	preset192CSVPath      = "Additionnals/general_sweep_192.csv"
	preset192NcolsSpec    = "4,6,8"
	preset192EllSpec      = "34,36,38,40,42,44,46,48"
	preset192EllPrimeSpec = "8,10,12"
	preset192RhoSpec      = "5,6,7"
	preset192ThetaSpec    = "2"
	preset192EtaSpec      = "26,28,30"
	preset192ChainWSpec   = "4,5"
	preset192MinBitsPer   = 190.0
	preset192MinTotal     = 188.0
	preset192MaxSpread    = 160.0
)

const (
	reasonInvalidOpts = "invalid-opts"
	reasonMinBits     = "eps-below-min"
	reasonTotalBits   = "total-bits"
	reasonSpread      = "bits-spread"
	reasonDQCap       = "dq-cap"
	reasonVerdict     = "verifier"
	reasonRunError    = "run-error"
)

type Runner struct {
	lambda           int
	q                uint64
	qBits            float64
	ringN            int
	jsonFile         *os.File
	jsonBuf          *bufio.Writer
	jsonEnc          *json.Encoder
	csvFile          *os.File
	csvWriter        *csv.Writer
	csvHeaderWritten bool
}

type record struct {
	Stage  string                 `json:"stage"`
	Meta   map[string]interface{} `json:"meta,omitempty"`
	Report P.SimReport            `json:"report"`
}

type finalResult struct {
	Stage  string
	Report P.SimReport
}

type gridOverride []string

func (g *gridOverride) String() string {
	return strings.Join(*g, ", ")
}

func (g *gridOverride) Set(value string) error {
	*g = append(*g, value)
	return nil
}

type sweepConfig struct {
	ncols     []int
	ell       []int
	ellPrime  []int
	rho       []int
	theta     []int
	eta       []int
	chainW    []int
	chainL    []int
	nLeaves   []int
	minBits   float64
	minTotal  float64
	maxSpread float64
	estSecs   float64
}

type gridPoint struct {
	Opts P.SimOpts
}

type candidateVariant struct {
	StageID    int
	GrindLevel int
	Opts       P.SimOpts
}

type prediction struct {
	bits      [4]float64
	grinding  [4]float64
	totalBits float64
	dQ        int
	ok        bool
}

type progressBar struct {
	total int
	start time.Time
}

type filterStats struct {
	sampleLimit int
	samples     []rejectionSample
	pred        predCounts
	run         runCounts
	grind       grindCounts
}

type predCounts struct {
	total    int
	accepted int
	invalid  int
	lowBits  int
	lowTotal int
	spread   int
}

type runCounts struct {
	total    int
	accepted int
	dqCap    int
	verdict  int
	lowBits  int
	lowTotal int
	spread   int
	errors   int
}

type grindCounts struct {
	candidates int
	perRound   [4]int
}

type rejectionSample struct {
	Phase  string
	Reason string
	Opts   P.SimOpts
	Bits   [4]float64
	Total  float64
	DQ     int
}

func newFilterStats(limit int) *filterStats {
	if limit < 0 {
		limit = 0
	}
	return &filterStats{sampleLimit: limit}
}

func (fs *filterStats) recordPredAccept() {
	fs.pred.total++
	fs.pred.accepted++
}

func (fs *filterStats) recordPredReject(reason string, pt gridPoint, pred prediction) {
	fs.pred.total++
	switch reason {
	case reasonInvalidOpts:
		fs.pred.invalid++
	case reasonMinBits:
		fs.pred.lowBits++
	case reasonTotalBits:
		fs.pred.lowTotal++
	case reasonSpread:
		fs.pred.spread++
	}
	fs.addSample("prediction", reason, pt.Opts, pred.bits, pred.totalBits, pred.dQ)
}

func (fs *filterStats) recordRunAccept() {
	fs.run.total++
	fs.run.accepted++
}

func (fs *filterStats) recordRunReject(reason string, opts P.SimOpts, rep P.SimReport) {
	fs.run.total++
	switch reason {
	case reasonDQCap:
		fs.run.dqCap++
	case reasonVerdict:
		fs.run.verdict++
	case reasonMinBits:
		fs.run.lowBits++
	case reasonTotalBits:
		fs.run.lowTotal++
	case reasonSpread:
		fs.run.spread++
	}
	fs.addSample("post-run", reason, opts, rep.Soundness.Bits, rep.Soundness.TotalBits, rep.Soundness.DQ)
}

func (fs *filterStats) recordRunError() {
	fs.run.total++
	fs.run.errors++
}

func (fs *filterStats) recordGrinding(additions [4]int) {
	if fs == nil {
		return
	}
	applied := false
	for i, add := range additions {
		if add <= 0 {
			continue
		}
		fs.grind.perRound[i] += add
		applied = true
	}
	if applied {
		fs.grind.candidates++
	}
}

func (fs *filterStats) PrintPredictionSummary() {
	if fs.pred.total == 0 {
		return
	}
	fmt.Println("Prediction filter breakdown:")
	fmt.Printf("  grid points evaluated: %d\n", fs.pred.total)
	fmt.Printf("  queued for simulation: %d (%.1f%%)\n", fs.pred.accepted, percent(fs.pred.accepted, fs.pred.total))
	rejected := fs.pred.total - fs.pred.accepted
	if rejected == 0 {
		return
	}
	fmt.Printf("  rejected before simulation: %d (%.1f%%)\n", rejected, percent(rejected, fs.pred.total))
	fs.printReason("    invalid parameter tuple", fs.pred.invalid, fs.pred.total)
	fs.printReason("    ε bits below min", fs.pred.lowBits, fs.pred.total)
	fs.printReason("    total bits below min", fs.pred.lowTotal, fs.pred.total)
	fs.printReason("    bits spread above limit", fs.pred.spread, fs.pred.total)
}

func (fs *filterStats) PrintRunSummary() {
	if fs.run.total == 0 {
		return
	}
	fmt.Println("Post-simulation filter breakdown:")
	fmt.Printf("  candidates executed: %d\n", fs.run.total)
	fmt.Printf("  accepted after simulation: %d (%.1f%%)\n", fs.run.accepted, percent(fs.run.accepted, fs.run.total))
	fs.printReason("    degree cap exceeded", fs.run.dqCap, fs.run.total)
	fs.printReason("    verifier rejected", fs.run.verdict, fs.run.total)
	fs.printReason("    ε bits below min", fs.run.lowBits, fs.run.total)
	fs.printReason("    total bits below min", fs.run.lowTotal, fs.run.total)
	fs.printReason("    bits spread above limit", fs.run.spread, fs.run.total)
	if fs.run.errors > 0 {
		fmt.Printf("    runtime errors: %d (%.1f%%)\n", fs.run.errors, percent(fs.run.errors, fs.run.total))
	}
}

func (fs *filterStats) PrintSamples() {
	if fs.sampleLimit == 0 || len(fs.samples) == 0 {
		return
	}
	fmt.Println("Filtered-out sample details:")
	for idx, sample := range fs.samples {
		fmt.Printf("  %d. [%s] %-12s ncols=%d ell=%d ellp=%d rho=%d theta=%d eta=%d W=%d L=%d bits=[%.1f, %.1f, %.1f, %.1f] total=%.2f dQ=%d\n",
			idx+1,
			sample.Phase,
			sample.Reason,
			sample.Opts.NCols,
			sample.Opts.Ell,
			sample.Opts.EllPrime,
			sample.Opts.Rho,
			sample.Opts.Theta,
			sample.Opts.Eta,
			sample.Opts.ChainW,
			sample.Opts.ChainL,
			sample.Bits[0],
			sample.Bits[1],
			sample.Bits[2],
			sample.Bits[3],
			sample.Total,
			sample.DQ,
		)
	}
}

func (fs *filterStats) PrintGrindingSummary() {
	if fs.grind.candidates == 0 {
		return
	}
	fmt.Printf("Grinding boosts applied to %d candidates\n", fs.grind.candidates)
	fmt.Printf("  per-round additions (bits): [%d, %d, %d, %d]\n",
		fs.grind.perRound[0],
		fs.grind.perRound[1],
		fs.grind.perRound[2],
		fs.grind.perRound[3])
}

func (fs *filterStats) addSample(phase, reason string, opts P.SimOpts, bits [4]float64, total float64, dQ int) {
	if fs.sampleLimit <= 0 || len(fs.samples) >= fs.sampleLimit {
		return
	}
	fs.samples = append(fs.samples, rejectionSample{
		Phase:  phase,
		Reason: reason,
		Opts:   opts,
		Bits:   bits,
		Total:  total,
		DQ:     dQ,
	})
}

func (fs *filterStats) printReason(label string, count, total int) {
	if count == 0 || total == 0 {
		return
	}
	fmt.Printf("%s: %d (%.1f%%)\n", label, count, percent(count, total))
}

func computeGrindingAdditions(bits [4]float64) [4]int {
	maxBit := math.Inf(-1)
	for _, b := range bits {
		if math.IsInf(b, 1) {
			continue
		}
		if b > maxBit {
			maxBit = b
		}
	}
	var adds [4]int
	if math.IsInf(maxBit, -1) {
		return adds
	}
	for i, b := range bits {
		if math.IsInf(b, 1) {
			continue
		}
		gap := maxBit - b
		if gap > 2 {
			add := int(math.Ceil(gap - 2))
			if add < 1 {
				add = 1
			}
			if add > 2 {
				add = 2
			}
			adds[i] = add
		}
	}
	return adds
}

func applyGrindingAdditions(opts *P.SimOpts, adds [4]int, maxLevel int) bool {
	if opts == nil {
		return false
	}
	applied := false
	for i, add := range adds {
		if add <= 0 {
			continue
		}
		if maxLevel >= 0 && add > maxLevel {
			add = maxLevel
		}
		if add > 2 {
			add = 2
		}
		if add <= 0 {
			continue
		}
		if opts.Kappa[i] < add {
			opts.Kappa[i] = add
			applied = true
		}
	}
	return applied
}

func grindLevels(adds [4]int) []int {
	max := 0
	for _, a := range adds {
		if a > max {
			max = a
		}
	}
	switch {
	case max <= 0:
		return []int{0}
	case max == 1:
		return []int{0, 1}
	default:
		return []int{0, 1, 2}
	}
}

func hasGrinding(adds [4]int) bool {
	for _, a := range adds {
		if a > 0 {
			return true
		}
	}
	return false
}

func newRunner(jsonPath, csvPath string, lambda int) (*Runner, error) {
	par, err := ntrurio.LoadParams("Parameters/Parameters.json", true)
	if err != nil {
		return nil, err
	}
	r := &Runner{
		lambda: lambda,
		q:      par.Q,
		qBits:  math.Log2(float64(par.Q)),
		ringN:  int(par.N),
	}
	if jsonPath != "" {
		if err := os.MkdirAll(dirOf(jsonPath), 0o755); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("create json dir: %w", err)
		}
		f, err := os.Create(jsonPath)
		if err != nil {
			return nil, fmt.Errorf("open json output: %w", err)
		}
		buf := bufio.NewWriter(f)
		r.jsonFile = f
		r.jsonBuf = buf
		r.jsonEnc = json.NewEncoder(buf)
	}
	if csvPath != "" {
		if err := os.MkdirAll(dirOf(csvPath), 0o755); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("create csv dir: %w", err)
		}
		f, err := os.Create(csvPath)
		if err != nil {
			return nil, fmt.Errorf("open csv output: %w", err)
		}
		r.csvFile = f
		r.csvWriter = csv.NewWriter(f)
	}
	return r, nil
}

func (r *Runner) Close() {
	if r.jsonBuf != nil {
		_ = r.jsonBuf.Flush()
	}
	if r.jsonFile != nil {
		_ = r.jsonFile.Close()
	}
	if r.csvWriter != nil {
		r.csvWriter.Flush()
	}
	if r.csvFile != nil {
		_ = r.csvFile.Close()
	}
}

func main() {
	jsonPath := flag.String("jsonl", defaultJSONLPath, "JSONL output path")
	csvPath := flag.String("csv", defaultCSVPath, "CSV output path")
	lambda := flag.Int("lambda", 128, "Fiat–Shamir security parameter λ")
	lambdaPreset192 := flag.Bool("lambda-192", false, "use preset grid targeting ≈2^192 total soundness")

	minBitsPer := flag.Float64("min_bits_per", defaultMinBitsPer, "minimum ε component bits required to queue a candidate")
	minBitsTotal := flag.Float64("min_bits_total", defaultMinBitsTot, "minimum total soundness bits required to queue a candidate")
	maxBitsSpread := flag.Float64("max_bits_spread", defaultBitsSpread, "reject candidates if ε components differ by more than this many bits (≤0 disables)")
	estSeconds := flag.Float64("est_seconds", defaultEstSeconds, "estimated seconds per simulation (for ETA display)")

	ncolsSpec := flag.String("ncols", defaultNcolsSpec, "ncols grid (comma list or start..end[:step])")
	ellSpec := flag.String("ell", defaultEllSpec, "ℓ grid")
	ellPrimeSpec := flag.String("ellp", defaultEllPrimeSpec, "ℓ' grid")
	rhoSpec := flag.String("rho", defaultRhoSpec, "ρ grid")
	thetaSpec := flag.String("theta", defaultThetaSpec, "θ grid")
	etaSpec := flag.String("eta", defaultEtaSpec, "η grid")
	chainWSpec := flag.String("W", defaultChainWSpec, "ℓ∞ chain window bits (B=2^W)")
	chainLSpec := flag.String("L", "0,1,2,3", "ℓ∞ chain digit counts (0=auto)")
	leavesSpec := flag.String("nleaves", "0", "Merkle leaf counts (0 = ring dimension)")
	logRejects := flag.Int("log_rejections", 0, "print details for the first N filtered-out candidates (prediction or post-run)")

	var gridSpecs gridOverride
	flag.Var(&gridSpecs, "grid", "grid override spec (key=values;key=values). May be repeated.")

	flag.Parse()

	if *lambdaPreset192 {
		*lambda = 256
		if *jsonPath == defaultJSONLPath {
			*jsonPath = preset192JSONLPath
		}
		if *csvPath == defaultCSVPath {
			*csvPath = preset192CSVPath
		}
		if *minBitsPer == defaultMinBitsPer {
			*minBitsPer = preset192MinBitsPer
		}
		if *minBitsTotal == defaultMinBitsTot {
			*minBitsTotal = preset192MinTotal
		}
		if *maxBitsSpread == defaultBitsSpread {
			*maxBitsSpread = preset192MaxSpread
		}
		if *ncolsSpec == defaultNcolsSpec {
			*ncolsSpec = preset192NcolsSpec
		}
		if *ellSpec == defaultEllSpec {
			*ellSpec = preset192EllSpec
		}
		if *ellPrimeSpec == defaultEllPrimeSpec {
			*ellPrimeSpec = preset192EllPrimeSpec
		}
		if *rhoSpec == defaultRhoSpec {
			*rhoSpec = preset192RhoSpec
		}
		if *thetaSpec == defaultThetaSpec {
			*thetaSpec = preset192ThetaSpec
		}
		if *etaSpec == defaultEtaSpec {
			*etaSpec = preset192EtaSpec
		}
		if *chainWSpec == defaultChainWSpec {
			*chainWSpec = preset192ChainWSpec
		}
	}

	runner, err := newRunner(*jsonPath, *csvPath, *lambda)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init runner: %v\n", err)
		os.Exit(1)
	}
	defer runner.Close()

	cfg := sweepConfig{
		minBits:   *minBitsPer,
		minTotal:  *minBitsTotal,
		maxSpread: *maxBitsSpread,
		estSecs:   *estSeconds,
	}

	if cfg.ncols, err = parseIntList(*ncolsSpec); err != nil {
		exitErr("parse ncols: %v", err)
	}
	if cfg.ell, err = parseIntList(*ellSpec); err != nil {
		exitErr("parse ell: %v", err)
	}
	if cfg.ellPrime, err = parseIntList(*ellPrimeSpec); err != nil {
		exitErr("parse ellp: %v", err)
	}
	if cfg.rho, err = parseIntList(*rhoSpec); err != nil {
		exitErr("parse rho: %v", err)
	}
	if cfg.theta, err = parseIntList(*thetaSpec); err != nil {
		exitErr("parse theta: %v", err)
	}
	if cfg.eta, err = parseIntList(*etaSpec); err != nil {
		exitErr("parse eta: %v", err)
	}
	if cfg.chainW, err = parseIntList(*chainWSpec); err != nil {
		exitErr("parse W: %v", err)
	}
	if cfg.chainL, err = parseIntList(*chainLSpec); err != nil {
		exitErr("parse L: %v", err)
	}
	if cfg.nLeaves, err = parseIntList(*leavesSpec); err != nil {
		exitErr("parse nleaves: %v", err)
	}

	if err := cfg.applyGridOverrides(gridSpecs); err != nil {
		exitErr("grid override: %v", err)
	}
	cfg.ensureDefaults()
	cfg.chainL = []int{0}

	// Ensure seed-derived witnesses use default bounds so β stays within the
	// expected range for the Linf gadget.
	if err := ntru.SetSeedPolyBounds(ntru.DefaultSeedPolyBounds); err != nil {
		exitErr("reset seed bounds: %v", err)
	}

	var baseline P.SimOpts
	if *lambdaPreset192 {
		baseline = P.SimOpts{
			NCols:    6,
			Ell:      40,
			EllPrime: 10,
			Rho:      6,
			Eta:      28,
			NLeaves:  0,
			Theta:    2,
			ChainW:   5,
			ChainL:   0,
			Lambda:   *lambda,
		}
	} else {
		baseline = P.SimOpts{
			NCols:    8,
			Ell:      24,
			EllPrime: 2,
			Rho:      1,
			Eta:      7,
			NLeaves:  0,
			Theta:    1,
			ChainW:   4,
			ChainL:   0,
			Lambda:   *lambda,
		}
	}
	basePred := predictCandidate(runner, baseline)
	baseAdds := computeGrindingAdditions(basePred.bits)
	applyGrindingAdditions(&baseline, baseAdds, -1)

	baseReport, err := runner.Run("baseline", baseline, map[string]interface{}{"note": "baseline"})
	if err != nil {
		exitErr("baseline: %v", err)
	}

	points := enumerateGrid(cfg, *lambda)
	fmt.Printf("Enumerated %d grid points\n", len(points))

	stats := newFilterStats(*logRejects)
	candidates := make([]candidateVariant, 0, len(points)*3)
	for idx, pt := range points {
		pred := predictCandidate(runner, pt.Opts)
		reason := predictionRejectReason(pred, cfg)
		if reason != "" {
			stats.recordPredReject(reason, pt, pred)
			continue
		}
		opts := pt.Opts
		adds := computeGrindingAdditions(pred.bits)
		if hasGrinding(adds) {
			stats.recordGrinding(adds)
		}
		levels := grindLevels(adds)
		for _, level := range levels {
			variant := opts
			applyGrindingAdditions(&variant, adds, level)
			stats.recordPredAccept()
			candidates = append(candidates, candidateVariant{
				StageID:    idx + 1,
				GrindLevel: level,
				Opts:       variant,
			})
		}
	}

	stats.PrintPredictionSummary()
	fmt.Printf("Accepted %d candidates after prediction filter (%.1f%% of grid)\n", len(candidates), percent(len(candidates), len(points)))
	if len(candidates) == 0 {
		stats.PrintSamples()
		fmt.Println("No candidates left after filtering; exiting.")
		return
	}
	planned := len(candidates)
	fmt.Printf("Planned simulations: 1 baseline + %d candidates (est %.1fs)\n", planned, cfg.estSecs*float64(planned))

	bar := newProgressBar(planned)
	finals := []finalResult{{Stage: "baseline", Report: baseReport}}
	for idx, cand := range candidates {
		stage := fmt.Sprintf("grid[%d]/g%d", cand.StageID, cand.GrindLevel)
		meta := map[string]interface{}{
			"part":        "grid",
			"stage_id":    cand.StageID,
			"ncols":       cand.Opts.NCols,
			"ell":         cand.Opts.Ell,
			"ellp":        cand.Opts.EllPrime,
			"rho":         cand.Opts.Rho,
			"theta":       cand.Opts.Theta,
			"eta":         cand.Opts.Eta,
			"nleaves":     cand.Opts.NLeaves,
			"chain_W":     cand.Opts.ChainW,
			"chain_L":     cand.Opts.ChainL,
			"grind_level": cand.GrindLevel,
		}
		meta["kappa"] = cand.Opts.Kappa

		rep, err := runner.Run(stage, cand.Opts, meta)
		bar.Update(idx + 1)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\n%s failed: %v\n", stage, err)
			stats.recordRunError()
			continue
		}
		reason := runRejectReason(rep, cfg)
		if reason != "" {
			stats.recordRunReject(reason, cand.Opts, rep)
			continue
		}
		stats.recordRunAccept()
		finals = append(finals, finalResult{Stage: stage, Report: rep})
	}

	stats.PrintRunSummary()
	stats.PrintGrindingSummary()
	stats.PrintSamples()

	fmt.Println()
	if len(finals) == 0 {
		fmt.Println("No candidates satisfied security targets.")
		return
	}
	runner.PrintFinalSummary(finals)
}

func dirOf(path string) string {
	if path == "" {
		return "."
	}
	last := strings.LastIndexByte(path, '/')
	if last == -1 {
		return "."
	}
	if last == 0 {
		return "/"
	}
	return path[:last]
}

func safeRunOnce(opts P.SimOpts) (rep P.SimReport, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic: %v", rec)
		}
	}()
	return P.RunOnce(opts)
}

func (r *Runner) Run(stage string, opts P.SimOpts, meta map[string]interface{}) (P.SimReport, error) {
	rep, err := safeRunOnce(opts)
	if err != nil {
		return rep, err
	}
	rec := record{Stage: stage, Meta: cloneMeta(meta), Report: rep}
	if r.jsonEnc != nil {
		if err := r.jsonEnc.Encode(rec); err != nil {
			fmt.Fprintf(os.Stderr, "json encode: %v\n", err)
		}
		if r.jsonBuf != nil {
			_ = r.jsonBuf.Flush()
		}
	}
	if r.csvWriter != nil {
		if !r.csvHeaderWritten {
			r.writeCSVHeader()
		}
		if err := r.writeCSVRow(stage, rep); err != nil {
			fmt.Fprintf(os.Stderr, "csv write: %v\n", err)
		}
	}
	return rep, nil
}

func (r *Runner) writeCSVHeader() {
	if r.csvWriter == nil {
		return
	}
	header := []string{
		"stage", "proof_bytes", "total_bits",
		"eps1_bits", "eps2_bits", "eps3_bits", "eps4_bits",
		"ncols", "ell", "ellp", "rho", "theta", "eta", "nleaves",
		"chain_W", "chain_L", "chain_base",
		"parallel_deg", "aggregated_deg", "dQ",
	}
	_ = r.csvWriter.Write(header)
	r.csvHeaderWritten = true
}

func (r *Runner) writeCSVRow(stage string, rep P.SimReport) error {
	if r.csvWriter == nil {
		return nil
	}
	sb := rep.Soundness
	row := []string{
		stage,
		fmt.Sprintf("%d", rep.ProofBytes),
		fmt.Sprintf("%.2f", sb.TotalBits),
		fmt.Sprintf("%.2f", sb.Bits[0]),
		fmt.Sprintf("%.2f", sb.Bits[1]),
		fmt.Sprintf("%.2f", sb.Bits[2]),
		fmt.Sprintf("%.2f", sb.Bits[3]),
		fmt.Sprintf("%d", rep.NCols),
		fmt.Sprintf("%d", rep.Ell),
		fmt.Sprintf("%d", rep.EllPrime),
		fmt.Sprintf("%d", rep.Rho),
		fmt.Sprintf("%d", rep.Theta),
		fmt.Sprintf("%d", rep.Eta),
		fmt.Sprintf("%d", rep.NLeaves),
		fmt.Sprintf("%d", rep.Chain.W),
		fmt.Sprintf("%d", rep.Chain.L),
		fmt.Sprintf("%d", rep.Chain.Base),
		fmt.Sprintf("%d", rep.ParallelDeg),
		fmt.Sprintf("%d", rep.AggregatedDeg),
		fmt.Sprintf("%d", sb.DQ),
	}
	return r.csvWriter.Write(row)
}

func (r *Runner) PrintFinalSummary(finals []finalResult) {
	if len(finals) == 0 {
		fmt.Println("No candidates to display.")
		return
	}
	sort.Slice(finals, func(i, j int) bool {
		if finals[i].Report.ProofBytes == finals[j].Report.ProofBytes {
			return finals[i].Report.Soundness.TotalBits > finals[j].Report.Soundness.TotalBits
		}
		return finals[i].Report.ProofBytes < finals[j].Report.ProofBytes
	})
	fmt.Println("Final parameter sets sorted by proof size:")
	fmt.Println("ProofKB  Bytes   Stage         s  W  L  θ  ρ  ℓ'  ncols  η  ℓ   N  d  dQ  eps1  eps2  eps3  eps4  TotalBits")
	for _, fr := range finals {
		rep := fr.Report
		sb := rep.Soundness
		fmt.Printf("%7.2f  %6d  %-12s  %2d %2d %2d %2d %2d %3d %5d %2d %2d %3d %2d %3d  %6.1f %6.1f %6.1f %6.1f  %9.2f\n",
			float64(rep.ProofBytes)/1024.0,
			rep.ProofBytes,
			fr.Stage,
			rep.NCols,
			rep.Chain.W,
			rep.Chain.L,
			rep.Theta,
			rep.Rho,
			rep.EllPrime,
			rep.NCols,
			rep.Eta,
			rep.Ell,
			rep.NLeaves,
			rep.ParallelDeg,
			sb.DQ,
			sb.Bits[0],
			sb.Bits[1],
			sb.Bits[2],
			sb.Bits[3],
			sb.TotalBits,
		)
	}
}

func enumerateGrid(cfg sweepConfig, lambda int) []gridPoint {
	points := []gridPoint{}
	for _, ncols := range cfg.ncols {
		for _, ell := range cfg.ell {
			for _, ellp := range cfg.ellPrime {
				for _, rho := range cfg.rho {
					for _, theta := range cfg.theta {
						for _, eta := range cfg.eta {
							for _, W := range cfg.chainW {
								for _, L := range cfg.chainL {
									if L != 0 && L < 2 {
										// Linf chain needs either auto-selection (0) or at least two digits.
										continue
									}
									for _, leaves := range cfg.nLeaves {
										opts := P.SimOpts{
											NCols:    ncols,
											Ell:      ell,
											EllPrime: ellp,
											Rho:      rho,
											Theta:    theta,
											Eta:      eta,
											NLeaves:  leaves,
											ChainW:   W,
											ChainL:   L,
											Lambda:   lambda,
										}
										points = append(points, gridPoint{Opts: opts})
									}
								}
							}
						}
					}
				}
			}
		}
	}
	return points
}

func predictCandidate(r *Runner, opts P.SimOpts) prediction {
	ncols := opts.NCols
	ell := opts.Ell
	ellPrime := opts.EllPrime
	rho := opts.Rho
	theta := opts.Theta
	eta := opts.Eta
	if ncols <= 0 || ell <= 0 || ellPrime <= 0 || rho <= 0 || theta <= 0 || eta <= 0 {
		return prediction{ok: false}
	}
	dQ := estimateDQ(opts)
	nLeaves := opts.NLeaves
	if nLeaves <= 0 {
		nLeaves = r.ringN
	}
	fieldBits := r.qBits * float64(theta)
	fieldSize := math.Pow(float64(r.q), float64(theta))

	ddecs := ncols + ell - 1
	bits1 := float64(eta)*math.Log2(float64(r.q)) - logComb2(float64(nLeaves), ddecs+2)
	if math.IsInf(bits1, -1) || bits1 < 0 {
		bits1 = 0
	}
	eps1 := math.Pow(2, -bits1)

	var bits2 float64
	if theta > 1 {
		bits2 = float64(rho) * fieldBits
	} else {
		bits2 = float64(rho) * r.qBits
	}
	eps2 := math.Pow(2, -bits2)

	if ellPrime < 1 {
		ellPrime = 1
	}
	Ssize := fieldSize - float64(ncols)
	if Ssize < 1 {
		Ssize = 1
	}
	bits3 := logComb2(Ssize, ellPrime) - logComb2(float64(dQ), ellPrime)
	if math.IsInf(bits3, -1) {
		bits3 = math.Inf(1)
	}
	if bits3 < 0 {
		bits3 = 0
	}
	eps3 := math.Pow(2, -bits3)

	bits4 := logComb2(float64(nLeaves), ell) - logComb2(float64(ncols+ell-1), ell)
	if bits4 < 0 {
		bits4 = 0
	}
	eps4 := math.Pow(2, -bits4)

	var grindingBits [4]float64
	var grindingEps [4]float64
	for i := 0; i < 4; i++ {
		kappa := opts.Kappa[i]
		diff := float64(opts.Lambda - kappa)
		grindingBits[i] = diff
		grindingEps[i] = math.Pow(2, -diff)
	}

	total := eps1 + eps2 + eps3 + eps4
	for _, ge := range grindingEps {
		total += ge
	}
	totalBits := math.Inf(1)
	if total > 0 {
		totalBits = -math.Log2(total)
	}

	return prediction{
		bits:      [4]float64{bits1, bits2, bits3, bits4},
		grinding:  grindingBits,
		totalBits: totalBits,
		dQ:        dQ,
		ok:        true,
	}
}

func estimateDQ(opts P.SimOpts) int {
	ncols := opts.NCols
	span := opts.EllPrime + ncols - 1
	parallelDeg := 1
	if opts.ChainW > 0 {
		parallelDeg = 1 << opts.ChainW
	}
	const aggregatedDeg = 1
	c1 := parallelDeg*span + (ncols - 1)
	c2 := aggregatedDeg * span
	dq := c1
	if c2 > dq {
		dq = c2
	}
	if opts.DQOverride > 0 {
		dq = opts.DQOverride
	}
	return dq
}

func parseIntList(spec string) ([]int, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	values := map[int]struct{}{}
	tokens := strings.Split(spec, ",")
	for _, tok := range tokens {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "..") {
			rangeVals, err := expandRange(tok)
			if err != nil {
				return nil, err
			}
			for _, v := range rangeVals {
				values[v] = struct{}{}
			}
			continue
		}
		v, err := parseInt(tok)
		if err != nil {
			return nil, err
		}
		values[v] = struct{}{}
	}
	if len(values) == 0 {
		return nil, errors.New("empty value set")
	}
	out := make([]int, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Ints(out)
	return out, nil
}

func expandRange(rng string) ([]int, error) {
	step := 1
	rangePart := rng
	if strings.Contains(rng, ":") {
		parts := strings.SplitN(rng, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid range %q", rng)
		}
		rangePart = parts[0]
		val, err := parseInt(strings.TrimSpace(parts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid step in %q: %w", rng, err)
		}
		if val <= 0 {
			return nil, fmt.Errorf("step must be >0 in %q", rng)
		}
		step = val
	}
	bounds := strings.SplitN(rangePart, "..", 2)
	if len(bounds) != 2 {
		return nil, fmt.Errorf("invalid range %q", rng)
	}
	start, err := parseInt(strings.TrimSpace(bounds[0]))
	if err != nil {
		return nil, fmt.Errorf("invalid start in %q: %w", rng, err)
	}
	end, err := parseInt(strings.TrimSpace(bounds[1]))
	if err != nil {
		return nil, fmt.Errorf("invalid end in %q: %w", rng, err)
	}
	if end < start {
		return nil, fmt.Errorf("range end < start in %q", rng)
	}
	out := []int{}
	for v := start; v <= end; v += step {
		out = append(out, v)
	}
	return out, nil
}

func parseInt(tok string) (int, error) {
	val, err := strconvParseInt(tok)
	if err != nil {
		return 0, err
	}
	return val, nil
}

func (cfg *sweepConfig) applyGridOverrides(overrides []string) error {
	for _, spec := range overrides {
		entries := strings.Split(spec, ";")
		for _, entry := range entries {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.SplitN(entry, "=", 2)
			if len(parts) != 2 {
				return fmt.Errorf("invalid grid override %q", entry)
			}
			key := strings.TrimSpace(strings.ToLower(parts[0]))
			vals, err := parseIntList(parts[1])
			if err != nil {
				return fmt.Errorf("%s: %w", key, err)
			}
			switch key {
			case "ncols", "s":
				cfg.ncols = vals
			case "ell", "l":
				cfg.ell = vals
			case "ellp", "ellprime":
				cfg.ellPrime = vals
			case "rho":
				cfg.rho = vals
			case "theta":
				cfg.theta = vals
			case "eta":
				cfg.eta = vals
			case "w", "chain_w":
				cfg.chainW = vals
			case "chainl", "chain_l", "lchain":
				cfg.chainL = vals
			case "nleaves", "leaves", "n":
				cfg.nLeaves = vals
			default:
				return fmt.Errorf("unknown grid key %q", key)
			}
		}
	}
	return nil
}

func (cfg *sweepConfig) ensureDefaults() {
	if len(cfg.ncols) == 0 {
		cfg.ncols = []int{8}
	}
	if len(cfg.ell) == 0 {
		cfg.ell = append([]int(nil), cfg.ncols...)
	}
	if len(cfg.ellPrime) == 0 {
		cfg.ellPrime = []int{2}
	}
	if len(cfg.rho) == 0 {
		cfg.rho = []int{1}
	}
	if len(cfg.theta) == 0 {
		cfg.theta = []int{1}
	}
	if len(cfg.eta) == 0 {
		cfg.eta = []int{7}
	}
	if len(cfg.chainW) == 0 {
		cfg.chainW = []int{4}
	}
	if len(cfg.chainL) == 0 {
		cfg.chainL = []int{0}
	}
	if len(cfg.nLeaves) == 0 {
		cfg.nLeaves = []int{0}
	}
}

func (bar *progressBar) Update(done int) {
	if bar.total <= 0 {
		return
	}
	if done > bar.total {
		done = bar.total
	}
	if bar.start.IsZero() {
		bar.start = time.Now()
	}
	ratio := float64(done) / float64(bar.total)
	filled := int(ratio * progressBarWidth)
	if filled > progressBarWidth {
		filled = progressBarWidth
	}
	barStr := strings.Repeat("█", filled) + strings.Repeat(" ", progressBarWidth-filled)
	elapsed := time.Since(bar.start)
	var eta time.Duration
	if done > 0 && done < bar.total {
		eta = time.Duration(float64(elapsed) * (float64(bar.total-done) / float64(done)))
	}
	fmt.Printf("\r\033[32m[%s]\033[0m %3.0f%% (%3d/%3d) ETA %s", barStr, ratio*100, done, bar.total, formatDuration(eta))
	if done == bar.total {
		fmt.Print("\n")
	}
}

func newProgressBar(total int) *progressBar {
	return &progressBar{total: total}
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "--s"
	}
	sec := d.Round(time.Second)
	return sec.String()
}

func bitsAllAbove(bits [4]float64, thresh float64) bool {
	if thresh <= 0 {
		return true
	}
	for _, b := range bits {
		if math.IsInf(b, 1) {
			continue
		}
		if b < thresh {
			return false
		}
	}
	return true
}

func bitsWithinSpread(bits [4]float64, limit float64) bool {
	if limit <= 0 {
		return true
	}
	min := math.Inf(1)
	max := math.Inf(-1)
	for _, b := range bits {
		if math.IsInf(b, 1) {
			continue
		}
		if b < min {
			min = b
		}
		if b > max {
			max = b
		}
	}
	if math.IsInf(min, 1) && math.IsInf(max, -1) {
		return true
	}
	return (max - min) <= limit
}

func predictionRejectReason(pred prediction, cfg sweepConfig) string {
	if !pred.ok {
		return reasonInvalidOpts
	}
	if !bitsAllAbove(pred.bits, cfg.minBits) {
		return reasonMinBits
	}
	if pred.totalBits < cfg.minTotal {
		return reasonTotalBits
	}
	if !bitsWithinSpread(pred.bits, cfg.maxSpread) {
		return reasonSpread
	}
	return ""
}

func runRejectReason(rep P.SimReport, cfg sweepConfig) string {
	if rep.Soundness.DQ > degreeCap {
		return reasonDQCap
	}
	if !verdictOK(rep.Verdict) {
		return reasonVerdict
	}
	if !bitsAllAbove(rep.Soundness.Bits, cfg.minBits) {
		return reasonMinBits
	}
	if rep.Soundness.TotalBits < cfg.minTotal {
		return reasonTotalBits
	}
	if !bitsWithinSpread(rep.Soundness.Bits, cfg.maxSpread) {
		return reasonSpread
	}
	return ""
}

func verdictOK(v P.SimVerdict) bool {
	return v.OkLin && v.OkEq4 && v.OkSum
}

func cloneMeta(meta map[string]interface{}) map[string]interface{} {
	if meta == nil {
		return nil
	}
	out := make(map[string]interface{}, len(meta))
	for k, v := range meta {
		out[k] = v
	}
	return out
}

func percent(part, total int) float64 {
	if total == 0 {
		return 0
	}
	return 100 * float64(part) / float64(total)
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
	if float64(k) > n/2 {
		k = int(n) - k
	}
	if k <= 32 {
		var sum float64
		for i := 0; i < k; i++ {
			sum += math.Log2(n - float64(i))
			sum -= math.Log2(float64(i + 1))
		}
		return sum
	}
	nPlus, _ := math.Lgamma(n + 1)
	kPlus, _ := math.Lgamma(float64(k) + 1)
	nMinusKPlus, _ := math.Lgamma(n - float64(k) + 1)
	return (nPlus - kPlus - nMinusKPlus) / math.Ln2
}

func exitErr(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

// strconvParseInt is a thin wrapper around strconv.Atoi but keeps the import list short.
func strconvParseInt(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty string")
	}
	sign := 1
	if strings.HasPrefix(s, "-") {
		sign = -1
		s = s[1:]
	}
	var val int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid digit %q", ch)
		}
		val = val*10 + int(ch-'0')
	}
	return sign * val, nil
}
