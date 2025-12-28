package main

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/issuance"
	"vSIS-Signature/ntru"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

type sweepConfig struct {
	ncols    []int
	ell      []int
	ellPrime []int
	rho      []int
	theta    []int
	eta      []int
}

type sweepRow struct {
	TargetBits    int     `json:"target_bits"`
	NCols         int     `json:"ncols"`
	Ell           int     `json:"ell"`
	EllPrime      int     `json:"ell_prime"`
	Rho           int     `json:"rho"`
	Theta         int     `json:"theta"`
	Eta           int     `json:"eta"`
	IssBits       float64 `json:"issuance_bits"`
	ShowBits      float64 `json:"showing_bits"`
	MinBits       float64 `json:"min_bits"`
	IssKB         float64 `json:"issuance_kb"`
	ShowKB        float64 `json:"showing_kb"`
	IssTimeSec    float64 `json:"issuance_time_sec"`
	ShowTimeSec   float64 `json:"showing_time_sec"`
	IssDQ         int     `json:"issuance_dq"`
	ShowDQ        int     `json:"showing_dq"`
	IssFpar       int     `json:"issuance_fpar"`
	ShowFpar      int     `json:"showing_fpar"`
	IssFagg       int     `json:"issuance_fagg"`
	ShowFagg      int     `json:"showing_fagg"`
	ProofsChecked bool    `json:"proofs_checked"`
}

type runArtifacts struct {
	inputs issuance.Inputs
	state  *issuance.State
	com    []*ring.Poly
	ch     issuance.Challenge
	params *credential.Params
	proof  *PIOP.Proof
	dur    time.Duration
}

type showArtifacts struct {
	proof *PIOP.Proof
	dur   time.Duration
}

type sweepWriter struct {
	csv      *csv.Writer
	csvFile  *os.File
	jsonEnc  *json.Encoder
	jsonFile *os.File
	wroteHdr bool
}

func main() {
	var (
		mode      = flag.String("mode", "both", "issuance|showing|both")
		ncolsSpec = flag.String("ncols", "4,6,8", "comma-separated NCols values")
		ellSpec   = flag.String("ell", "1,2,4", "comma-separated ell values")
		ellpSpec  = flag.String("ellp", "1,2", "comma-separated ell' values")
		rhoSpec   = flag.String("rho", "1,2", "comma-separated rho values")
		thetaSpec = flag.String("theta", "2", "comma-separated theta values")
		etaSpec   = flag.String("eta", "7,11,17", "comma-separated eta values")
		targets   = flag.String("targets", "128,256", "comma-separated target soundness bits")
		boundB    = flag.Int64("bound", 8, "bound B for sampling and constraints")
		maxTrials = flag.Int("max-trials", 2048, "max NTRU signing trials")
		seed      = flag.Int64("seed", 0, "rng seed (0 = time-based)")
		maxRuns   = flag.Int("max", 0, "max grid points to run (0 = all)")
		skipVerify = flag.Bool("skip-verify", false, "skip proof verification for speed")
		csvPath   = flag.String("csv", "", "write csv results to path")
		jsonPath  = flag.String("jsonl", "", "write jsonl results to path")
		verbose   = flag.Bool("v", false, "verbose logging")
	)
	flag.Parse()

	cfg, err := parseConfig(*ncolsSpec, *ellSpec, *ellpSpec, *rhoSpec, *thetaSpec, *etaSpec)
	if err != nil {
		log.Fatalf("parse config: %v", err)
	}
	targetList, err := parseIntList(*targets)
	if err != nil {
		log.Fatalf("parse targets: %v", err)
	}
	if len(targetList) == 0 {
		log.Fatalf("no targets specified")
	}

	if *seed == 0 {
		*seed = time.Now().UnixNano()
	}
	log.Printf("[sweep] seed=%d", *seed)

	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		log.Fatalf("load ring: %v", err)
	}
	prfParams, err := prf.LoadDefaultParams()
	if err != nil {
		log.Fatalf("load prf params: %v", err)
	}

	pk, err := keys.LoadPublic()
	if err != nil {
		log.Fatalf("load public key: %v", err)
	}

	writer, err := newSweepWriter(*csvPath, *jsonPath)
	if err != nil {
		log.Fatalf("init writer: %v", err)
	}
	defer writer.Close()

	runs := 0
	for _, ncols := range cfg.ncols {
		if ncols%2 != 0 {
			log.Printf("[sweep] skip ncols=%d (packing requires even)", ncols)
			continue
		}
		for _, ell := range cfg.ell {
			for _, ellp := range cfg.ellPrime {
				for _, rho := range cfg.rho {
					for _, theta := range cfg.theta {
						for _, eta := range cfg.eta {
							if *maxRuns > 0 && runs >= *maxRuns {
								log.Printf("[sweep] reached max=%d runs", *maxRuns)
								return
							}
							runs++
							opts := PIOP.SimOpts{
								Credential: true,
								NCols:      ncols,
								Ell:        ell,
								EllPrime:   ellp,
								Rho:        rho,
								Theta:      theta,
								Eta:        eta,
							}
							opts.ApplyDefaultsExported()

							rng := rand.New(rand.NewSource(*seed + int64(runs)))
							if *verbose {
								log.Printf("[sweep] run ncols=%d ell=%d ellp=%d rho=%d theta=%d eta=%d", ncols, ell, ellp, rho, theta, eta)
							}

							var iss *runArtifacts
							var show *showArtifacts
							if *mode == "issuance" || *mode == "both" {
								iss, err = runIssuance(ringQ, opts, *boundB, rng, *maxTrials, *skipVerify)
								if err != nil {
									log.Printf("[sweep] issuance failed (ncols=%d ell=%d ellp=%d rho=%d theta=%d eta=%d): %v", ncols, ell, ellp, rho, theta, eta, err)
									continue
								}
							}
							if *mode == "showing" || *mode == "both" {
								if iss == nil {
									// Need issuance artifacts to build showing inputs.
									iss, err = runIssuance(ringQ, opts, *boundB, rng, *maxTrials, *skipVerify)
									if err != nil {
										log.Printf("[sweep] issuance (for showing) failed: %v", err)
										continue
									}
								}
								show, err = runShowing(ringQ, prfParams, pk, opts, *boundB, rng, *maxTrials, *skipVerify, iss)
								if err != nil {
									log.Printf("[sweep] showing failed (ncols=%d ell=%d ellp=%d rho=%d theta=%d eta=%d): %v", ncols, ell, ellp, rho, theta, eta, err)
									continue
								}
							}

							for _, target := range targetList {
								row, ok := buildSweepRow(ringQ, opts, target, iss, show)
								if !ok {
									continue
								}
								if err := writer.Write(row); err != nil {
									log.Printf("[sweep] write row: %v", err)
								}
							}
						}
					}
				}
			}
		}
	}
}

func parseConfig(ncolsSpec, ellSpec, ellpSpec, rhoSpec, thetaSpec, etaSpec string) (sweepConfig, error) {
	var cfg sweepConfig
	var err error
	if cfg.ncols, err = parseIntList(ncolsSpec); err != nil {
		return cfg, fmt.Errorf("ncols: %w", err)
	}
	if cfg.ell, err = parseIntList(ellSpec); err != nil {
		return cfg, fmt.Errorf("ell: %w", err)
	}
	if cfg.ellPrime, err = parseIntList(ellpSpec); err != nil {
		return cfg, fmt.Errorf("ellp: %w", err)
	}
	if cfg.rho, err = parseIntList(rhoSpec); err != nil {
		return cfg, fmt.Errorf("rho: %w", err)
	}
	if cfg.theta, err = parseIntList(thetaSpec); err != nil {
		return cfg, fmt.Errorf("theta: %w", err)
	}
	if cfg.eta, err = parseIntList(etaSpec); err != nil {
		return cfg, fmt.Errorf("eta: %w", err)
	}
	return cfg, nil
}

func parseIntList(spec string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		val, err := strconv.Atoi(part)
		if err != nil {
			return nil, err
		}
		out = append(out, val)
	}
	return out, nil
}

func runIssuance(ringQ *ring.Ring, opts PIOP.SimOpts, bound int64, rng *rand.Rand, maxTrials int, skipVerify bool) (*runArtifacts, error) {
	if ringQ == nil {
		return nil, fmt.Errorf("nil ring")
	}
	if opts.NCols <= 0 {
		return nil, fmt.Errorf("ncols required")
	}
	lenM1, lenM2, lenRU0, lenRU1, lenR := 1, 1, 1, 1, 1
	cols := lenM1 + lenM2 + lenRU0 + lenRU1 + lenR
	Ac := sampleAc(ringQ, cols, cols, rng)
	params := &credential.Params{
		Ac:     Ac,
		BPath:  "Parameters/Bmatrix.json",
		BoundB: bound,
		RingQ:  ringQ,
		LenM1:  lenM1,
		LenM2:  lenM2,
		LenRU0: lenRU0,
		LenRU1: lenRU1,
		LenR:   lenR,
	}

	m1 := samplePackedHalfEval(ringQ, bound, opts.NCols, rng, true)
	m2 := samplePackedHalfEval(ringQ, bound, opts.NCols, rng, false)
	ru0 := sampleBoundedEval(ringQ, bound, rng)
	ru1 := sampleBoundedEval(ringQ, bound, rng)
	rPoly := sampleBoundedEval(ringQ, bound, rng)

	inputs := issuance.Inputs{
		M1:  []*ring.Poly{m1},
		M2:  []*ring.Poly{m2},
		RU0: []*ring.Poly{ru0},
		RU1: []*ring.Poly{ru1},
		R:   []*ring.Poly{rPoly},
	}
	ch := issuance.Challenge{RI0: []*ring.Poly{makePolyConstNTT(ringQ, 1)}, RI1: []*ring.Poly{makePolyConstNTT(ringQ, 1)}}

	com, err := issuance.PrepareCommit(params, inputs)
	if err != nil {
		return nil, fmt.Errorf("prepare commit: %w", err)
	}
	state, err := issuance.ApplyChallenge(params, inputs, ch)
	if err != nil {
		return nil, fmt.Errorf("apply challenge: %w", err)
	}

	start := time.Now()
	proof, err := issuance.ProvePreSign(params, ch, com, inputs, state, opts)
	if err != nil {
		return nil, fmt.Errorf("prove pre-sign: %w", err)
	}
	dur := time.Since(start)
	if !skipVerify {
		ok, err := issuance.VerifyPreSign(params, ch, com, state, proof, opts)
		if err != nil || !ok {
			return nil, fmt.Errorf("verify pre-sign failed: ok=%v err=%v", ok, err)
		}
	}
	return &runArtifacts{
		inputs: inputs,
		state:  state,
		com:    com,
		ch:     ch,
		params: params,
		proof:  proof,
		dur:    dur,
	}, nil
}

func runShowing(ringQ *ring.Ring, prfParams *prf.Params, pk *keys.PublicKey, opts PIOP.SimOpts, bound int64, rng *rand.Rand, maxTrials int, skipVerify bool, iss *runArtifacts) (*showArtifacts, error) {
	if iss == nil || iss.state == nil {
		return nil, errors.New("missing issuance state")
	}
	sig, err := signverify.SignTarget(iss.state.T, maxTrials, ntru.SamplerOpts{})
	if err != nil {
		return nil, fmt.Errorf("sign target: %w", err)
	}
	if sig.Signature.Rejected {
		return nil, fmt.Errorf("signature rejected")
	}
	uRows := signatureRows(ringQ, sig)
	A, err := buildSignatureMatrix(ringQ, pk, len(uRows))
	if err != nil {
		return nil, fmt.Errorf("build A: %w", err)
	}

	key, err := prfKeyFromPoly(iss.inputs.M2[0], prfParams.LenKey, ringQ)
	if err != nil {
		return nil, fmt.Errorf("prf key: %w", err)
	}
	nonce, noncePublic := sampleNonce(prfParams.LenNonce, opts.NCols, ringQ.Modulus[0], rng)
	tag, err := prf.Tag(key, nonce, prfParams)
	if err != nil {
		return nil, fmt.Errorf("prf tag: %w", err)
	}
	tagPublic := lanesFromElems(tag, opts.NCols)

	x0, err := prf.ConcatKeyNonce(key, nonce, prfParams)
	if err != nil {
		return nil, fmt.Errorf("concat key/nonce: %w", err)
	}
	trace, err := prf.Trace(x0, prfParams)
	if err != nil {
		return nil, fmt.Errorf("prf trace: %w", err)
	}
	traceRows := traceToPolys(ringQ, trace)

	wit := PIOP.WitnessInputs{
		M1:  iss.inputs.M1,
		M2:  iss.inputs.M2,
		RU0: iss.inputs.RU0,
		RU1: iss.inputs.RU1,
		R:   iss.inputs.R,
		R0:  iss.state.R0,
		R1:  iss.state.R1,
		K0:  iss.state.K0,
		K1:  iss.state.K1,
		T:   iss.state.T,
		U:   uRows,
		Extras: map[string]interface{}{
			"prf_trace": traceRows,
		},
	}
	pub := PIOP.PublicInputs{
		A:      A,
		B:      iss.state.B,
		Tag:    tagPublic,
		Nonce:  noncePublic,
		BoundB: bound,
	}

	start := time.Now()
	proof, err := PIOP.BuildShowingCombined(pub, wit, opts)
	if err != nil {
		return nil, fmt.Errorf("build showing: %w", err)
	}
	dur := time.Since(start)
	if !skipVerify {
		ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub, opts, PIOP.FSModeCredential)
		if err != nil || !ok {
			return nil, fmt.Errorf("verify showing failed: ok=%v err=%v", ok, err)
		}
	}
	return &showArtifacts{proof: proof, dur: dur}, nil
}

func buildSweepRow(ringQ *ring.Ring, opts PIOP.SimOpts, target int, iss *runArtifacts, show *showArtifacts) (sweepRow, bool) {
	row := sweepRow{
		TargetBits: target,
		NCols:      opts.NCols,
		Ell:        opts.Ell,
		EllPrime:   opts.EllPrime,
		Rho:        opts.Rho,
		Theta:      opts.Theta,
		Eta:        opts.Eta,
		ProofsChecked: true,
	}
	if iss != nil {
		optsIss := opts
		optsIss.Lambda = target
		issRep, err := PIOP.BuildProofReport(iss.proof, optsIss, ringQ)
		if err != nil {
			return row, false
		}
		row.IssBits = issRep.Soundness.TotalBits
		row.IssKB = issRep.ProofKB
		row.IssTimeSec = iss.dur.Seconds()
		row.IssDQ = issRep.DQ
		row.IssFpar = len(iss.proof.FparNTT)
		row.IssFagg = len(iss.proof.FaggNTT)
	}
	if show != nil {
		optsShow := opts
		optsShow.Lambda = target
		showRep, err := PIOP.BuildProofReport(show.proof, optsShow, ringQ)
		if err != nil {
			return row, false
		}
		row.ShowBits = showRep.Soundness.TotalBits
		row.ShowKB = showRep.ProofKB
		row.ShowTimeSec = show.dur.Seconds()
		row.ShowDQ = showRep.DQ
		row.ShowFpar = len(show.proof.FparNTT)
		row.ShowFagg = len(show.proof.FaggNTT)
	}
	row.MinBits = minFloat(row.IssBits, row.ShowBits)
	if row.MinBits < float64(target) {
		return row, false
	}
	return row, true
}

func minFloat(a, b float64) float64 {
	if a == 0 {
		return b
	}
	if b == 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func newSweepWriter(csvPath, jsonPath string) (*sweepWriter, error) {
	w := &sweepWriter{}
	if csvPath != "" {
		if err := os.MkdirAll(filepath.Dir(csvPath), 0o755); err != nil {
			return nil, err
		}
		f, err := os.Create(csvPath)
		if err != nil {
			return nil, err
		}
		w.csvFile = f
		w.csv = csv.NewWriter(f)
	}
	if jsonPath != "" {
		if err := os.MkdirAll(filepath.Dir(jsonPath), 0o755); err != nil {
			return nil, err
		}
		f, err := os.Create(jsonPath)
		if err != nil {
			return nil, err
		}
		w.jsonFile = f
		w.jsonEnc = json.NewEncoder(f)
	}
	return w, nil
}

func (w *sweepWriter) Close() {
	if w == nil {
		return
	}
	if w.csv != nil {
		w.csv.Flush()
	}
	if w.csvFile != nil {
		_ = w.csvFile.Close()
	}
	if w.jsonFile != nil {
		_ = w.jsonFile.Close()
	}
}

func (w *sweepWriter) Write(row sweepRow) error {
	if w == nil {
		return nil
	}
	if w.csv != nil {
		if !w.wroteHdr {
			header := []string{"target_bits", "ncols", "ell", "ellp", "rho", "theta", "eta", "issuance_bits", "showing_bits", "min_bits", "issuance_kb", "showing_kb", "issuance_time_s", "showing_time_s", "issuance_dq", "showing_dq", "issuance_fpar", "showing_fpar", "issuance_fagg", "showing_fagg"}
			if err := w.csv.Write(header); err != nil {
				return err
			}
			w.wroteHdr = true
		}
		rec := []string{
			strconv.Itoa(row.TargetBits),
			strconv.Itoa(row.NCols),
			strconv.Itoa(row.Ell),
			strconv.Itoa(row.EllPrime),
			strconv.Itoa(row.Rho),
			strconv.Itoa(row.Theta),
			strconv.Itoa(row.Eta),
			fmt.Sprintf("%.2f", row.IssBits),
			fmt.Sprintf("%.2f", row.ShowBits),
			fmt.Sprintf("%.2f", row.MinBits),
			fmt.Sprintf("%.2f", row.IssKB),
			fmt.Sprintf("%.2f", row.ShowKB),
			fmt.Sprintf("%.4f", row.IssTimeSec),
			fmt.Sprintf("%.4f", row.ShowTimeSec),
			strconv.Itoa(row.IssDQ),
			strconv.Itoa(row.ShowDQ),
			strconv.Itoa(row.IssFpar),
			strconv.Itoa(row.ShowFpar),
			strconv.Itoa(row.IssFagg),
			strconv.Itoa(row.ShowFagg),
		}
		if err := w.csv.Write(rec); err != nil {
			return err
		}
		w.csv.Flush()
	}
	if w.jsonEnc != nil {
		if err := w.jsonEnc.Encode(row); err != nil {
			return err
		}
	}
	fmt.Printf("target=%d bits; min=%.2f (iss=%.2f show=%.2f) params NCols=%d ℓ=%d ℓ'=%d ρ=%d θ=%d η=%d\n",
		row.TargetBits, row.MinBits, row.IssBits, row.ShowBits, row.NCols, row.Ell, row.EllPrime, row.Rho, row.Theta, row.Eta)
	return nil
}

func sampleAc(r *ring.Ring, rows, cols int, rng *rand.Rand) [][]*ring.Poly {
	mat := make([][]*ring.Poly, rows)
	for i := 0; i < rows; i++ {
		mat[i] = make([]*ring.Poly, cols)
		for j := 0; j < cols; j++ {
			p := r.NewPoly()
			for k := 0; k < r.N; k++ {
				p.Coeffs[0][k] = uint64(rng.Int63()) % r.Modulus[0]
			}
			r.NTT(p, p)
			mat[i][j] = p
		}
	}
	return mat
}

func sampleBoundedEval(r *ring.Ring, bound int64, rng *rand.Rand) *ring.Poly {
	pNTT := r.NewPoly()
	q := int64(r.Modulus[0])
	mod := 2*bound + 1
	for i := 0; i < r.N; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			pNTT.Coeffs[0][i] = uint64(v + q)
		} else {
			pNTT.Coeffs[0][i] = uint64(v)
		}
	}
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

func samplePackedHalfEval(r *ring.Ring, bound int64, ncols int, rng *rand.Rand, keepLower bool) *ring.Poly {
	pNTT := r.NewPoly()
	q := int64(r.Modulus[0])
	mod := 2*bound + 1
	for i := 0; i < r.N; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			pNTT.Coeffs[0][i] = uint64(v + q)
		} else {
			pNTT.Coeffs[0][i] = uint64(v)
		}
	}
	if ncols <= 0 || ncols > r.N {
		ncols = r.N
	}
	half := ncols / 2
	if keepLower {
		for i := half; i < ncols; i++ {
			pNTT.Coeffs[0][i] = 0
		}
	} else {
		for i := 0; i < half; i++ {
			pNTT.Coeffs[0][i] = 0
		}
	}
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

func makePolyConstNTT(r *ring.Ring, v int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	var coeff uint64
	if v >= 0 {
		coeff = uint64(v % q)
	} else {
		coeff = uint64((v+q)%q) % uint64(q)
	}
	for i := 0; i < r.N; i++ {
		p.Coeffs[0][i] = coeff
	}
	return p
}

func prfKeyFromPoly(m2 *ring.Poly, want int, ringQ *ring.Ring) ([]prf.Elem, error) {
	if m2 == nil {
		return nil, fmt.Errorf("missing m2")
	}
	coeffs := m2.Coeffs[0]
	if len(coeffs) < want {
		return nil, fmt.Errorf("m2 len=%d < lenkey=%d", len(coeffs), want)
	}
	q := int64(ringQ.Modulus[0])
	key := make([]prf.Elem, want)
	for i := 0; i < want; i++ {
		v := int64(coeffs[i]) % q
		if v < 0 {
			v += q
		}
		key[i] = prf.Elem(uint64(v))
	}
	return key, nil
}

func sampleNonce(lennonce, ncols int, q uint64, rng *rand.Rand) ([]prf.Elem, [][]int64) {
	nonce := make([]prf.Elem, lennonce)
	public := make([][]int64, lennonce)
	for i := 0; i < lennonce; i++ {
		v := uint64(rng.Int63()) % q
		nonce[i] = prf.Elem(v)
		public[i] = buildConstLane(ncols, int64(v))
	}
	return nonce, public
}

func lanesFromElems(vals []prf.Elem, ncols int) [][]int64 {
	out := make([][]int64, len(vals))
	for i, v := range vals {
		out[i] = buildConstLane(ncols, int64(v))
	}
	return out
}

func traceToPolys(r *ring.Ring, trace [][]prf.Elem) []*ring.Poly {
	rows := make([]*ring.Poly, 0, len(trace))
	for _, st := range trace {
		for _, v := range st {
			rows = append(rows, polyConst(r, int64(v)))
		}
	}
	return rows
}

func polyConst(r *ring.Ring, v int64) *ring.Poly {
	pNTT := r.NewPoly()
	q := int64(r.Modulus[0])
	var coeff uint64
	if v >= 0 {
		coeff = uint64(v % q)
	} else {
		coeff = uint64((v+q)%q) % uint64(q)
	}
	for i := 0; i < r.N; i++ {
		pNTT.Coeffs[0][i] = coeff
	}
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

func polyFromInt64(r *ring.Ring, coeffs []int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	for i := 0; i < r.N && i < len(coeffs); i++ {
		v := coeffs[i] % q
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	return p
}

func signatureRows(r *ring.Ring, sig *keys.Signature) []*ring.Poly {
	if sig == nil || len(sig.Signature.S0) == 0 {
		return []*ring.Poly{r.NewPoly()}
	}
	u0 := polyFromInt64(r, sig.Signature.S0)
	if len(sig.Signature.S1) == 0 {
		return []*ring.Poly{u0}
	}
	u1 := polyFromInt64(r, sig.Signature.S1)
	return []*ring.Poly{u1, u0}
}

func buildSignatureMatrix(r *ring.Ring, pk *keys.PublicKey, uCount int) ([][]*ring.Poly, error) {
	if pk == nil || len(pk.HCoeffs) == 0 {
		return nil, fmt.Errorf("missing public key")
	}
	if uCount <= 1 {
		one := r.NewPoly()
		one.Coeffs[0][0] = 1 % r.Modulus[0]
		r.NTT(one, one)
		return [][]*ring.Poly{{one}}, nil
	}
	h := polyFromInt64(r, pk.HCoeffs)
	r.NTT(h, h)
	one := r.NewPoly()
	one.Coeffs[0][0] = 1 % r.Modulus[0]
	r.NTT(one, one)
	return [][]*ring.Poly{{h, one}}, nil
}

func buildConstLane(ncols int, v int64) []int64 {
	row := make([]int64, ncols)
	for i := range row {
		row[i] = v
	}
	return row
}
