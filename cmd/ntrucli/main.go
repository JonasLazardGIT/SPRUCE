package main

import (
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	PIOP "vSIS-Signature/PIOP"
	measure "vSIS-Signature/measure"
	ntru "vSIS-Signature/ntru"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"
)

func usage() {
	fmt.Println(`usage: ntru <gen|sign|verify> [options]

Subcommands:
  gen      Generate an NTRU keypair and write ./ntru_keys/{public,private}.json
           Flags:
             -mode   <annulus|trivial>  keygen mode (default: annulus)
             -alpha  <float>            annulus quality window α (default: 1.20)
             -kgtrials <int>            max annulus trials (default: 10000)
             -prec   <int>              big-float precision (default: 256)
             -use-c-radius              use fixed C radius instead of α window
             -radius <float>            radius scale used when -use-c-radius is set
             -kgverbose                 log annulus statistics while sampling

  sign     Sign a message and write ./ntru_keys/signature.json
           Flags:
             -m            <string>     message to sign (required)
             -max          <int>        max rejection trials    (default: 2048)
             -sigma-scale  <float>      per-slot sigma multiplier (>=1, default 1.0)
             -reduce-iters <int>        Babai reductions before sampling (default: 64)
             -prec         <int>        big-float precision (bits, default: 256)
             -v                         verbose: print telemetry (L2 estimate)
           Output (stdout):
             trials_used, rejected (true if trials_used > 1), max_trials

  verify   Verify ./ntru_keys/signature.json against embedded params & public key

  pacs          Run a PACS simulation (large-field defaults)
  pacs-small    Run a PACS simulation using the small-field variant (θ>1)`)
	os.Exit(1)
}

func parseChainDigitsFlag(flagValue string) (int, error) {
	v := strings.TrimSpace(strings.ToLower(flagValue))
	if v == "" || v == "auto" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid L flag %q: %w", flagValue, err)
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid L flag %q: must be >= 0", flagValue)
	}
	return n, nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "gen":
		runGen()
	case "sign":
		runSign(os.Args[2:])
	case "verify":
		runVerify()
	case "pacs":
		runPACS(os.Args[2:])
	case "pacs-small":
		runPACSSmall(os.Args[2:])
	default:
		usage()
	}
}

func runGen() {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	mode := fs.String("mode", "annulus", "keygen mode: annulus|trivial")
	alpha := fs.Float64("alpha", 1.20, "quality parameter α (≥ 1) for annulus window")
	kgTrials := fs.Int("kgtrials", 10000, "maximum annulus trials")
	useCRadius := fs.Bool("use-c-radius", false, "use fixed radius annulus sampling")
	radius := fs.Float64("radius", 0.0, "ANTRAG_RADIUS (rad = sqrt(Q)*radius) when -use-c-radius")
	kgVerbose := fs.Bool("kgverbose", false, "verbose annulus keygen logging")
	prec := fs.Int("prec", 256, "big-float precision (bits)")
	fs.Parse(os.Args[2:])

	pp, err := signverify.LoadParamsForCLI()
	if err != nil {
		log.Fatalf("load params: %v", err)
	}
	q := new(big.Int).SetUint64(pp.Q)
	par, err := ntru.NewParams(pp.N, q)
	if err != nil {
		log.Fatalf("params: %v", err)
	}

	switch *mode {
	case "trivial":
		_, _, err = signverify.GenerateKeypair(par, ntru.SolveOpts{Prec: 128}, 128)
	case "annulus":
		if !*useCRadius && *alpha < 1.0 {
			log.Fatal("alpha must be ≥ 1")
		}
		kg := ntru.KeygenOpts{
			Prec:       uint(*prec),
			MaxTrials:  *kgTrials,
			Alpha:      *alpha,
			UseCRadius: *useCRadius,
			Radius:     *radius,
			Verbose:    *kgVerbose,
		}
		_, _, err = signverify.GenerateKeypairAnnulus(par, kg)
	default:
		log.Fatalf("unknown mode %q", *mode)
	}
	if err != nil {
		log.Fatalf("gen: %v", err)
	}
	fmt.Println("keys written to ./ntru_keys")
}

func runSign(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	msg := fs.String("m", "", "message string")
	verbose := fs.Bool("v", false, "verbose telemetry")
	max := fs.Int("max", 2048, "max rejection trials")
	sigmaScale := fs.Float64("sigma-scale", 1.0, "multiplier for per-slot sigmas (>=1)")
	reduceIters := fs.Int("reduce-iters", 64, "Babai reduction iterations before sampling")
	prec := fs.Int("prec", 256, "big-float precision for sampler")
	fs.Parse(args)
	if *sigmaScale <= 0 {
		log.Fatalf("sign: -sigma-scale must be > 0")
	}
	if *prec <= 0 {
		log.Fatalf("sign: -prec must be positive")
	}
	ri := *reduceIters
	if ri <= 0 {
		ri = 64
	}
	opts := ntru.SamplerOpts{
		RSquare:          ntru.CReferenceRSquare(),
		Alpha:            1.25,
		Slack:            1.042,
		SigmaScale:       *sigmaScale,
		ReduceIters:      ri,
		Prec:             uint(*prec),
		UseCNormalDist:   true,
		UseExactResidual: true,
		BoundShape:       "cstyle",
	}
	sig, err := signverify.SignWithOpts([]byte(*msg), *max, opts)
	if err != nil {
		log.Fatalf("sign: %v", err)
	}
	fmt.Printf("sign: trials_used=%d rejected=%v max_trials=%d\n", sig.Signature.TrialsUsed, sig.Signature.Rejected, sig.Signature.MaxTrials)
	if *verbose {
		fmt.Printf("sign: l2_est=%.4g\n", sig.Signature.Norm.L2Est)
	}
	// Compute centered residual Linf for diagnostics
	priv, err := keys.LoadPrivate()
	if err == nil {
		qInt := new(big.Int)
		if _, ok := qInt.SetString(sig.Params.Q, 16); ok {
			if parRes, err := ntru.NewParams(sig.Params.N, qInt); err == nil {
				h, errH := ntru.PublicKeyH(ntru.Int64ToModQPoly(priv.Fsmall, parRes), ntru.Int64ToModQPoly(priv.Gsmall, parRes), parRes)
				s1Poly := ntru.Int64ToModQPoly(sig.Signature.S1, parRes)
				hs1, errConv := ntru.ConvolveRNS(s1Poly, h, parRes)
				if errH == nil && errConv == nil {
					tPoly := ntru.Int64ToModQPoly(sig.Hash.TCoeffs, parRes)
					residual := hs1.Add(tPoly)
					if centered, errC := ntru.CenterModQToInt64(residual, parRes); errC == nil {
						fmt.Printf("sign: residual_linf=%d\n", maxAbs(centered))
					}
				}
			}
		}
	}
	fmt.Println("signature written to ./ntru_keys/signature.json")
	if measure.Enabled {
		measure.Global.Dump()
	}
}

func runVerify() {
	sig, err := keys.Load()
	if err != nil {
		log.Fatalf("load signature: %v", err)
	}
	if err := signverify.Verify(sig); err != nil {
		log.Fatalf("verify failed: %v", err)
	}
	fmt.Println("signature verified")
}

func maxAbs(vals []int64) int64 {
	var m int64
	for _, v := range vals {
		if v < 0 {
			v = -v
		}
		if v > m {
			m = v
		}
	}
	return m
}

func reportVerifyMetrics(prefix string, proof *PIOP.Proof) {
	start := time.Now()
	okLin, okEq4, okSum, err := PIOP.VerifyNIZK(proof)
	duration := time.Since(start)
	if err != nil {
		fmt.Printf("%sVerifyNIZK failed: %v\n", prefix, err)
	} else {
		fmt.Printf("%sVerifyNIZK checks: OkLin=%v OkEq4=%v OkSum=%v\n", prefix, okLin, okEq4, okSum)
	}
	fmt.Printf("%sVerifyNIZK duration: %s\n", prefix, duration)
	report := PIOP.MeasureProofSize(proof)
	fmt.Printf("%sVerifyNIZK input size total=%d bytes\n", prefix, report.Total)
	if len(report.Parts) == 0 {
		return
	}
	keys := make([]string, 0, len(report.Parts))
	for k := range report.Parts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if report.Parts[keys[i]] == report.Parts[keys[j]] {
			return keys[i] < keys[j]
		}
		return report.Parts[keys[i]] > report.Parts[keys[j]]
	})
	for _, k := range keys {
		fmt.Printf("%s  %-12s %8d\n", prefix, k, report.Parts[k])
	}
}

func renderPACSReport(prefix string, rep PIOP.SimReport) {
	fmt.Printf("%sChecks: OkLin=%v OkEq4=%v OkSum=%v\n", prefix, rep.Verdict.OkLin, rep.Verdict.OkEq4, rep.Verdict.OkSum)
	if totalUS, ok := rep.TimingsUS["__total__"]; ok && totalUS > 0 {
		fmt.Printf("%sProver runtime≈%s\n", prefix, time.Duration(totalUS)*time.Microsecond)
	}
	fmt.Printf("%sProof size≈%d bytes\n", prefix, rep.ProofBytes)
	fmt.Printf("%sSoundness bits: eps1=%.2f eps2=%.2f eps3=%.2f eps4=%.2f total=%.2f (≈%.3e)\n",
		prefix,
		rep.Soundness.Bits[0], rep.Soundness.Bits[1], rep.Soundness.Bits[2], rep.Soundness.Bits[3],
		rep.Soundness.TotalBits, rep.Soundness.Total)
	fmt.Printf("%sParameters: |Ω|=%d ℓ=%d ℓ'=%d ρ=%d η=%d θ=%d dQ=%d λ=%d κ=%v\n",
		prefix,
		rep.NCols, rep.Ell, rep.EllPrime, rep.Rho, rep.Eta, rep.Theta,
		rep.Soundness.DQ, rep.Opts.Lambda, rep.Opts.Kappa)
	fmt.Printf("%sMerkle leaves: N=%d opened=%d (mask=%d tail=%d)\n",
		prefix,
		rep.NLeaves, rep.MerkleOpens, rep.MaskLeaves, rep.TailLeaves)
	fmt.Printf("%sRows: witness-cols=%d parallel=%d aggregated=%d\n",
		prefix,
		rep.WitnessCols, rep.ParallelRows, rep.AggregatedRows)
	fmt.Printf("%sConstraint degrees: d=%d d'=%d dQ=%d\n",
		prefix,
		rep.ParallelDeg, rep.AggregatedDeg, rep.Soundness.DQ)
	fmt.Printf("%sChain: W=%d base=%d L=%d LSD∈[%d,%d]\n",
		prefix,
		rep.Chain.W, rep.Chain.Base, rep.Chain.L, rep.Chain.LSDLo, rep.Chain.LSDHi)
	if rep.QMod != 0 {
		fmt.Printf("%sRing: q=%d (N=%d)\n", prefix, rep.QMod, rep.NLeaves)
	}
	if rep.Soundness.NRows > 0 || rep.Soundness.M > 0 {
		fmt.Printf("%sVerifier layout: nrows=%d m=%d\n", prefix, rep.Soundness.NRows, rep.Soundness.M)
	}
	if len(rep.ProofSizeLayers) > 0 {
		fmt.Printf("%sProof size by layer:\n", prefix)
		keys := make([]string, 0, len(rep.ProofSizeLayers))
		for k := range rep.ProofSizeLayers {
			if k == "TOTAL" {
				continue
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if rep.ProofSizeLayers[keys[i]] == rep.ProofSizeLayers[keys[j]] {
				return keys[i] < keys[j]
			}
			return rep.ProofSizeLayers[keys[i]] > rep.ProofSizeLayers[keys[j]]
		})
		for _, k := range keys {
			fmt.Printf("%s  %-6s %8d\n", prefix, k, rep.ProofSizeLayers[k])
		}
		if total, ok := rep.ProofSizeLayers["TOTAL"]; ok {
			fmt.Printf("%s  %-6s %8d\n", prefix, "TOTAL", total)
		}
	} else if len(rep.SizesB) == 0 {
		fmt.Printf("%sProof size breakdown unavailable (sizes map empty)\n", prefix)
	}
}

// runPACS runs the PACS simulation similarly to tests and records sizes.
func runPACS(args []string) {
	fs := flag.NewFlagSet("pacs", flag.ExitOnError)
	ncols := fs.Int("ncols", 8, "|Ω| evaluation points (s)")
	ell := fs.Int("ell", 26, "ℓ masked openings for DECS")
	ellp := fs.Int("ellp", 10, "ℓ' evaluation queries for PIOP")
	rho := fs.Int("rho", 7, "ρ parallel Q batches")
	eta := fs.Int("eta", 7, "η DECS repetitions")
	nLeaves := fs.Int("nleaves", 0, "Merkle leaf count N (0=ring dimension)")
	theta := fs.Int("theta", 1, "extension degree θ")
	dq := fs.Int("dq", 0, "override d_Q (0 = compute from layout)")
	k1 := fs.Int("kappa1", 0, "grinding bits κ₁")
	k2 := fs.Int("kappa2", 0, "grinding bits κ₂")
	k3 := fs.Int("kappa3", 0, "grinding bits κ₃")
	k4 := fs.Int("kappa4", 0, "grinding bits κ₄")
	lambda := fs.Int("lambda", 256, "Fiat–Shamir security parameter λ")
	chainW := fs.Int("W", 4, "ℓ∞ chain window bits (B = 2^W)")
	chainLFlag := fs.String("L", "auto", "ℓ∞ chain digit count (integer) or 'auto'")
	fs.Parse(args)

	chainL, err := parseChainDigitsFlag(*chainLFlag)
	if err != nil {
		log.Fatalf("pacs: %v", err)
	}

	opts := PIOP.SimOpts{
		NCols:      *ncols,
		Ell:        *ell,
		EllPrime:   *ellp,
		Rho:        *rho,
		Eta:        *eta,
		NLeaves:    *nLeaves,
		Theta:      *theta,
		DQOverride: *dq,
		Kappa:      [4]int{*k1, *k2, *k3, *k4},
		Lambda:     *lambda,
		ChainW:     *chainW,
		ChainL:     chainL,
	}

	rep, err := PIOP.RunOnce(opts)
	if err != nil {
		log.Fatalf("pacs: %v", err)
	}

	renderPACSReport("[pacs] ", rep)
	if proof := rep.Proof.Restore(); proof != nil {
		reportVerifyMetrics("[pacs] ", proof)
	}
}

func runPACSSmall(args []string) {
	fs := flag.NewFlagSet("pacs-small", flag.ExitOnError)
	ncols := fs.Int("ncols", 4, "|Ω| evaluation points (s)")
	ell := fs.Int("ell", 20, "ℓ masked openings for DECS")
	rho := fs.Int("rho", 2, "ρ parallel Q batches")
	eta := fs.Int("eta", 15, "η DECS repetitions")
	nLeaves := fs.Int("nleaves", 0, "Merkle leaf count N (0=ring dimension)")
	theta := fs.Int("theta", 4, "extension degree θ")
	dq := fs.Int("dq", 0, "override d_Q (0 = compute from layout)")
	k1 := fs.Int("kappa1", 0, "grinding bits κ₁")
	k2 := fs.Int("kappa2", 0, "grinding bits κ₂")
	k3 := fs.Int("kappa3", 0, "grinding bits κ₃")
	k4 := fs.Int("kappa4", 0, "grinding bits κ₄")
	lambda := fs.Int("lambda", 256, "Fiat–Shamir security parameter λ")
	ellPrime := fs.Int("ellp", 2, "ℓ' evaluation queries")
	chainW := fs.Int("W", 3, "ℓ∞ chain window bits (B = 2^W)")
	chainLFlag := fs.String("L", "auto", "ℓ∞ chain digit count (integer) or 'auto'")
	fs.Parse(args)

	if *theta <= 0 {
		log.Fatalf("pacs-small: theta must be > 0")
	}
	chainL, err := parseChainDigitsFlag(*chainLFlag)
	if err != nil {
		log.Fatalf("pacs-small: %v", err)
	}
	rep, err := PIOP.RunOnce(PIOP.SimOpts{
		NCols:      *ncols,
		Ell:        *ell,
		EllPrime:   *ellPrime,
		Rho:        *rho,
		Eta:        *eta,
		NLeaves:    *nLeaves,
		Theta:      *theta,
		DQOverride: *dq,
		Kappa:      [4]int{*k1, *k2, *k3, *k4},
		Lambda:     *lambda,
		ChainW:     *chainW,
		ChainL:     chainL,
	})
	if err != nil {
		log.Fatalf("pacs-small: %v", err)
	}

	renderPACSReport("[small-field] ", rep)
	if proof := rep.Proof.Restore(); proof != nil {
		reportVerifyMetrics("[small-field] ", proof)
	}
}
