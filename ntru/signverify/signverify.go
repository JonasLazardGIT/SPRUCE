package signverify

import (
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"

	measure "vSIS-Signature/measure"
	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
)

// Hybrid-B defaults enforce a meaningful residual bound during sampling.
var defaultOpts = ntru.SamplerOpts{
	RSquare:          ntru.CReferenceRSquare(),
	Alpha:            1.25,
	Slack:            1.042,
	ReduceIters:      64,
	UseCNormalDist:   true,
	UseExactResidual: true,
	BoundShape:       "cstyle",
	Prec:             256,
}

func loadParams() (*ntrurio.SystemParams, error) {
	// Try local path, then parent directory (for subdir tests)
	if p, err := ntrurio.LoadParams("Parameters/Parameters.json", true /* allowMismatch */); err == nil {
		return &p, nil
	} else {
		if p2, err2 := ntrurio.LoadParams("../Parameters/Parameters.json", true); err2 == nil {
			return &p2, nil
		}
		return nil, err
	}
}

// LoadParamsForCLI exposes parameter loading for external callers.
func LoadParamsForCLI() (*ntrurio.SystemParams, error) { return loadParams() }

// GenerateKeypairAnnulus runs the Antrag key generation and persists the resulting trapdoor.
func GenerateKeypairAnnulus(par ntru.Params, kg ntru.KeygenOpts) (*keys.PublicKey, *keys.PrivateKey, error) {
	f, g, F, G, err := ntru.Keygen(par, kg)
	if err != nil {
		return nil, nil, err
	}
	hQ, err := ntru.PublicKeyH(ntru.Int64ToModQPoly(f, par), ntru.Int64ToModQPoly(g, par), par)
	if err != nil {
		return nil, nil, err
	}
	hCoeffs, _ := ntru.CenterModQToInt64(hQ, par)
	pk := &keys.PublicKey{
		Version: "ntru-key-v1",
		N:       par.N,
		Q:       par.Q.Text(16),
		HCoeffs: hCoeffs,
	}
	priv := &keys.PrivateKey{
		Version: "ntru-key-v1",
		N:       par.N,
		Q:       par.Q.Text(16),
		F:       F,
		G:       G,
		Fsmall:  f,
		Gsmall:  g,
	}
	if err := keys.SavePublic(pk); err != nil {
		return nil, nil, err
	}
	if err := keys.SavePrivate(priv); err != nil {
		return nil, nil, err
	}
	return pk, priv, nil
}

// GenerateKeypair creates a simple trapdoor and persists it under ./ntru_keys/.
func GenerateKeypair(par ntru.Params, opts ntru.SolveOpts, prec uint) (*keys.PublicKey, *keys.PrivateKey, error) {
	f := make([]int64, par.N)
	g := make([]int64, par.N)
	f[0] = 1
	if par.N > 1 {
		g[1] = 1
	} else {
		g[0] = 1
	}
	F, G, err := ntru.NTRUSolve(f, g, par, opts)
	if err != nil {
		return nil, nil, err
	}
	hQ, err := ntru.PublicKeyH(ntru.Int64ToModQPoly(f, par), ntru.Int64ToModQPoly(g, par), par)
	if err != nil {
		return nil, nil, err
	}
	hCoeffs, _ := ntru.CenterModQToInt64(hQ, par)
	pk := &keys.PublicKey{
		Version: "ntru-key-v1",
		N:       par.N,
		Q:       par.Q.Text(16),
		HCoeffs: hCoeffs,
	}
	priv := &keys.PrivateKey{
		Version: "ntru-key-v1",
		N:       par.N,
		Q:       par.Q.Text(16),
		F:       F,
		G:       G,
		Fsmall:  f,
		Gsmall:  g,
	}
	if err := keys.SavePublic(pk); err != nil {
		return nil, nil, err
	}
	if err := keys.SavePrivate(priv); err != nil {
		return nil, nil, err
	}
	return pk, priv, nil
}

// Sign generates a signature for the given message and persists it.
func Sign(message []byte, maxTrials int) (*keys.Signature, error) {
	return SignWithOpts(message, maxTrials, defaultOpts)
}

// SignWithOpts mirrors Sign but allows callers to override sampler options.
func SignWithOpts(message []byte, maxTrials int, opts ntru.SamplerOpts) (*keys.Signature, error) {
	pk, err := keys.LoadPublic()
	if err != nil {
		return nil, err
	}
	sk, err := keys.LoadPrivate()
	if err != nil {
		return nil, err
	}
	Q := new(big.Int)
	if _, ok := Q.SetString(pk.Q, 16); !ok {
		return nil, errors.New("invalid Q")
	}
	par, err := ntru.NewParams(pk.N, Q)
	if err != nil {
		return nil, err
	}
	// Load system params for hashing the target
	sys, err := loadParams()
	if err != nil {
		return nil, err
	}
	// seeds from message and fresh randomness
	mSeedArr := sha256.Sum256(message)
	mSeed := mSeedArr[:]
	x0Seed := make([]byte, 32)
	x1Seed := make([]byte, 32)
	if _, err := crand.Read(x0Seed); err != nil {
		return nil, err
	}
	if _, err := crand.Read(x1Seed); err != nil {
		return nil, err
	}
	// target t
	tCoeffs, err := ntru.ComputeTargetFromSeeds(sys, "Parameters/Bmatrix.json", mSeed, x0Seed, x1Seed)
	if err != nil {
		return nil, err
	}
	// Hybrid‑B sampler producing (s0,s1)
	prec := opts.Prec
	if prec == 0 {
		prec = 256
	}
	opts.Prec = prec
	opts.ApplyDefaults(par)
	S, err := ntru.NewSampler(sk.Fsmall, sk.Gsmall, sk.F, sk.G, par, prec)
	if err != nil {
		return nil, err
	}
	opts.UseCNormalDist = true
	opts.UseExactResidual = true
	opts.BoundShape = "cstyle"
	if par.LOG3_D {
		opts.UseLog3Cross = true
	}
	S.Opts = opts
	S.Opts.UseCNormalDist = true
	S.Opts.UseExactResidual = true
	S.Opts.BoundShape = "cstyle"
	S.Opts.UseLog3Cross = opts.UseLog3Cross
	S.Opts.MaxSignTrials = maxTrials
	S.Opts.ApplyDefaults(S.Par)
	tPoly := ntru.Int64ToModQPoly(tCoeffs, par)
	s0, s1, trials, err := S.SamplePreimageTargetOptionB(tPoly, maxTrials)
	if err != nil {
		return nil, err
	}
	// coefficient-domain copies used for persistence and telemetry
	s0i := make([]int64, par.N)
	s1i := make([]int64, par.N)
	for i := 0; i < par.N; i++ {
		s0i[i] = s0.Coeffs[i].Int64()
		s1i[i] = s1.Coeffs[i].Int64()
	}

	// Compute the same acceptance predicate enforced in the sampler loop:
	// s2 := center(h*s1 + c1), accept iff CheckNormC(s1, s2).
	var hPoly ntru.ModQPoly
	var herr error
	if len(pk.HCoeffs) == par.N {
		hPoly = ntru.Int64ToModQPoly(pk.HCoeffs, par)
	} else {
		hPoly, herr = ntru.PublicKeyH(ntru.Int64ToModQPoly(sk.Fsmall, par), ntru.Int64ToModQPoly(sk.Gsmall, par), par)
		if herr != nil {
			return nil, herr
		}
	}
	c1Mod := ntru.Int64ToModQPoly(tCoeffs, par)
	hs1, err := ntru.ConvolveRNS(ntru.Int64ToModQPoly(s1i, par), hPoly, par)
	if err != nil {
		return nil, err
	}
	s2 := hs1.Add(c1Mod)
	for i := 0; i < par.N; i++ {
		s2.Coeffs[i].Mod(s2.Coeffs[i], par.Q)
	}
	s2c, err := ntru.CenterModQToInt64(s2, par)
	if err != nil {
		return nil, err
	}
	s2Vec := S.LastS2()
	if len(s2Vec) != par.N {
		s2Vec = s2c
	} else {
		for i := 0; i < par.N; i++ {
			if s2Vec[i] != s2c[i] {
				s2Vec = s2c
				break
			}
		}
	}
	passed := ntru.CheckNormC(s1i, s2Vec, par, S.Opts)

	var linf int64
	for _, v := range s2Vec {
		if v < 0 {
			v = -v
		}
		if v > linf {
			linf = v
		}
	}
	// bundle
	sig := keys.NewSignature()
	sig.Params.N = par.N
	sig.Params.Q = pk.Q
	sig.Hash.BFile = "Parameters/Bmatrix.json"
	sig.Hash.MSeed = keys.EncodeSeed(mSeed)
	sig.Hash.X0Seed = keys.EncodeSeed(x0Seed)
	sig.Hash.X1Seed = keys.EncodeSeed(x1Seed)
	sig.Hash.TCoeffs = tCoeffs
	sig.PublicKey.HCoeffs = pk.HCoeffs
	sig.Signature.S0 = s0i
	sig.Signature.S1 = s1i
	normSq := ntru.CoefficientNormSquared(s1i, s2Vec, par, S.Opts)
	sig.Signature.Norm.Passed = passed
	sig.Signature.Norm.L2Est = normSq
	sig.Signature.Norm.ResidualLinf = linf
	sig.Signature.TrialsUsed = trials
	sig.Signature.Rejected = trials > 1
	sig.Signature.MaxTrials = maxTrials
	sig.Signature.S2 = s2Vec
	if measure.Enabled {
		recordSignatureMeasurements(sig, mSeed, x0Seed, x1Seed)
	}
	if err := keys.Save(sig); err != nil {
		return nil, err
	}
	return sig, nil
}

func recordSignatureMeasurements(sig *keys.Signature, mSeed, x0Seed, x1Seed []byte) {
	const int64Bytes = 8
	coeffBytes := func(vec []int64) int64 {
		return int64(len(vec)) * int64Bytes
	}
	s0Actual := coeffBytes(sig.Signature.S0)
	s1Actual := coeffBytes(sig.Signature.S1)
	s2Actual := coeffBytes(sig.Signature.S2)
	tActual := coeffBytes(sig.Hash.TCoeffs)
	hActual := coeffBytes(sig.PublicKey.HCoeffs)

	measure.Global.Add("ntru/signature/s0_actual", s0Actual)
	measure.Global.Add("ntru/signature/s1_actual", s1Actual)
	measure.Global.Add("ntru/signature/s2_actual", s2Actual)
	measure.Global.Add("ntru/signature/t_actual", tActual)
	measure.Global.Add("ntru/signature/h_actual", hActual)

	// Expected packed sizes assuming 16-bit coefficients for s1 and s2.
	const packed16Bit = 2
	s1Packed := int64(len(sig.Signature.S1)) * packed16Bit
	s2Packed := int64(len(sig.Signature.S2)) * packed16Bit
	measure.Global.Add("ntru/signature/s1_expected_packed", s1Packed)
	measure.Global.Add("ntru/signature/s2_expected_packed", s2Packed)
	measure.Global.Add("ntru/signature/expected_packed_total", s1Packed+s2Packed)

	seedBytes := int64(len(mSeed) + len(x0Seed) + len(x1Seed))
	if seedBytes > 0 {
		measure.Global.Add("ntru/signature/seeds", seedBytes)
	}
}

// Verify checks the signature bundle for congruence and norm predicate.
func Verify(sig *keys.Signature) error {
	if sig == nil {
		return errors.New("nil signature")
	}
	Q := new(big.Int)
	if _, ok := Q.SetString(sig.Params.Q, 16); !ok {
		return errors.New("invalid Q")
	}
	par, err := ntru.NewParams(sig.Params.N, Q)
	if err != nil {
		return err
	}
	// Recompute target from seeds and compare
	sys, err := loadParams()
	if err != nil {
		return err
	}
	mSeed, err := keys.DecodeSeed(sig.Hash.MSeed)
	if err != nil {
		return err
	}
	x0Seed, err := keys.DecodeSeed(sig.Hash.X0Seed)
	if err != nil {
		return err
	}
	x1Seed, err := keys.DecodeSeed(sig.Hash.X1Seed)
	if err != nil {
		return err
	}
	tCmp, err := ntru.ComputeTargetFromSeeds(sys, sig.Hash.BFile, mSeed, x0Seed, x1Seed)
	if err != nil {
		return err
	}
	if len(tCmp) != len(sig.Hash.TCoeffs) {
		return errors.New("t size mismatch")
	}
	for i := range tCmp {
		if tCmp[i] != sig.Hash.TCoeffs[i] {
			return errors.New("target mismatch")
		}
	}
	// Congruence: h*s1 + s0 == t (mod Q)
	h := ntru.Int64ToModQPoly(sig.PublicKey.HCoeffs, par)
	s0 := ntru.Int64ToModQPoly(sig.Signature.S0, par)
	s1 := ntru.Int64ToModQPoly(sig.Signature.S1, par)
	t := ntru.Int64ToModQPoly(tCmp, par)
	hs1, err := ntru.ConvolveRNS(s1, h, par)
	if err != nil {
		return err
	}
	lhs := hs1.Add(s0)
	for i := 0; i < par.N; i++ {
		want := new(big.Int).Mod(t.Coeffs[i], par.Q)
		got := new(big.Int).Mod(lhs.Coeffs[i], par.Q)
		if want.Cmp(got) != 0 {
			return errors.New("congruence check failed")
		}
	}
	c1Mod := ntru.Int64ToModQPoly(tCmp, par)
	s2 := hs1.Add(c1Mod)
	for i := 0; i < par.N; i++ {
		s2.Coeffs[i].Mod(s2.Coeffs[i], par.Q)
	}
	s2c, err := ntru.CenterModQToInt64(s2, par)
	if err != nil {
		return err
	}
	s2Stored := sig.Signature.S2
	if len(s2Stored) == 0 {
		s2Stored = s2c
	} else {
		if len(s2Stored) != par.N {
			return errors.New("s2 length mismatch")
		}
		for i := 0; i < par.N; i++ {
			if s2Stored[i] != s2c[i] {
				return errors.New("s2 mismatch")
			}
		}
	}
	resOpts := defaultOpts
	if par.LOG3_D {
		resOpts.UseLog3Cross = true
	}
	if !ntru.CheckNormC(sig.Signature.S1, s2Stored, par, resOpts) {
		return errors.New("norm check failed (s1,s2)")
	}
	return nil
}
