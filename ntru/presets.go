package ntru

import "math/big"

// PresetPower2_512_Q1038337 returns Params and SamplerOpts tuned to Table 2 (q=1038337, d=512).
func PresetPower2_512_Q1038337() (Params, SamplerOpts, error) {
	par, err := NewParams(512, big.NewInt(1038337))
	if err != nil {
		return Params{}, SamplerOpts{}, err
	}
	// single-limb RNS for simplicity
	par, _ = par.WithRNSFactorization([]uint64{1038337})
	// Quality alpha ~1.15, Slack ~1.042, smoothing R^2 ~ 1
	opts := SamplerOpts{
		Prec:    128,
		Alpha:   1.15,
		RSquare: CReferenceRSquare(),
		Slack:   1.042,
		// allow more trials up-front for large-N acceptance
		MaxSignTrials: 8000,
		SaltBytes:     32,
	}
	opts.ReduceIters = 64
	opts.UseCNormalDist = true
	return par, opts, nil
}

// PresetPower2_1024_Q1038337 returns Table 2 option (d=1024, q=1038337) with alpha≈1.23.
func PresetPower2_1024_Q1038337() (Params, SamplerOpts, error) {
	par, err := NewParams(1024, big.NewInt(1038337))
	if err != nil {
		return Params{}, SamplerOpts{}, err
	}
	par, _ = par.WithRNSFactorization([]uint64{1038337})
	opts := SamplerOpts{Prec: 128, Alpha: 1.23, RSquare: CReferenceRSquare(), Slack: 1.042, MaxSignTrials: 12000, SaltBytes: 32}
	opts.ReduceIters = 64
	opts.UseCNormalDist = true
	return par, opts, nil
}

// PresetPower2_512_Q3329 returns Table 2 option (d=512, q=3329) with alpha≈1.23.
func PresetPower2_512_Q3329() (Params, SamplerOpts, error) {
	par, err := NewParams(512, big.NewInt(3329))
	if err != nil {
		return Params{}, SamplerOpts{}, err
	}
	par, _ = par.WithRNSFactorization([]uint64{3329})
	opts := SamplerOpts{Prec: 128, Alpha: 1.23, RSquare: CReferenceRSquare(), Slack: 1.042, MaxSignTrials: 8000, SaltBytes: 32}
	opts.ReduceIters = 64
	opts.UseCNormalDist = true
	return par, opts, nil
}

// 3-smooth conductor presets (Table 3), modulus q = 1038337
func PresetSmooth3_648_Q1038337() (Params, SamplerOpts, error) {
	par, err := NewParams(648, big.NewInt(1038337))
	if err != nil {
		return Params{}, SamplerOpts{}, err
	}
	par, _ = par.WithRNSFactorization([]uint64{1038337})
	opts := SamplerOpts{Prec: 128, Alpha: 1.17, RSquare: CReferenceRSquare(), Slack: 1.042, MaxSignTrials: 16000, SaltBytes: 32}
	opts.ReduceIters = 64
	opts.UseCNormalDist = true
	return par, opts, nil
}

func PresetSmooth3_768_Q1038337() (Params, SamplerOpts, error) {
	par, err := NewParams(768, big.NewInt(1038337))
	if err != nil {
		return Params{}, SamplerOpts{}, err
	}
	par, _ = par.WithRNSFactorization([]uint64{1038337})
	opts := SamplerOpts{Prec: 128, Alpha: 1.19, RSquare: CReferenceRSquare(), Slack: 1.042, MaxSignTrials: 16000, SaltBytes: 32}
	opts.ReduceIters = 64
	opts.UseCNormalDist = true
	return par, opts, nil
}

func PresetSmooth3_864_Q1038337() (Params, SamplerOpts, error) {
	par, err := NewParams(864, big.NewInt(1038337))
	if err != nil {
		return Params{}, SamplerOpts{}, err
	}
	par, _ = par.WithRNSFactorization([]uint64{1038337})
	opts := SamplerOpts{Prec: 128, Alpha: 1.21, RSquare: CReferenceRSquare(), Slack: 1.042, MaxSignTrials: 16000, SaltBytes: 32}
	opts.ReduceIters = 64
	opts.UseCNormalDist = true
	return par, opts, nil
}

func PresetSmooth3_972_Q1038337() (Params, SamplerOpts, error) {
	par, err := NewParams(972, big.NewInt(1038337))
	if err != nil {
		return Params{}, SamplerOpts{}, err
	}
	par, _ = par.WithRNSFactorization([]uint64{1038337})
	opts := SamplerOpts{Prec: 128, Alpha: 1.22, RSquare: CReferenceRSquare(), Slack: 1.042, MaxSignTrials: 20000, SaltBytes: 32}
	opts.ReduceIters = 64
	opts.UseCNormalDist = true
	return par, opts, nil
}

// Small 3-smooth presets for tests and validation
func PresetSmooth3_6_Q1038337() (Params, SamplerOpts, error) {
	par, err := NewParams(6, big.NewInt(1038337))
	if err != nil {
		return Params{}, SamplerOpts{}, err
	}
	par.M = 6
	par.LOG3_D = true
	par, _ = par.WithRNSFactorization([]uint64{1038337})
	opts := SamplerOpts{Prec: 128, Alpha: 1.20, RSquare: CReferenceRSquare(), Slack: 1.042, MaxSignTrials: 4000, SaltBytes: 32}
	opts.ReduceIters = 64
	opts.UseCNormalDist = true
	return par, opts, nil
}

func PresetSmooth3_12_Q1038337() (Params, SamplerOpts, error) {
	par, err := NewParams(12, big.NewInt(1038337))
	if err != nil {
		return Params{}, SamplerOpts{}, err
	}
	par.M = 12
	par.LOG3_D = true
	par, _ = par.WithRNSFactorization([]uint64{1038337})
	opts := SamplerOpts{Prec: 128, Alpha: 1.20, RSquare: CReferenceRSquare(), Slack: 1.042, MaxSignTrials: 4000, SaltBytes: 32}
	opts.ReduceIters = 64
	opts.UseCNormalDist = true
	return par, opts, nil
}
