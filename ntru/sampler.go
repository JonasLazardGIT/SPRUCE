package ntru

// This file previously provided strict/GPV preimage helpers. Hybrid‑B is now the only path.

// SolveAndSample solves for (F,G) and samples a Hybrid‑B preimage for t given (f,g).
func SolveAndSample(f, g []int64, t ModQPoly, par Params, opts SolveOpts) (z0, z1 []int64, err error) {
	F, G, err := NTRUSolve(f, g, par, opts)
	if err != nil {
		return nil, nil, err
	}
	S, err := NewSampler(f, g, F, G, par, opts.Prec)
	if err != nil {
		return nil, nil, err
	}
	// Set sane default sampler options for Hybrid‑B path
	// - Precision is enforced >=256 in NewSampler
	// - Use C-style sigma computation with Alpha, RSquare and modest Slack
	S.Opts.Alpha = 1.25
	S.Opts.RSquare = CReferenceRSquare()
	S.Opts.Slack = 1.042
	S.Opts.UseCNormalDist = true
	if err := S.BuildGram(); err != nil {
		return nil, nil, err
	}
	// Route through Hybrid‑B sampler and convert to []int64
	s0, s1, _, err := S.SamplePreimageTargetOptionB(t, 1<<16)
	if err != nil {
		return nil, nil, err
	}
	z0 = make([]int64, par.N)
	z1 = make([]int64, par.N)
	for i := 0; i < par.N; i++ {
		z0[i] = s0.Coeffs[i].Int64()
		z1[i] = s1.Coeffs[i].Int64()
	}
	return z0, z1, nil
}
