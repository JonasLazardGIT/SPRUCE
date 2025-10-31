package ntru

import "math"

const (
	AntragAlpha           = 1.25
	AntragSlack           = 1.042
	AntragSigmaScale      = 1.0
	AntragReduceIters     = 64
	defaultResidualFactor = 4.0
)

type SamplerOpts struct {
	Prec       uint    // floating precision for embedding/big.Float
	SigmaScale float64 // multiplier >= 1.0 applied to sqrt(diag(D)) per slot
	// C-style parameters (from antrag param.h / gen headers)
	Alpha         float64 // ANTRAG_ALPHA
	RSquare       float64 // R_SQUARE
	Slack         float64 // ANTRAG_SLACK
	UseLog3Cross  bool    // include log3 cross-terms in check_norm
	MaxSignTrials int     // max trials in SignC (default 128)
	ReduceIters   int     // extra Babai reduction iterations before C-sign
	SaltBytes     int     // length of salt for hashing (default 32; match C presets if known)
	// Eval Gaussian sampler behavior
	UseCNormalDist bool // if true, use Box–Muller (C-like) for Eval Gaussian instead of NormFloat64
	// Tightening options (runtime always enforces C-style residual acceptance)
	UseExactResidual bool    // retained for API compatibility (always forced to true)
	BoundShape       string  // retained for API compatibility (always forced to "cstyle")
	ResidualLInf     float64 // optional L∞ cap on center(h*s1 + c1); <=0 disables
}

// ApplyDefaults fills unset fields with Antrag reference values.
func (opts *SamplerOpts) ApplyDefaults(par Params) {
	if opts.RSquare <= 0 {
		opts.RSquare = CReferenceRSquare()
	}
	if opts.Alpha <= 0 {
		opts.Alpha = AntragAlpha
	}
	if opts.Slack <= 0 {
		opts.Slack = AntragSlack
	}
	if opts.SigmaScale <= 0 {
		opts.SigmaScale = AntragSigmaScale
	}
	if opts.ReduceIters <= 0 {
		opts.ReduceIters = AntragReduceIters
	}
	if opts.ResidualLInf < 0 {
		opts.ResidualLInf = 0
	}
	if opts.ResidualLInf == 0 {
		qf := float64(par.Q.Uint64())
		sigma := math.Sqrt(opts.RSquare * opts.Alpha * opts.Alpha * qf)
		opts.ResidualLInf = defaultResidualFactor * opts.Slack * sigma
	}
}
