package PIOP

// MaskConfig captures masking/degree knobs so builders can share configuration.
type MaskConfig struct {
	Rho      int
	EllPrime int
	Ell      int
	Eta      int
	DQ       int
}

// MaskConfigFromOpts derives a MaskConfig from SimOpts.
func MaskConfigFromOpts(o SimOpts) MaskConfig {
	return MaskConfig{
		Rho:      o.Rho,
		EllPrime: o.EllPrime,
		Ell:      o.Ell,
		Eta:      o.Eta,
		DQ:       o.DQOverride,
	}
}
