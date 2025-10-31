package ntru

import (
    "fmt"
    "os"
)

// PublicKeyH computes h = g * f^{-1} (mod q) in R_q.
// f and g are ModQPoly in coefficient domain.
func PublicKeyH(f, g ModQPoly, par Params) (ModQPoly, error) {
    dbg(os.Stderr, "[H] PublicKeyH begin N=%d Q=%s\n", par.N, par.Q.String())
	fInv, ok := InvertModQ(f, par)
	if !ok {
		return ModQPoly{}, fmt.Errorf("PublicKeyH: f is not invertible in R_q")
	}
	h, err := ConvolveRNS(g, fInv, par)
	if err != nil {
		return ModQPoly{}, fmt.Errorf("PublicKeyH: convolution failed: %w", err)
	}
	dbg(os.Stderr, "[H] PublicKeyH done\n")
	return h, nil
}
