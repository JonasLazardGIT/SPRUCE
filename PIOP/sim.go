package PIOP

import (
	"errors"
	"fmt"
)

// ErrMissingFixture is returned when required fixture files are absent.
var ErrMissingFixture = errors.New("missing fixtures")

// ErrInvalidParams is returned when the simulation options are invalid.
var ErrInvalidParams = errors.New("invalid parameters")

// SimResult captures the verifier outcomes of a simulation run.
type SimResult struct {
	OkLin bool
	OkEq4 bool
	OkSum bool
}

// RunSimulation executes the PACS flow with the provided options.
// It returns the verifier outcomes. If required fixtures are missing, an
// ErrMissingFixture is returned. If the parameter combination is invalid,
// ErrInvalidParams is returned.
func RunSimulation(o SimOpts) (SimResult, error) {
	if o.Rho < o.Ell {
		return SimResult{}, fmt.Errorf("%w: rho (%d) must be >= ell (%d)", ErrInvalidParams, o.Rho, o.Ell)
	}

	ctx, okLin, okEq4, okSum := buildSimWith(nil, o)
	if ctx == nil {
		return SimResult{OkLin: okLin, OkEq4: okEq4, OkSum: okSum}, ErrMissingFixture
	}
	return SimResult{OkLin: okLin, OkEq4: okEq4, OkSum: okSum}, nil
}
