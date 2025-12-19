package ntru

import (
	"errors"
	"math/big"
)

// CenterModQToInt64 converts a polynomial with big.Int coefficients
// modulo q into a slice of signed int64 coefficients in the interval
// [-q/2,q/2). It returns an error if dimensions mismatch or if q does
// not fit into an int64.
func CenterModQToInt64(a ModQPoly, par Params) ([]int64, error) {
	if len(a.Coeffs) != par.N {
		return nil, errors.New("dimension mismatch")
	}
	if !par.Q.IsInt64() {
		return nil, errors.New("q does not fit into int64")
	}
	halfUp := new(big.Int).Rsh(par.Q, 1)
	out := make([]int64, par.N)
	for i := 0; i < par.N; i++ {
		ci := new(big.Int).Mod(new(big.Int).Set(a.Coeffs[i]), par.Q)
		if ci.Cmp(halfUp) == 1 {
			ci.Sub(ci, par.Q)
		}
		if !ci.IsInt64() {
			return nil, errors.New("coefficient out of int64 range")
		}
		out[i] = ci.Int64()
	}
	return out, nil
}

// TargetToEval centers the target polynomial t modulo q and maps it to
// the Eval domain using the embedding parameters provided.
func TargetToEval(t ModQPoly, par Params, epar EmbedParams) (EvalVec, error) {
	centered, err := CenterModQToInt64(t, par)
	if err != nil {
		return EvalVec{}, err
	}
	return ToEval(centered, par, epar)
}

// EvalToTargetInt converts an Eval-domain vector back to centered
// integer coefficients. It is the inverse of TargetToEval.
func EvalToTargetInt(ev EvalVec, par Params, epar EmbedParams) ([]int64, error) {
	cv, err := ToCoeffInt(ev, par, epar)
	if err != nil {
		return nil, err
	}
	return cv.Int, nil
}
