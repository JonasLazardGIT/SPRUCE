package ntru

import (
	"math/big"

	ps "vSIS-Signature/Preimage_Sampler"
)

// HermitianTransposeElem returns the Hermitian transpose of a cyclotomic field element.
// - If input is in Coeff domain:  out[0] = f[0], out[i] = -f[n-i] for i=1..n-1.
// - If input is in Eval domain:   out[kp] = conj(f[k]) with kp = n-k-1.
// The output preserves the input domain flag.
func HermitianTransposeElem(f *ps.CyclotomicFieldElem) *ps.CyclotomicFieldElem {
	n := f.N
	prec := f.Coeffs[0].Real.Prec()
	out := ps.NewFieldElemBig(n, prec)

	switch f.Domain {
	case ps.Coeff:
		for i := 0; i < n; i++ {
			if i == 0 {
				out.Coeffs[0] = &ps.BigComplex{
					Real: new(big.Float).SetPrec(prec).Copy(f.Coeffs[0].Real),
					Imag: new(big.Float).SetPrec(prec).Copy(f.Coeffs[0].Imag),
				}
			} else {
				src := f.Coeffs[n-i]
				out.Coeffs[i] = &ps.BigComplex{
					Real: new(big.Float).SetPrec(prec).Neg(src.Real),
					Imag: new(big.Float).SetPrec(prec).Neg(src.Imag),
				}
			}
		}
		out.Domain = ps.Coeff
	case ps.Eval:
		for k := 0; k < n; k++ {
			kp := n - k - 1
			src := f.Coeffs[k]
			out.Coeffs[kp] = &ps.BigComplex{
				Real: new(big.Float).SetPrec(prec).Copy(src.Real),
				Imag: new(big.Float).SetPrec(prec).Neg(src.Imag),
			}
		}
		out.Domain = ps.Eval
	default:
		panic("HermitianTransposeElem: unknown domain")
	}
	return out
}
