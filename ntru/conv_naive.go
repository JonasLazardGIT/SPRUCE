package ntru

import "math/big"

// NaiveConvolutionZ computes negacyclic convolution over Z modulo x^N+1.
func NaiveConvolutionZ(a, b IntPoly, N int) IntPoly {
	res := NewIntPoly(N)
	for i, ai := range a.Coeffs {
		for j, bj := range b.Coeffs {
			tmp := new(big.Int).Mul(ai, bj)
			k := i + j
			if k < N {
				res.Coeffs[k].Add(res.Coeffs[k], tmp)
			} else {
				res.Coeffs[k-N].Sub(res.Coeffs[k-N], tmp)
			}
		}
	}
	return res
}

// NaiveConvolutionModQ computes negacyclic convolution modulo Q.
func NaiveConvolutionModQ(a, b ModQPoly, N int) ModQPoly {
	res := NewModQPoly(N, a.Q)
	for i, ai := range a.Coeffs {
		for j, bj := range b.Coeffs {
			tmp := new(big.Int).Mul(ai, bj)
			k := i + j
			if k < N {
				res.Coeffs[k].Add(res.Coeffs[k], tmp)
			} else {
				res.Coeffs[k-N].Sub(res.Coeffs[k-N], tmp)
			}
		}
	}
	for _, c := range res.Coeffs {
		c.Mod(c, a.Q)
	}
	return res
}
