package ntru

import (
	"math"
	"math/big"
	"testing"

	ps "vSIS-Signature/Preimage_Sampler"
)

func approxEqual(a, b, eps float64) bool {
	return math.Abs(a-b) <= eps
}

// TestFieldOpsMulAdd checks that FieldMulBig combined with FieldAddBig
// matches double-precision complex arithmetic, emulating the C helper
// cpoly_sum_pairs(a, b, c, d) = a*b + c*d.
func TestFieldOpsMulAdd(t *testing.T) {
	const n = 4
	prec := uint(128)
	a := ps.NewFieldElemBig(n, prec)
	b := ps.NewFieldElemBig(n, prec)
	c := ps.NewFieldElemBig(n, prec)
	d := ps.NewFieldElemBig(n, prec)
	for i := 0; i < n; i++ {
		a.Coeffs[i] = ps.NewBigComplex(float64(i+1), float64(2*i-1), prec)
		b.Coeffs[i] = ps.NewBigComplex(float64(3*i-2), float64(5-i), prec)
		c.Coeffs[i] = ps.NewBigComplex(float64(-i), float64(i+1), prec)
		d.Coeffs[i] = ps.NewBigComplex(float64(2-i), -3, prec)
	}
	got := ps.FieldAddBig(ps.FieldMulBig(a, b), ps.FieldMulBig(c, d))
	for i := 0; i < n; i++ {
		ar, _ := a.Coeffs[i].Real.Float64()
		ai, _ := a.Coeffs[i].Imag.Float64()
		br, _ := b.Coeffs[i].Real.Float64()
		bi, _ := b.Coeffs[i].Imag.Float64()
		cr, _ := c.Coeffs[i].Real.Float64()
		ci, _ := c.Coeffs[i].Imag.Float64()
		dr, _ := d.Coeffs[i].Real.Float64()
		di, _ := d.Coeffs[i].Imag.Float64()
		want := complex(ar, ai)*complex(br, bi) + complex(cr, ci)*complex(dr, di)
		gr, _ := got.Coeffs[i].Real.Float64()
		gi, _ := got.Coeffs[i].Imag.Float64()
		if diff := math.Hypot(gr-real(want), gi-imag(want)); diff > 1e-12 {
			t.Fatalf("slot %d diff %g", i, diff)
		}
	}
}

// TestFieldOpsConjDiv verifies conjugation and division by real scalars
// against native complex128 arithmetic.
func TestFieldOpsConjDiv(t *testing.T) {
	const n = 4
	prec := uint(128)
	x := ps.NewFieldElemBig(n, prec)
	norms := make([]*big.Float, n)
	for i := 0; i < n; i++ {
		x.Coeffs[i] = ps.NewBigComplex(float64(i+2), float64(1-i), prec)
		norms[i] = new(big.Float).SetPrec(prec).SetFloat64(float64(i + 3))
	}
	conj := x.Conj()
	for i := 0; i < n; i++ {
		xr, _ := x.Coeffs[i].Real.Float64()
		xi, _ := x.Coeffs[i].Imag.Float64()
		cr, _ := conj.Coeffs[i].Real.Float64()
		ci, _ := conj.Coeffs[i].Imag.Float64()
		if !approxEqual(cr, xr, 1e-15) || !approxEqual(ci, -xi, 1e-15) {
			t.Fatalf("conj slot %d got %v + %vi want %v - %vi", i, cr, ci, xr, xi)
		}
	}
	div := ps.FieldScalarDiv(x, norms)
	for i := 0; i < n; i++ {
		xr, _ := x.Coeffs[i].Real.Float64()
		xi, _ := x.Coeffs[i].Imag.Float64()
		dn, _ := norms[i].Float64()
		want := complex(xr, xi) / complex(dn, 0)
		dr, _ := div.Coeffs[i].Real.Float64()
		di, _ := div.Coeffs[i].Imag.Float64()
		if diff := math.Hypot(dr-real(want), di-imag(want)); diff > 1e-12 {
			t.Fatalf("div slot %d diff %g", i, diff)
		}
	}
}
