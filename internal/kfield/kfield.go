package kfield

// Package kfield implements small extension fields K/F_q represented over a power basis.
// It is self-contained and provides irreducible polynomial search, base arithmetic,
// evaluation of F-polynomials at K-points, and multiplication matrices used by PACS.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/bits"
)

// Field describes K = F_q[X]/(chi(X)) with degree theta power-basis representation.
type Field struct {
	Q     uint64
	Theta int
	Chi   []uint64
}

// Elem is a K element represented by its theta limbs in the power basis.
type Elem struct {
	Limb []uint64
}

// New constructs an extension field descriptor. chi must be monic irreducible of degree theta.
func New(q uint64, theta int, chi []uint64) (*Field, error) {
	if q == 0 {
		return nil, fmt.Errorf("kfield: q must be non-zero")
	}
	if theta <= 0 {
		return nil, fmt.Errorf("kfield: theta must be positive")
	}
	if len(chi) != theta+1 {
		return nil, fmt.Errorf("kfield: chi must have degree theta")
	}
	chiNorm := make([]uint64, len(chi))
	for i := range chi {
		chiNorm[i] = chi[i] % q
	}
	if chiNorm[len(chiNorm)-1] != 1%q {
		return nil, fmt.Errorf("kfield: chi must be monic")
	}
	if !isIrreducible(q, chiNorm) {
		return nil, fmt.Errorf("kfield: chi is reducible")
	}
	return &Field{Q: q, Theta: theta, Chi: chiNorm}, nil
}

// FindIrreducible samples random monic irreducible polynomials of degree theta over F_q.
func FindIrreducible(q uint64, theta int, rnd io.Reader) ([]uint64, error) {
	if q == 0 || theta <= 0 {
		return nil, fmt.Errorf("kfield: invalid q or theta")
	}
	if rnd == nil {
		rnd = rand.Reader
	}
	const maxTries = 1 << 16
	for try := 0; try < maxTries; try++ {
		chi := make([]uint64, theta+1)
		chi[theta] = 1 % q
		chi[0] = 1 + randU64(rnd)%(q-1)
		for i := 1; i < theta; i++ {
			chi[i] = randU64(rnd) % q
		}
		if isIrreducible(q, chi) {
			return chi, nil
		}
	}
	return nil, errors.New("kfield: failed to find irreducible polynomial")
}

// Zero returns the additive identity in K.
func (f *Field) Zero() Elem {
	return Elem{Limb: make([]uint64, f.Theta)}
}

// One returns the multiplicative identity in K.
func (f *Field) One() Elem {
	e := f.Zero()
	e.Limb[0] = 1 % f.Q
	return e
}

// EmbedF lifts an F_q element into K via the canonical embedding.
func (f *Field) EmbedF(x uint64) Elem {
	e := f.Zero()
	e.Limb[0] = x % f.Q
	return e
}

// Phi builds the power-basis element from its coordinate vector (truncated/padded as needed).
func (f *Field) Phi(coords []uint64) Elem {
	e := f.Zero()
	n := len(coords)
	if n > f.Theta {
		n = f.Theta
	}
	copy(e.Limb, coords[:n])
	for i := 0; i < f.Theta; i++ {
		e.Limb[i] %= f.Q
	}
	return e
}

// PhiInv returns a copy of the coordinates of e in the power basis.
func (f *Field) PhiInv(e Elem) []uint64 {
	out := make([]uint64, f.Theta)
	copy(out, e.Limb)
	for i := range out {
		out[i] %= f.Q
	}
	return out
}

// Add returns a + b in K.
func (f *Field) Add(a, b Elem) Elem {
	out := f.Zero()
	for i := 0; i < f.Theta; i++ {
		out.Limb[i] = modAdd(a.Limb[i]%f.Q, b.Limb[i]%f.Q, f.Q)
	}
	return out
}

// Sub returns a - b in K.
func (f *Field) Sub(a, b Elem) Elem {
	out := f.Zero()
	for i := 0; i < f.Theta; i++ {
		out.Limb[i] = modSub(a.Limb[i]%f.Q, b.Limb[i]%f.Q, f.Q)
	}
	return out
}

// Mul multiplies two K-elements using schoolbook arithmetic followed by modular reduction.
func (f *Field) Mul(a, b Elem) Elem {
	deg := f.Theta
	tmp := make([]uint64, 2*deg)
	for i := 0; i < deg; i++ {
		ai := a.Limb[i] % f.Q
		if ai == 0 {
			continue
		}
		for j := 0; j < deg; j++ {
			bj := b.Limb[j] % f.Q
			if bj == 0 {
				continue
			}
			idx := i + j
			tmp[idx] = modAdd(tmp[idx], modMul(ai, bj, f.Q), f.Q)
		}
	}
	for k := len(tmp) - 1; k >= deg; k-- {
		coeff := tmp[k] % f.Q
		if coeff == 0 {
			if k == deg {
				break
			}
			continue
		}
		tmp[k] = 0
		m := k - deg
		for j := 0; j < deg; j++ {
			tmp[m+j] = modSub(tmp[m+j], modMul(coeff, f.Chi[j]%f.Q, f.Q), f.Q)
		}
	}
	res := make([]uint64, deg)
	copy(res, tmp[:deg])
	for i := range res {
		res[i] %= f.Q
	}
	return Elem{Limb: res}
}

// MulMatrix returns the theta×theta F_q-matrix representing multiplication by e.
func (f *Field) MulMatrix(e Elem) [][]uint64 {
	M := make([][]uint64, f.Theta)
	for i := 0; i < f.Theta; i++ {
		M[i] = make([]uint64, f.Theta)
	}
	for col := 0; col < f.Theta; col++ {
		basis := f.Zero()
		basis.Limb[col] = 1 % f.Q
		prod := f.Mul(e, basis)
		for row := 0; row < f.Theta; row++ {
			M[row][col] = prod.Limb[row] % f.Q
		}
	}
	return M
}

// RandomElement samples a uniform K-element by drawing theta uniform limbs over F_q.
func (f *Field) RandomElement(r io.Reader) (Elem, error) {
	if r == nil {
		r = rand.Reader
	}
	limb := make([]uint64, f.Theta)
	for i := 0; i < f.Theta; i++ {
		limb[i] = randU64(r) % f.Q
	}
	return Elem{Limb: limb}, nil
}

// Normalize returns a copy of e with limbs reduced modulo q.
func (f *Field) Normalize(e Elem) Elem {
	out := f.Zero()
	copy(out.Limb, e.Limb)
	for i := range out.Limb {
		out.Limb[i] %= f.Q
	}
	return out
}

// IsZero reports whether all limbs of e are zero modulo q.
func (f *Field) IsZero(e Elem) bool {
	for _, limb := range e.Limb {
		if limb%f.Q != 0 {
			return false
		}
	}
	return true
}

// Pow returns base^{exp} in K using square-and-multiply. exp must be non-negative.
func (f *Field) Pow(base Elem, exp *big.Int) Elem {
	if exp == nil || exp.Sign() == 0 {
		return f.One()
	}
	result := f.One()
	cur := f.Normalize(base)
	for i := exp.BitLen() - 1; i >= 0; i-- {
		result = f.Mul(result, result)
		if exp.Bit(i) == 1 {
			result = f.Mul(result, cur)
		}
	}
	return result
}

// Inv returns the multiplicative inverse of a in K. It panics if a is zero.
func (f *Field) Inv(a Elem) Elem {
	if f.IsZero(a) {
		panic("kfield: inverse of zero element")
	}
	qBig := big.NewInt(int64(f.Q))
	thetaBig := big.NewInt(int64(f.Theta))
	exp := new(big.Int).Exp(qBig, thetaBig, nil)
	exp.Sub(exp, big.NewInt(2))
	return f.Pow(a, exp)
}

// EvalFPolyAtK evaluates an F_q-coefficient polynomial at a K-element using Horner's method.
func (f *Field) EvalFPolyAtK(coeff []uint64, e Elem) Elem {
	acc := f.Zero()
	for i := len(coeff) - 1; i >= 0; i-- {
		acc = f.Mul(acc, e)
		acc = f.Add(acc, f.EmbedF(coeff[i]))
		if i == 0 {
			break
		}
	}
	return acc
}

// randU64 reads 8 random bytes and returns them as a uint64 in little endian.
func randU64(r io.Reader) uint64 {
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		panic(err)
	}
	return uint64(buf[0]) | uint64(buf[1])<<8 | uint64(buf[2])<<16 | uint64(buf[3])<<24 |
		uint64(buf[4])<<32 | uint64(buf[5])<<40 | uint64(buf[6])<<48 | uint64(buf[7])<<56
}

func modAdd(a, b, q uint64) uint64 {
	a %= q
	b %= q
	sum := a + b
	if sum >= q || sum < a {
		sum -= q
	}
	return sum
}

func modSub(a, b, q uint64) uint64 {
	a %= q
	b %= q
	if a >= b {
		return a - b
	}
	return a + q - b
}

func modMul(a, b, q uint64) uint64 {
	a %= q
	b %= q
	hi, lo := bits.Mul64(a, b)
	_, rem := bits.Div64(hi, lo, q)
	return rem
}

func modPow(a, e, q uint64) uint64 {
	if q == 1 {
		return 0
	}
	result := uint64(1 % q)
	base := a % q
	exp := e
	for exp > 0 {
		if exp&1 == 1 {
			result = modMul(result, base, q)
		}
		exp >>= 1
		if exp > 0 {
			base = modMul(base, base, q)
		}
	}
	return result
}

func modInv(a, q uint64) uint64 {
	if a%q == 0 {
		panic("kfield: inverse of zero")
	}
	return modPow(a, q-2, q)
}

// ---------------- Polynomial helpers ----------------

type poly []uint64

func polyTrim(p poly, q uint64) poly {
	if len(p) == 0 {
		return poly{0}
	}
	idx := len(p) - 1
	for idx > 0 {
		if p[idx]%q != 0 {
			break
		}
		idx--
	}
	out := make(poly, idx+1)
	for i := 0; i <= idx; i++ {
		out[i] = p[i] % q
	}
	return out
}

func polySub(a, b poly, q uint64) poly {
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	out := make(poly, n)
	for i := 0; i < n; i++ {
		var ai, bi uint64
		if i < len(a) {
			ai = a[i]
		}
		if i < len(b) {
			bi = b[i]
		}
		out[i] = modSub(ai, bi, q)
	}
	return polyTrim(out, q)
}

func polyMul(a, b poly, q uint64) poly {
	if len(a) == 0 || len(b) == 0 {
		return poly{0}
	}
	out := make(poly, len(a)+len(b)-1)
	for i := 0; i < len(a); i++ {
		if a[i]%q == 0 {
			continue
		}
		for j := 0; j < len(b); j++ {
			if b[j]%q == 0 {
				continue
			}
			out[i+j] = modAdd(out[i+j], modMul(a[i], b[j], q), q)
		}
	}
	return polyTrim(out, q)
}

func polyDivMod(a, b poly, q uint64) (poly, poly) {
	A := polyTrim(a, q)
	B := polyTrim(b, q)
	if len(B) == 1 && B[0] == 0 {
		panic("kfield: divide by zero polynomial")
	}
	if len(A) < len(B) {
		return poly{0}, A
	}
	rem := make(poly, len(A))
	copy(rem, A)
	quotient := make(poly, len(A)-len(B)+1)
	invLead := modInv(B[len(B)-1], q)
	for i := len(A) - 1; i >= len(B)-1; i-- {
		coeff := rem[i]
		if coeff != 0 {
			coeff = modMul(coeff, invLead, q)
			qIdx := i - (len(B) - 1)
			quotient[qIdx] = coeff
			for j := 0; j < len(B); j++ {
				remIdx := i - j
				rem[remIdx] = modSub(rem[remIdx], modMul(coeff, B[len(B)-1-j], q), q)
			}
		}
		if i == len(B)-1 {
			break
		}
	}
	return polyTrim(quotient, q), polyTrim(rem[:len(B)-1], q)
}

func polyMod(a, b poly, q uint64) poly {
	_, r := polyDivMod(a, b, q)
	return r
}

func polyGCD(a, b poly, q uint64) poly {
	A := polyTrim(a, q)
	B := polyTrim(b, q)
	zero := func(p poly) bool { return len(p) == 1 && p[0] == 0 }
	for !zero(B) {
		_, r := polyDivMod(A, B, q)
		A, B = B, r
	}
	lead := A[len(A)-1]
	inv := modInv(lead, q)
	for i := range A {
		A[i] = modMul(A[i], inv, q)
	}
	return A
}

func polyPowMod(base poly, exp uint64, modulus poly, q uint64) poly {
	result := poly{1}
	b := polyTrim(base, q)
	m := polyTrim(modulus, q)
	e := exp
	for e > 0 {
		if e&1 == 1 {
			result = polyMod(polyMul(result, b, q), m, q)
		}
		e >>= 1
		if e > 0 {
			b = polyMod(polyMul(b, b, q), m, q)
		}
	}
	return polyTrim(result, q)
}

func frobPow(polyX poly, q uint64, modulus poly) poly {
	return polyPowMod(polyX, q, modulus, q)
}

// isIrreducible implements the Ben-Or/Frobenius irreducibility test for prime fields.
func isIrreducible(q uint64, f poly) bool {
	f = polyTrim(f, q)
	if len(f) <= 1 {
		return false
	}
	n := len(f) - 1
	x := poly{0, 1}
	xp := poly{0, 1}
	for i := 1; i <= n/2; i++ {
		xp = frobPow(xp, q, f)
		g := polyGCD(polySub(xp, x, q), f, q)
		if len(g) > 1 {
			return false
		}
	}
	xp = poly{0, 1}
	for i := 0; i < n; i++ {
		xp = frobPow(xp, q, f)
	}
	diff := polyTrim(polySub(xp, x, q), q)
	return len(diff) == 1 && diff[0] == 0
}
