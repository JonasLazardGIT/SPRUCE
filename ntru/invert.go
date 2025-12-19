package ntru

import (
	"math/big"
	"os"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// InvertModQ returns the inverse of f in R_q if it exists.
func InvertModQ(f ModQPoly, par Params) (ModQPoly, bool) {
	dbg(os.Stderr, "[Inv] InvertModQ begin N=%d\n", par.N)
	rings, err := par.BuildRings()
	if err != nil {
		return ModQPoly{}, false
	}
	if len(rings) == 0 {
		return ModQPoly{}, false
	}

	limbs := ToRNS(f, par)
	outLimbs := make([]*ring.Poly, len(rings))
	for i, r := range rings {
		qi := r.Modulus[0]
		fp := polyP{coeffs: make([]uint64, par.N), q: qi}
		for j := 0; j < par.N; j++ {
			fp.coeffs[j] = limbs[i].Coeffs[0][j] % qi
		}
		gi, ok := invertPoly(fp, par.N)
		if !ok {
			return ModQPoly{}, false
		}
		invPoly := r.NewPoly()
		for j := 0; j < par.N; j++ {
			invPoly.Coeffs[0][j] = gi.coeffs[j]
		}
		outLimbs[i] = invPoly
	}
	fInv := FromRNS(outLimbs, par)
	one, err := ConvolveRNS(f, fInv, par)
	if err != nil {
		return ModQPoly{}, false
	}
	for i := 0; i < par.N; i++ {
		coeff := new(big.Int).Mod(one.Coeffs[i], par.Q)
		if i == 0 {
			if coeff.Cmp(big.NewInt(1)) != 0 {
				return ModQPoly{}, false
			}
		} else if coeff.Sign() != 0 {
			return ModQPoly{}, false
		}
	}
	dbg(os.Stderr, "[Inv] InvertModQ done\n")
	return fInv, true
}

// IsUnitModQ reports whether f is invertible in R_q.
func IsUnitModQ(f ModQPoly, par Params) bool {
	_, ok := InvertModQ(f, par)
	return ok
}

// polyP represents a polynomial with coefficients mod q.
type polyP struct {
	coeffs []uint64
	q      uint64
}

func (p polyP) degree() int {
	for i := len(p.coeffs) - 1; i >= 0; i-- {
		if p.coeffs[i]%p.q != 0 {
			return i
		}
	}
	return -1
}

func polySub(a, b polyP) polyP {
	n := len(a.coeffs)
	if len(b.coeffs) > n {
		n = len(b.coeffs)
	}
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		var ai, bi uint64
		if i < len(a.coeffs) {
			ai = a.coeffs[i]
		}
		if i < len(b.coeffs) {
			bi = b.coeffs[i]
		}
		out[i] = modSub(ai, bi, a.q)
	}
	return polyP{coeffs: out, q: a.q}
}

func polyScalarMul(a polyP, c uint64) polyP {
	out := make([]uint64, len(a.coeffs))
	for i := range a.coeffs {
		out[i] = modMul(a.coeffs[i], c, a.q)
	}
	return polyP{coeffs: out, q: a.q}
}

func polyMul(a, b polyP) polyP {
	out := make([]uint64, len(a.coeffs)+len(b.coeffs)-1)
	for i, ai := range a.coeffs {
		if ai == 0 {
			continue
		}
		for j, bj := range b.coeffs {
			if bj == 0 {
				continue
			}
			prod := modMul(ai, bj, a.q)
			out[i+j] = modAdd(out[i+j], prod, a.q)
		}
	}
	return polyP{coeffs: out, q: a.q}
}

func polyDiv(a, b polyP) (polyP, polyP, bool) {
	db := b.degree()
	if db < 0 {
		return polyP{}, polyP{}, false
	}
	q := a.q
	r := make([]uint64, len(a.coeffs))
	copy(r, a.coeffs)
	da := degreeSlice(r)
	qcoeffs := make([]uint64, 0)
	inv, ok := modInv(b.coeffs[db], q)
	if !ok {
		return polyP{}, polyP{}, false
	}
	for da >= db {
		coef := modMul(r[da], inv, q)
		shift := da - db
		if shift >= len(qcoeffs) {
			tmp := make([]uint64, shift+1)
			copy(tmp, qcoeffs)
			qcoeffs = tmp
		}
		qcoeffs[shift] = modAdd(qcoeffs[shift], coef, q)
		for i := 0; i <= db; i++ {
			idx := i + shift
			term := modMul(coef, b.coeffs[i], q)
			r[idx] = modSub(r[idx], term, q)
		}
		da = degreeSlice(r)
	}
	return polyP{coeffs: trimSlice(qcoeffs), q: q}, polyP{coeffs: trimSlice(r), q: q}, true
}

func degreeSlice(a []uint64) int {
	for i := len(a) - 1; i >= 0; i-- {
		if a[i] != 0 {
			return i
		}
	}
	return -1
}

func trimSlice(a []uint64) []uint64 {
	i := len(a) - 1
	for i >= 0 {
		if a[i] != 0 {
			break
		}
		i--
	}
	return a[:i+1]
}

func reduceModXN1(a polyP, N int) polyP {
	out := make([]uint64, N)
	q := a.q
	for i, coeff := range a.coeffs {
		coeff %= q
		idx := i % N
		if (i/N)%2 == 0 {
			out[idx] = modAdd(out[idx], coeff, q)
		} else {
			out[idx] = modSub(out[idx], coeff, q)
		}
	}
	return polyP{coeffs: out, q: q}
}

func invertPoly(f polyP, N int) (polyP, bool) {
	q := f.q
	R0 := polyP{coeffs: make([]uint64, N+1), q: q}
	R0.coeffs[0] = 1
	R0.coeffs[N] = 1
	R1 := polyP{coeffs: append([]uint64(nil), f.coeffs...), q: q}
	S0 := polyP{coeffs: []uint64{1}, q: q}
	S1 := polyP{coeffs: []uint64{}, q: q}
	T0 := polyP{coeffs: []uint64{}, q: q}
	T1 := polyP{coeffs: []uint64{1}, q: q}
	for R1.degree() >= 0 {
		qhat, r2, ok := polyDiv(R0, R1)
		if !ok {
			return polyP{}, false
		}
		R0, R1 = R1, r2
		tmpS := S0
		tmpT := T0
		S0 = S1
		T0 = T1
		S1 = polySub(tmpS, polyMul(qhat, S1))
		T1 = polySub(tmpT, polyMul(qhat, T1))
	}
	if R0.degree() != 0 || R0.coeffs[0] == 0 {
		return polyP{}, false
	}
	invConst, ok := modInv(R0.coeffs[0], q)
	if !ok {
		return polyP{}, false
	}
	g := polyScalarMul(T0, invConst)
	g = reduceModXN1(g, N)
	g.coeffs = padToN(g.coeffs, N)
	return g, true
}

func padToN(a []uint64, N int) []uint64 {
	if len(a) < N {
		tmp := make([]uint64, N)
		copy(tmp, a)
		return tmp
	}
	return a[:N]
}

func modAdd(x, y, q uint64) uint64 {
	z := x + y
	if z < x || z >= q {
		z -= q
	}
	return z
}

func modSub(x, y, q uint64) uint64 {
	if x >= y {
		return x - y
	}
	return x + (q - y)
}

func modMul(x, y, q uint64) uint64 {
	bx := new(big.Int).SetUint64(x)
	by := new(big.Int).SetUint64(y)
	bq := new(big.Int).SetUint64(q)
	prod := new(big.Int).Mul(bx, by)
	prod.Mod(prod, bq)
	return prod.Uint64()
}

func modInv(a, q uint64) (uint64, bool) {
	A := new(big.Int).SetUint64(a)
	Q := new(big.Int).SetUint64(q)
	inv := new(big.Int).ModInverse(A, Q)
	if inv == nil {
		return 0, false
	}
	return inv.Uint64(), true
}
