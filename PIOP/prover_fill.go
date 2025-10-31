package PIOP

import (
	"fmt"
	"math/big"
	"time"

	measure "vSIS-Signature/measure"
	prof "vSIS-Signature/prof"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// ChainDecomp holds magnitude and digit columns for the membership-chain gadget.
type ChainDecomp struct {
	M []*ring.Poly
	D [][]*ring.Poly
}

// appendChainDigits allocates, for each signature row, one magnitude row and two digit rows.
func appendChainDigits(r *ring.Ring, mSig, digits int) ChainDecomp {
	defer prof.Track(time.Now(), "appendChainDigits")
	if digits <= 0 {
		panic("appendChainDigits: digit count must be positive")
	}
	mk := func() *ring.Poly { p := r.NewPoly(); r.NTT(p, p); return p }
	cd := ChainDecomp{
		M: make([]*ring.Poly, mSig),
		D: make([][]*ring.Poly, mSig),
	}
	for t := 0; t < mSig; t++ {
		cd.M[t] = mk()
		cd.D[t] = make([]*ring.Poly, digits)
		for i := 0; i < digits; i++ {
			cd.D[t][i] = mk()
		}
	}
	if measure.Enabled {
		qb := new(big.Int).SetUint64(r.Modulus[0])
		bytesR := measure.BytesRing(r.N, qb)
		measure.Global.Add("piop/witness/linf_chain/M", int64(len(cd.M))*int64(bytesR))
		measure.Global.Add("piop/witness/linf_chain/D", int64(len(cd.D))*int64(digits)*int64(bytesR))
	}
	return cd
}

// ProverFillLinfChain populates magnitude and digit rows for the membership-chain gadget.
func ProverFillLinfChain(
	r *ring.Ring,
	P []*ring.Poly,
	spec LinfSpec,
	omega []uint64, ell int,
	cd ChainDecomp,
) error {
	defer prof.Track(time.Now(), "ProverFillLinfChain")
	q := r.Modulus[0]
	mSig := len(P)
	s := len(omega)
	R := int64(spec.R)
	maxAbs := spec.MaxAbs
	if spec.L <= 0 {
		return fmt.Errorf("linfchain: invalid digit count %d", spec.L)
	}
	if len(cd.M) != mSig || len(cd.D) != mSig {
		return fmt.Errorf("chain decomp size mismatch: got %d rows, want %d", len(cd.M), mSig)
	}
	coeffP := make([]*ring.Poly, mSig)
	for t := 0; t < mSig; t++ {
		coeffP[t] = r.NewPoly()
		r.InvNTT(P[t], coeffP[t])
	}
	for t := 0; t < mSig; t++ {
		valsM := make([]uint64, s)
		valsDigit := make([][]uint64, spec.L)
		for i := 0; i < spec.L; i++ {
			valsDigit[i] = make([]uint64, s)
		}
		for j := 0; j < s; j++ {
			wj := omega[j] % q
			av := EvalPoly(coeffP[t].Coeffs[0], wj, q)
			a := int64(av)
			if a > int64(q)/2 {
				a -= int64(q)
			}
			absA := a
			if absA < 0 {
				absA = -absA
			}
			if uint64(absA) > maxAbs {
				return fmt.Errorf("linfchain: |P|=%d exceeds supported bound %d", absA, maxAbs)
			}
			remaining := absA
			digits := make([]int64, spec.L)
			for idx := 0; idx < spec.L; idx++ {
				if idx == spec.L-1 {
					digit := remaining
					if digit < 0 || digit > int64(spec.DMax[idx]) {
						return fmt.Errorf("linfchain: D%d out of range (%d)", idx, digit)
					}
					digits[idx] = digit
					remaining = 0
					continue
				}
				digit := remaining % R
				remaining /= R
				if idx == 0 {
					lo := int64(spec.LSDLo)
					hi := int64(spec.LSDHi)
					if lo >= 0 {
						lo = -int64(spec.DMax[0])
					}
					if hi <= 0 {
						hi = int64(spec.DMax[0])
					}
					for digit > hi {
						digit -= R
						remaining++
					}
					for digit < lo {
						digit += R
						remaining--
					}
					if digit < lo || digit > hi {
						return fmt.Errorf("linfchain: D0 out of range (%d)", digit)
					}
				} else {
					if digit < 0 || digit > int64(spec.DMax[idx]) {
						return fmt.Errorf("linfchain: D%d out of range (%d)", idx, digit)
					}
				}
				digits[idx] = digit
			}
			if remaining != 0 {
				return fmt.Errorf("linfchain: leftover magnitude (%d) after digit decomposition", remaining)
			}
			valsM[j] = liftToField(q, absA)
			for idx := 0; idx < spec.L; idx++ {
				valsDigit[idx][j] = liftToField(q, digits[idx])
			}
		}
		rowM := buildValueRow(r, valsM, omega, ell)
		copyPolyNTT(cd.M[t], rowM)
		if len(cd.D[t]) != spec.L {
			return fmt.Errorf("linfchain: row %d digit slice length %d != spec.L=%d", t, len(cd.D[t]), spec.L)
		}
		for idx := 0; idx < spec.L; idx++ {
			rowDigit := buildValueRow(r, valsDigit[idx], omega, ell)
			copyPolyNTT(cd.D[t][idx], rowDigit)
		}
	}
	return nil
}

func liftToField(q uint64, v int64) uint64 {
	if v >= 0 {
		return uint64(v) % q
	}
	neg := uint64(-v) % q
	if neg == 0 {
		return 0
	}
	return (q - neg) % q
}
