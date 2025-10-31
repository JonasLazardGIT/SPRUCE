//go:build testonly

package ntru

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"os"

	"golang.org/x/crypto/sha3"
	ps "vSIS-Signature/Preimage_Sampler"
)

// CSig is a minimal C-style signature with s1 and salt.
type CSig struct {
	S1   []int64
	Salt []byte
}

// hashToTargetXOF fills a ModQPoly by reading from xof and mapping to [0,Q) using C's 16-bit
// rejection sampling if Q < 2^16, otherwise a 64-bit rejection sampling fallback.
func hashToTargetXOF(xof io.Reader, par Params) ModQPoly {
	n := par.N
	out := NewModQPoly(n, par.Q)
	// If Q fits in 16 bits, use C's Q_MULT16 method for exact parity.
	if par.Q.BitLen() <= 16 {
		q16 := new(big.Int).Set(par.Q)
		two16 := big.NewInt(1 << 16)
		k := new(big.Int).Div(two16, q16)
		qMult16 := new(big.Int).Mul(k, q16)
		buf := make([]byte, 512)
		i := 0
		for i < n {
			if _, err := io.ReadFull(xof, buf); err != nil {
				break
			}
			for j := 0; j+1 < len(buf) && i < n; j += 2 {
				v := uint64(binary.LittleEndian.Uint16(buf[j : j+2]))
				if new(big.Int).SetUint64(v).Cmp(qMult16) < 0 {
					m := new(big.Int).Mod(new(big.Int).SetUint64(v), par.Q)
					out.Coeffs[i].Set(m)
					i++
				}
			}
		}
		return out
	}
	two64 := new(big.Int).Lsh(big.NewInt(1), 64)
	q := new(big.Int).Set(par.Q)
	k := new(big.Int).Div(two64, q)
	thr := new(big.Int).Mul(k, q)
	buf := make([]byte, 8*32)
	i := 0
	for i < n {
		if _, err := io.ReadFull(xof, buf); err != nil {
			break
		}
		for j := 0; j+7 < len(buf) && i < n; j += 8 {
			u := binary.LittleEndian.Uint64(buf[j : j+8])
			U := new(big.Int).SetUint64(u)
			if U.Cmp(thr) < 0 {
				out.Coeffs[i].Mod(U, par.Q)
				i++
			}
		}
	}
	return out
}

// hashToTarget produces a ModQPoly by hashing (salt || msg) with SHAKE128 and mapping to [0,Q).
func hashToTarget(msg, salt []byte, par Params) ModQPoly {
	h := sha3.NewShake128()
	h.Write(salt)
	h.Write(msg)
	return hashToTargetXOF(h, par)
}

// PublicHashToTarget exposes hashToTarget for CLI/tests when built with testonly tag.
func PublicHashToTarget(msg, salt []byte, par Params) ModQPoly { return hashToTarget(msg, salt, par) }

// PublicHashToTargetFromXOF exposes hashToTargetXOF for tests.
func PublicHashToTargetFromXOF(xof io.Reader, par Params) ModQPoly { return hashToTargetXOF(xof, par) }

// NewSalt returns a freshly generated 32-byte salt.
func NewSaltWithLen(n int) ([]byte, error) {
	if n <= 0 {
		n = 32
	}
	salt := make([]byte, n)
	_, err := crand.Read(salt)
	return salt, err
}

// NewSalt returns a freshly generated salt of length S.Opts.SaltBytes if available, else 32.
func (S *Sampler) NewSalt() ([]byte, error) { return NewSaltWithLen(S.Opts.SaltBytes) }

// SignC generates a C-style signature using the two-step Eval sampler and exact residual bound.
func (S *Sampler) SignC(msg []byte) (CSig, error) {
	if S.Opts.ReduceIters <= 0 {
		S.Opts.ReduceIters = 64
	}
	if err := S.ReduceTrapdoor(S.Opts.ReduceIters); err != nil {
		return CSig{}, err
	}
	if err := S.BuildGram(); err != nil {
		return CSig{}, err
	}
	if S.Opts.RSquare <= 0 {
		S.Opts.RSquare = CReferenceRSquare()
	}
	if S.Opts.Alpha <= 0 {
		S.Opts.Alpha = 1.25
	}
	if S.Opts.Slack <= 0 {
		S.Opts.Slack = 1.042
	}
	if _, _, err := S.ComputeSigmasC(); err != nil {
		return CSig{}, err
	}
	h, err := PublicKeyH(Int64ToModQPoly(S.f, S.Par), Int64ToModQPoly(S.g, S.Par), S.Par)
	if err != nil {
		return CSig{}, err
	}
	salt := make([]byte, S.Opts.SaltBytes)
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}
	maxTries := S.Opts.MaxSignTrials
	if maxTries <= 0 {
		maxTries = 128
	}
	for tries := 0; tries < maxTries; tries++ {
		if _, err := crand.Read(salt); err != nil {
			return CSig{}, err
		}
		t := hashToTarget(msg, salt, S.Par)
		c0, c1 := S.CentersFromSyndrome(t)
		z0, z1, err := S.samplePairCExact(c0, c1)
		if err != nil {
			continue
		}
		n := S.Par.N
		z1Coeff := psFromInt64Coeff(z1, S.Prec)
		z0Coeff := psFromInt64Coeff(z0, S.Prec)
		z1Eval := FloatToEvalCFFT(z1Coeff, S.Prec)
		z0Eval := FloatToEvalCFFT(z0Coeff, S.Prec)
		assertSameFlavor("signC:update:z1", S.b20, z1Eval)
		// Rebuild v1 = f*z0 + F*z1 in Eval domain for rounding.
		v1Eval := ps.FieldAddBig(ps.FieldMulBig(S.b10, z0Eval), ps.FieldMulBig(S.b20, z1Eval))
		v1Eval.Domain = ps.Eval
		v1Coeff := FloatToCoeffCFFT(v1Eval, S.Prec)
		s1 := make([]int64, n)
		for i := 0; i < n; i++ {
			re1, _ := v1Coeff.Coeffs[i].Real.Float64()
			s1[i] = -RoundAwayFromZero(re1)
		}
		s1poly := Int64ToModQPoly(s1, S.Par)
		hs1, convErr := ConvolveRNS(s1poly, h, S.Par)
		if convErr != nil {
			continue
		}
		centered := recenterModQ(t, S.Par)
		c1Mod := Int64ToModQPoly(centered, S.Par)
		s2 := NewModQPoly(n, S.Par.Q)
		for i := 0; i < n; i++ {
			s2.Coeffs[i].Add(hs1.Coeffs[i], c1Mod.Coeffs[i])
			s2.Coeffs[i].Mod(s2.Coeffs[i], S.Par.Q)
		}
		s2c := recenterModQ(s2, S.Par)
		if debugOn {
			sumBF := normSumBig(s1, s2c, S.Par, S.Opts)
			gammaBF := gammaSqBig(S.Par, S.Opts)
			ok := sumBF.Cmp(gammaBF) <= 0
			dbg(os.Stderr, "sign attempt: sum=%s gamma^2=%s accept=%v\n", sumBF.Text('g', 6), gammaBF.Text('g', 6), ok)
		}
		if !CheckNormC(s1, s2c, S.Par, S.Opts) {
			continue
		}
		if debugOn {
			S.debugHS1Residual(s1, &t)
		}
		return CSig{S1: s1, Salt: append([]byte(nil), salt...)}, nil
	}
	return CSig{}, errors.New("signC: too many rejections")
}

// VerifyC verifies the C-style signature using h = g*f^{-1} (mod Q).
func (S *Sampler) VerifyC(msg []byte, sig CSig) (bool, error) {
	t := hashToTarget(msg, sig.Salt, S.Par)
	h, err := PublicKeyH(Int64ToModQPoly(S.f, S.Par), Int64ToModQPoly(S.g, S.Par), S.Par)
	if err != nil {
		return false, err
	}
	s1poly := Int64ToModQPoly(sig.S1, S.Par)
	hs1, err := ConvolveRNS(s1poly, h, S.Par)
	if err != nil {
		return false, err
	}
	centered := recenterModQ(t, S.Par)
	c1Mod := Int64ToModQPoly(centered, S.Par)
	s2 := NewModQPoly(S.Par.N, S.Par.Q)
	for i := 0; i < S.Par.N; i++ {
		s2.Coeffs[i].Add(hs1.Coeffs[i], c1Mod.Coeffs[i])
		s2.Coeffs[i].Mod(s2.Coeffs[i], S.Par.Q)
	}
	s2c := recenterModQ(s2, S.Par)
	return CheckNormC(sig.S1, s2c, S.Par, S.Opts), nil
}
