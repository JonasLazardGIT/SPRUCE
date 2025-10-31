package PIOP

import (
	"math/rand"
	"testing"

	ntru "vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func TestNewRangeMembershipSpecRoots(t *testing.T) {
	const B = 4
	const q = uint64(1038337)

	spec := NewRangeMembershipSpec(q, B)
	expectedDegree := 2*B + 1
	if len(spec.Coeffs) != expectedDegree+1 {
		t.Fatalf("degree mismatch: got %d coefficients, want %d", len(spec.Coeffs), expectedDegree+1)
	}
	for i := -B; i <= B; i++ {
		root := liftIntToField(q, int64(i))
		if got := EvalPoly(spec.Coeffs, root, q); got != 0 {
			t.Fatalf("P_B(⟨%d⟩_q)=%d, want 0", i, got)
		}
	}
	for _, outside := range []int{B + 1, -(B + 1), 2 * B} {
		root := liftIntToField(q, int64(outside))
		if EvalPoly(spec.Coeffs, root, q) == 0 {
			t.Fatalf("expected P_B(⟨%d⟩_q) ≠ 0", outside)
		}
	}

	specBig := NewRangeMembershipSpec(q, 128)
	if EvalPoly(specBig.Coeffs, liftIntToField(q, 129), q) == 0 {
		t.Fatalf("P_128(129) ≡ 0 mod q – expected non-zero")
	}
}

func TestBuildFparRangeMembershipZero(t *testing.T) {
	par, err := ntrurio.LoadParams(resolve("Parameters/Parameters.json"), true)
	if err != nil {
		t.Skip("missing parameters: " + err.Error())
		return
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		t.Fatalf("ring.NewRing: %v", err)
	}
	q := ringQ.Modulus[0]
	ncols := 6

	bounds := ntru.CurrentSeedPolyBounds()
	maxAbs := bounds.Max
	if maxAbs < 0 {
		maxAbs = -maxAbs
	}
	if neg := -bounds.Min; neg > maxAbs {
		maxAbs = neg
	}
	if maxAbs < 0 {
		t.Fatalf("invalid seed bounds: %+v", bounds)
	}
	spec := NewRangeMembershipSpec(q, int(maxAbs))

	vals := make([]uint64, ncols)
	samples := []int64{0, -1, maxAbs, -maxAbs, 3, -4}
	for i := 0; i < ncols; i++ {
		v := samples[i%len(samples)]
		vals[i] = liftIntToField(q, v)
	}
	row := ringQ.NewPoly()
	copy(row.Coeffs[0], vals)
	ringQ.NTT(row, row)

	Fpar := buildFparRangeMembership(ringQ, []*ring.Poly{row}, spec)
	if len(Fpar) != 1 {
		t.Fatalf("expected 1 membership row, got %d", len(Fpar))
	}
	tmp := ringQ.NewPoly()
	ringQ.InvNTT(Fpar[0], tmp)
	for idx, coeff := range tmp.Coeffs[0] {
		if coeff%q != 0 {
			t.Fatalf("membership coefficient %d non-zero: got %d", idx, coeff%q)
		}
	}
}

func TestComposePolyNTTConsistency(t *testing.T) {
	const q = linfChainTestQ
	ringQ, err := ring.NewRing(128, []uint64{q})
	if err != nil {
		t.Fatalf("ring.NewRing: %v", err)
	}
	omega := []uint64{1, 2, 3, 4}
	ell := 1
	if err := checkOmega(omega, q); err != nil {
		t.Fatalf("invalid omega: %v", err)
	}
	vals := []uint64{3, 5, 7, 9}
	digit := buildValueRow(ringQ, vals, omega, ell)
	spec := buildMembershipPolyRange(q, 0, 5)
	mem := composePolyNTT(ringQ, digit, spec)

	memCoeff := ringQ.NewPoly()
	ringQ.InvNTT(mem, memCoeff)
	digitCoeff := ringQ.NewPoly()
	ringQ.InvNTT(digit, digitCoeff)

	evalPoint := uint64(5)
	got := EvalPoly(memCoeff.Coeffs[0], evalPoint%q, q)
	want := EvalPoly(spec, EvalPoly(digitCoeff.Coeffs[0], evalPoint%q, q), q)
	if got != want {
		manual := []uint64{0}
		base := append([]uint64(nil), digitCoeff.Coeffs[0]...)
		degBase := len(base) - 1
		for degBase >= 0 && base[degBase]%q == 0 {
			degBase--
		}
		trimmed := base[:degBase+1]
		for idx := len(spec) - 1; idx >= 0; idx-- {
			manual = polyMul(manual, trimmed, q)
			if len(manual) == 0 {
				manual = []uint64{spec[idx] % q}
			} else {
				manual[0] = modAdd(manual[0], spec[idx]%q, q)
			}
		}
		manualVal := EvalPoly(manual, evalPoint%q, q)
		for idx := range manual {
			if manual[idx]%q != memCoeff.Coeffs[0][idx]%q {
				t.Fatalf("coefficient mismatch at idx=%d: manual=%d compose=%d", idx, manual[idx]%q, memCoeff.Coeffs[0][idx]%q)
			}
		}
		t.Fatalf("composition mismatch at e=%d: got %d want %d manual=%d", evalPoint, got, want, manualVal)
	}

	// Tamper one value on Omega, recompute the digit polynomial but keep the old membership row.
	mutVals := append([]uint64(nil), vals...)
	mutVals[0] = modAdd(mutVals[0], 1, q)
	mutDigit := buildValueRow(ringQ, mutVals, omega, ell)
	mutDigitCoeff := ringQ.NewPoly()
	ringQ.InvNTT(mutDigit, mutDigitCoeff)

	mismatch := false
	rnd := rand.New(rand.NewSource(99))
	for trials := 0; trials < 32; trials++ {
		e := uint64(rnd.Int63()) % q
		skip := false
		for _, w := range omega {
			if e%q == w%q {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		lhs := EvalPoly(memCoeff.Coeffs[0], e%q, q)
		rhs := EvalPoly(spec, EvalPoly(mutDigitCoeff.Coeffs[0], e%q, q), q)
		if lhs != rhs {
			mismatch = true
			break
		}
	}
	if !mismatch {
		t.Fatalf("tampered digit escaped random audit against fixed membership row")
	}
}

func TestEq4RejectsMessageRangeTamper(t *testing.T) {
	ctx, okLin, okEq4, okSum := buildSimWith(t, defaultSimOpts())
	if !(okLin && okEq4 && okSum) {
		t.Fatalf("baseline simulation rejected: OkLin=%v OkEq4=%v OkSum=%v", okLin, okEq4, okSum)
	}
	spec := ctx.rangeSpec
	msgCount := ctx.proof.RowLayout.MsgCount
	if msgCount == 0 {
		t.Skip("no message rows in layout")
	}
	uStart := ctx.proof.RowLayout.SigCount
	uEnd := uStart + msgCount
	base := ctx.proof.RowLayout.MsgRangeBase
	if base < 0 {
		t.Fatalf("missing message range membership base in layout")
	}
	source := ctx.msgSource
	if len(source) == 0 {
		source = ctx.w1[uStart:uEnd]
	}
	tamperSource := clonePolySlice(source)
	if len(tamperSource) == 0 {
		t.Fatalf("no message polynomials to tamper")
	}
	coeff := ctx.ringQ.NewPoly()
	ctx.ringQ.InvNTT(tamperSource[0], coeff)
	coeff.Coeffs[0][0] = liftIntToField(ctx.q, int64(spec.B+1))
	ctx.ringQ.NTT(coeff, coeff)
	tamperSource[0] = coeff
	tamperedBlock := buildFparRangeMembership(ctx.ringQ, tamperSource, spec)
	tamperedFpar := append([]*ring.Poly(nil), ctx.Fpar...)
	copy(tamperedFpar[base:base+len(tamperedBlock)], tamperedBlock)
	if checkEq4OnOpening(ctx.ringQ, ctx.Q, ctx.M, ctx.maskOpen, tamperedFpar, ctx.Fagg, ctx.GammaPrimePoly, ctx.GammaPrimeScalars, ctx.omega, ctx.Eprime) {
		t.Fatalf("Eq.(4) verifier accepted tampered message membership block")
	}
}

func liftIntToField(q uint64, v int64) uint64 {
	if v >= 0 {
		return uint64(v) % q
	}
	neg := uint64(-v) % q
	return (q - neg) % q
}
