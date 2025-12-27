package tests

import (
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func buildShowingFixture(t *testing.T) (*ring.Ring, PIOP.PublicInputs, PIOP.WitnessInputs, PIOP.SimOpts) {
	t.Helper()
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	ncols := testNCols(ringQ)
	bound := int64(8)

	B, err := loadDefaultB(ringQ)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}

	m1 := makePackedHalf(ringQ, ncols, 1, true)
	m2 := makePackedHalf(ringQ, ncols, 2, false)
	r0 := makePolyConst(ringQ, 3)
	r1 := makePolyConst(ringQ, 4)

	tCoeff, err := credential.HashMessage(ringQ, B, m1, m2, r0, r1)
	if err != nil {
		t.Fatalf("hash message: %v", err)
	}
	tPoly := polyFromInt64(ringQ, tCoeff)
	uPoly := tPoly.CopyNew()

	aCoeff := makePolyConst(ringQ, 1)
	aNTT := nttCopy(ringQ, aCoeff)
	A := [][]*ring.Poly{{aNTT}}

	params, err := prf.LoadDefaultParams()
	if err != nil {
		t.Fatalf("load prf params: %v", err)
	}
	key := make([]prf.Elem, params.LenKey)
	nonce := make([]prf.Elem, params.LenNonce)
	q := ringQ.Modulus[0]
	for i := range key {
		key[i] = prf.Elem(uint64(i+1) % q)
	}
	for i := range nonce {
		nonce[i] = prf.Elem(uint64(i+11) % q)
	}
	x0, err := prf.ConcatKeyNonce(key, nonce, params)
	if err != nil {
		t.Fatalf("concat key/nonce: %v", err)
	}
	trace, err := prf.Trace(x0, params)
	if err != nil {
		t.Fatalf("trace: %v", err)
	}
	traceRows := make([]*ring.Poly, 0, len(trace)*params.T())
	for _, st := range trace {
		for _, v := range st {
			traceRows = append(traceRows, makePolyConst(ringQ, int64(v)))
		}
	}
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	tagPublic := make([][]int64, params.LenTag)
	for j := 0; j < params.LenTag; j++ {
		tagPublic[j] = buildConstLane(ncols, int64(tag[j]))
	}
	noncePublic := make([][]int64, params.LenNonce)
	for j := 0; j < params.LenNonce; j++ {
		noncePublic[j] = buildConstLane(ncols, int64(nonce[j]))
	}

	base := makePolyConst(ringQ, 0)
	wit := PIOP.WitnessInputs{
		M1:  []*ring.Poly{m1},
		M2:  []*ring.Poly{m2},
		RU0: []*ring.Poly{base},
		RU1: []*ring.Poly{base},
		R:   []*ring.Poly{base},
		R0:  []*ring.Poly{r0},
		R1:  []*ring.Poly{r1},
		K0:  []*ring.Poly{base},
		K1:  []*ring.Poly{base},
		T:   tCoeff,
		U:   []*ring.Poly{uPoly},
		Extras: map[string]interface{}{
			"prf_trace": traceRows,
		},
	}
	pub := PIOP.PublicInputs{
		A:      A,
		B:      B,
		Tag:    tagPublic,
		Nonce:  noncePublic,
		BoundB: bound,
	}
	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: ncols, Ell: 1}
	return ringQ, pub, wit, opts
}

func TestCredentialShowingTamperCases(t *testing.T) {
	ringQ, pub, wit, opts := buildShowingFixture(t)

	// Baseline sanity.
	proof, err := PIOP.BuildShowingCombined(pub, wit, opts)
	if err != nil {
		t.Fatalf("build baseline: %v", err)
	}
	if ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub, opts, PIOP.FSModeCredential); err != nil || !ok {
		t.Fatalf("baseline verify failed: ok=%v err=%v", ok, err)
	}

	t.Run("tamper-tag", func(t *testing.T) {
		pub2 := pub
		pub2.Tag = make([][]int64, len(pub.Tag))
		for i := range pub.Tag {
			pub2.Tag[i] = append([]int64(nil), pub.Tag[i]...)
		}
		pub2.Tag[0][0] += 1
		proof, err := PIOP.BuildShowingCombined(pub2, wit, opts)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub2, opts, PIOP.FSModeCredential); err == nil && ok {
			t.Fatalf("expected tag tamper to fail")
		}
	})

	t.Run("tamper-nonce", func(t *testing.T) {
		pub2 := pub
		pub2.Nonce = make([][]int64, len(pub.Nonce))
		for i := range pub.Nonce {
			pub2.Nonce[i] = append([]int64(nil), pub.Nonce[i]...)
		}
		pub2.Nonce[0][0] += 1
		proof, err := PIOP.BuildShowingCombined(pub2, wit, opts)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub2, opts, PIOP.FSModeCredential); err == nil && ok {
			t.Fatalf("expected nonce tamper to fail")
		}
	})

	t.Run("tamper-U", func(t *testing.T) {
		w2 := wit
		w2.U = []*ring.Poly{tamperEvalDomain(ringQ, wit.U[0], 0, 1)}
		proof, err := PIOP.BuildShowingCombined(pub, w2, opts)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub, opts, PIOP.FSModeCredential); err == nil && ok {
			t.Fatalf("expected U tamper to fail")
		}
	})

	t.Run("tamper-R0", func(t *testing.T) {
		w2 := wit
		w2.R0 = []*ring.Poly{tamperEvalDomain(ringQ, wit.R0[0], 0, 1)}
		proof, err := PIOP.BuildShowingCombined(pub, w2, opts)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub, opts, PIOP.FSModeCredential); err == nil && ok {
			t.Fatalf("expected R0 tamper to fail")
		}
	})

	t.Run("tamper-R1", func(t *testing.T) {
		w2 := wit
		w2.R1 = []*ring.Poly{tamperEvalDomain(ringQ, wit.R1[0], 0, 1)}
		proof, err := PIOP.BuildShowingCombined(pub, w2, opts)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub, opts, PIOP.FSModeCredential); err == nil && ok {
			t.Fatalf("expected R1 tamper to fail")
		}
	})

	t.Run("tamper-M2", func(t *testing.T) {
		w2 := wit
		w2.M2 = []*ring.Poly{tamperEvalDomain(ringQ, wit.M2[0], 0, 1)}
		proof, err := PIOP.BuildShowingCombined(pub, w2, opts)
		if err != nil {
			t.Fatalf("build: %v", err)
		}
		if ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub, opts, PIOP.FSModeCredential); err == nil && ok {
			t.Fatalf("expected M2 tamper to fail")
		}
	})
}
