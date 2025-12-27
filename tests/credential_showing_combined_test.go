package tests

import (
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func polyFromInt64(r *ring.Ring, coeffs []int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	for i := 0; i < r.N && i < len(coeffs); i++ {
		v := coeffs[i] % q
		if v < 0 {
			v += q
		}
		p.Coeffs[0][i] = uint64(v)
	}
	return p
}

func TestCredentialShowingCombinedTheta2(t *testing.T) {
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

	// Witness polys (packed halves).
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

	// Signature matrix A: 1x1 identity (NTT).
	aCoeff := makePolyConst(ringQ, 1)
	aNTT := nttCopy(ringQ, aCoeff)
	A := [][]*ring.Poly{{aNTT}}

	// PRF trace.
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

	proof, err := PIOP.BuildShowingCombined(pub, wit, opts)
	if err != nil {
		t.Fatalf("build combined showing: %v", err)
	}
	ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub, opts, PIOP.FSModeCredential)
	if err != nil || !ok {
		t.Fatalf("verify combined showing failed: ok=%v err=%v", ok, err)
	}
}
