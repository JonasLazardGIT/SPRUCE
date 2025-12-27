package tests

import (
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func buildConstLane(ncols int, v int64) []int64 {
	out := make([]int64, ncols)
	for i := 0; i < ncols; i++ {
		out[i] = v
	}
	return out
}

func TestPRFShowingTheta2Replay(t *testing.T) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	ncols := testNCols(ringQ)
	params, err := prf.LoadDefaultParams()
	if err != nil {
		t.Fatalf("load prf params: %v", err)
	}
	if ncols <= 0 {
		t.Fatalf("invalid ncols %d", ncols)
	}

	// Build deterministic key/nonce.
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

	// Build PRF trace rows as column-constant polys (evaluation-domain constant).
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

	// Provide dummy base rows so the credential row builder can run.
	baseRow := makePolyConst(ringQ, 0)
	baseRows := []*ring.Poly{baseRow, baseRow, baseRow, baseRow, baseRow, baseRow, baseRow, baseRow, baseRow}
	startIdx := len(baseRows)
	rowsFull := append(append([]*ring.Poly{}, baseRows...), traceRows...)
	rowsFullNTT := make([]*ring.Poly, len(rowsFull))
	for i := range rowsFull {
		rowsFullNTT[i] = nttCopy(ringQ, rowsFull[i])
	}

	cs, err := PIOP.BuildPRFConstraintSet(ringQ, params, rowsFullNTT, startIdx, tagPublic, noncePublic, ncols)
	if err != nil {
		t.Fatalf("build prf constraint set: %v", err)
	}
	cs.PRFLayout = &PIOP.PRFLayout{
		StartIdx: startIdx,
		LenKey:   params.LenKey,
		LenNonce: params.LenNonce,
		RF:       params.RF,
		RP:       params.RP,
		LenTag:   params.LenTag,
	}

	pub := PIOP.PublicInputs{
		Tag:   tagPublic,
		Nonce: noncePublic,
	}
	wit := PIOP.WitnessInputs{
		M1:  []*ring.Poly{baseRow},
		M2:  []*ring.Poly{baseRow},
		RU0: []*ring.Poly{baseRow},
		RU1: []*ring.Poly{baseRow},
		R:   []*ring.Poly{baseRow},
		R0:  []*ring.Poly{baseRow},
		R1:  []*ring.Poly{baseRow},
		K0:  []*ring.Poly{baseRow},
		K1:  []*ring.Poly{baseRow},
		Extras: map[string]interface{}{
			"prf_trace": traceRows,
		},
	}
	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: ncols, Ell: 1}

	proof, err := PIOP.BuildWithConstraints(pub, wit, cs, opts, PIOP.FSModeCredential)
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	ok, err := PIOP.VerifyWithConstraints(proof, cs, pub, opts, PIOP.FSModeCredential)
	if err != nil || !ok {
		t.Fatalf("verify failed: ok=%v err=%v", ok, err)
	}
}
