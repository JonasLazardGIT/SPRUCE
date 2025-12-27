package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/ntru/keys"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func main() {
	log.Printf("[showing-cli] starting showing demo")
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		log.Fatalf("load ring: %v", err)
	}
	statePath := filepath.Join("credential", "keys", "credential_state.json")
	state, err := credential.LoadState(statePath)
	if err != nil {
		log.Fatalf("load credential state: %v", err)
	}
	params, err := prf.LoadDefaultParams()
	if err != nil {
		log.Fatalf("load prf params: %v", err)
	}
	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: 8, Ell: 1}

	// Build public matrices.
	B, err := loadBFromState(ringQ, state)
	if err != nil {
		log.Fatalf("load B: %v", err)
	}
	wit, err := buildWitnessFromState(ringQ, state)
	if err != nil {
		log.Fatalf("build witness: %v", err)
	}
	A, err := buildSignatureMatrix(ringQ, state, len(wit.U))
	if err != nil {
		log.Fatalf("build A: %v", err)
	}

	// Witness rows from credential state.
	// PRF key from m2 coefficients.
	key, err := prfKeyFromM2(state.M2, params.LenKey, ringQ)
	if err != nil {
		log.Fatalf("prf key: %v", err)
	}
	nonce, noncePublic := sampleNonce(params.LenNonce, opts.NCols, ringQ.Modulus[0])
	tag, err := prf.Tag(key, nonce, params)
	if err != nil {
		log.Fatalf("prf tag: %v", err)
	}
	tagPublic := lanesFromElems(tag, opts.NCols)

	x0, err := prf.ConcatKeyNonce(key, nonce, params)
	if err != nil {
		log.Fatalf("concat key/nonce: %v", err)
	}
	trace, err := prf.Trace(x0, params)
	if err != nil {
		log.Fatalf("prf trace: %v", err)
	}
	traceRows := traceToPolys(ringQ, trace)
	if wit.Extras == nil {
		wit.Extras = map[string]interface{}{}
	}
	wit.Extras["prf_trace"] = traceRows

	pub := PIOP.PublicInputs{
		A:      A,
		B:      B,
		Tag:    tagPublic,
		Nonce:  noncePublic,
		BoundB: int64(8),
	}

	log.Printf("[showing-cli] building proof")
	proof, err := PIOP.BuildShowingCombined(pub, wit, opts)
	if err != nil {
		log.Fatalf("build showing: %v", err)
	}
	ok, err := PIOP.VerifyWithConstraints(proof, PIOP.ConstraintSet{PRFLayout: proof.PRFLayout}, pub, opts, PIOP.FSModeCredential)
	if err != nil || !ok {
		log.Fatalf("verify showing failed: ok=%v err=%v", ok, err)
	}
	log.Printf("[showing-cli] showing proof verified")
}

func loadBFromState(r *ring.Ring, st credential.State) ([]*ring.Poly, error) {
	if len(st.B) > 0 {
		out := make([]*ring.Poly, len(st.B))
		for i := range st.B {
			out[i] = polyFromInt64(r, st.B[i])
			r.NTT(out[i], out[i])
		}
		return out, nil
	}
	if st.BPath == "" {
		return nil, fmt.Errorf("missing B in state")
	}
	coeffs, err := ntrurio.LoadBMatrixCoeffs(st.BPath)
	if err != nil {
		return nil, err
	}
	out := make([]*ring.Poly, len(coeffs))
	for i := range coeffs {
		p := r.NewPoly()
		copy(p.Coeffs[0], coeffs[i])
		r.NTT(p, p)
		out[i] = p
	}
	return out, nil
}

func buildSignatureMatrix(r *ring.Ring, st credential.State, uCount int) ([][]*ring.Poly, error) {
	if len(st.NTRUPublic) == 0 {
		pk, err := keys.LoadPublic()
		if err != nil {
			return nil, fmt.Errorf("load public key: %w", err)
		}
		st.NTRUPublic = [][]int64{pk.HCoeffs}
	}
	if uCount <= 1 {
		one := r.NewPoly()
		one.Coeffs[0][0] = 1 % r.Modulus[0]
		r.NTT(one, one)
		return [][]*ring.Poly{{one}}, nil
	}
	h := polyFromInt64(r, st.NTRUPublic[0])
	r.NTT(h, h)
	one := r.NewPoly()
	one.Coeffs[0][0] = 1 % r.Modulus[0]
	r.NTT(one, one)
	return [][]*ring.Poly{{h, one}}, nil
}

func buildWitnessFromState(r *ring.Ring, st credential.State) (PIOP.WitnessInputs, error) {
	m1 := polysFromInt64(r, st.M1)
	m2 := polysFromInt64(r, st.M2)
	r0 := polysFromInt64(r, st.R0)
	r1 := polysFromInt64(r, st.R1)
	k0 := polysFromInt64(r, st.K0)
	k1 := polysFromInt64(r, st.K1)
	base := r.NewPoly()

	t := st.T
	if len(t) == 0 {
		return PIOP.WitnessInputs{}, fmt.Errorf("missing T in state")
	}
	u0 := st.U
	var u1 []int64
	if sig, err := keys.Load(); err == nil {
		if len(u0) == 0 && len(sig.Signature.S0) > 0 {
			u0 = sig.Signature.S0
		}
		if len(sig.Signature.S1) > 0 {
			u1 = sig.Signature.S1
		}
	}
	if len(u0) == 0 {
		return PIOP.WitnessInputs{}, fmt.Errorf("missing U (signature preimage)")
	}
	var uRows []*ring.Poly
	if len(u1) > 0 {
		uRows = []*ring.Poly{polyFromInt64(r, u1), polyFromInt64(r, u0)}
	} else {
		uRows = []*ring.Poly{polyFromInt64(r, u0)}
	}

	// Ensure required base rows exist (zero-fill if state omitted them).
	if len(m1) == 0 {
		m1 = []*ring.Poly{base}
	}
	if len(m2) == 0 {
		m2 = []*ring.Poly{base}
	}
	if len(r0) == 0 {
		r0 = []*ring.Poly{base}
	}
	if len(r1) == 0 {
		r1 = []*ring.Poly{base}
	}
	if len(k0) == 0 {
		k0 = []*ring.Poly{base}
	}
	if len(k1) == 0 {
		k1 = []*ring.Poly{base}
	}

	return PIOP.WitnessInputs{
		M1:  m1,
		M2:  m2,
		RU0: []*ring.Poly{base},
		RU1: []*ring.Poly{base},
		R:   []*ring.Poly{base},
		R0:  r0,
		R1:  r1,
		K0:  k0,
		K1:  k1,
		T:   t,
		U:   uRows,
	}, nil
}

func prfKeyFromM2(m2 [][]int64, want int, ringQ *ring.Ring) ([]prf.Elem, error) {
	if len(m2) == 0 {
		return nil, fmt.Errorf("missing m2")
	}
	coeffs := m2[0]
	if len(coeffs) < want {
		return nil, fmt.Errorf("m2 len=%d < lenkey=%d", len(coeffs), want)
	}
	q := int64(ringQ.Modulus[0])
	key := make([]prf.Elem, want)
	for i := 0; i < want; i++ {
		v := coeffs[i] % q
		if v < 0 {
			v += q
		}
		key[i] = prf.Elem(uint64(v))
	}
	return key, nil
}

func sampleNonce(lennonce, ncols int, q uint64) ([]prf.Elem, [][]int64) {
	nonce := make([]prf.Elem, lennonce)
	public := make([][]int64, lennonce)
	for i := 0; i < lennonce; i++ {
		v := randElem(q)
		nonce[i] = prf.Elem(v)
		public[i] = buildConstLane(ncols, int64(v))
	}
	return nonce, public
}

func randElem(q uint64) uint64 {
	n, err := rand.Int(rand.Reader, new(big.Int).SetUint64(q))
	if err != nil {
		panic(err)
	}
	return n.Uint64()
}

func lanesFromElems(vals []prf.Elem, ncols int) [][]int64 {
	out := make([][]int64, len(vals))
	for i, v := range vals {
		out[i] = buildConstLane(ncols, int64(v))
	}
	return out
}

func traceToPolys(r *ring.Ring, trace [][]prf.Elem) []*ring.Poly {
	rows := make([]*ring.Poly, 0, len(trace))
	for _, st := range trace {
		for _, v := range st {
			rows = append(rows, polyConst(r, int64(v)))
		}
	}
	return rows
}

func polyConst(r *ring.Ring, v int64) *ring.Poly {
	pNTT := r.NewPoly()
	q := int64(r.Modulus[0])
	var coeff uint64
	if v >= 0 {
		coeff = uint64(v % q)
	} else {
		coeff = uint64((v+q)%q) % uint64(q)
	}
	for i := 0; i < r.N; i++ {
		pNTT.Coeffs[0][i] = coeff
	}
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

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

func polysFromInt64(r *ring.Ring, vec [][]int64) []*ring.Poly {
	out := make([]*ring.Poly, len(vec))
	for i := range vec {
		out[i] = polyFromInt64(r, vec[i])
	}
	return out
}

func buildConstLane(ncols int, v int64) []int64 {
	row := make([]int64, ncols)
	for i := range row {
		row[i] = v
	}
	return row
}

func init() {
	// Ensure we run from repo root for relative paths.
	if wd, err := os.Getwd(); err == nil {
		log.Printf("[showing-cli] cwd=%s", wd)
	}
}
