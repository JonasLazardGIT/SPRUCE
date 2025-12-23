package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/issuance"
	"vSIS-Signature/ntru"
	"vSIS-Signature/ntru/keys"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func main() {
	log.Println("[issuance-cli] starting issuance demo")

	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		log.Fatalf("load ring: %v", err)
	}
	bound := int64(8)

	// Sample a fresh random Ac of correct dimensions (lenM1.. = 1 each for demo) and save it.
	lenM1, lenM2, lenRU0, lenRU1, lenR := 1, 1, 1, 1, 1
	cols := lenM1 + lenM2 + lenRU0 + lenRU1 + lenR
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	sampleMatrix := func() [][]*ring.Poly {
		mat := make([][]*ring.Poly, cols)
		for i := 0; i < cols; i++ {
			mat[i] = make([]*ring.Poly, cols)
			for j := 0; j < cols; j++ {
				p := ringQ.NewPoly()
				for k := 0; k < ringQ.N; k++ {
					p.Coeffs[0][k] = uint64(rng.Int63()) % ringQ.Modulus[0]
				}
				ringQ.NTT(p, p)
				mat[i][j] = p
			}
		}
		return mat
	}
	Ac := sampleMatrix()
	if err := saveAcJSON("credential/Ac.json", Ac); err != nil {
		log.Printf("[issuance-cli] warning: could not save Ac.json: %v", err)
	}
	// Save params file pointing to B/Ac.
	if err := saveParamsJSON("credential/params.json", "credential/Ac.json", "Parameters/Bmatrix.json", bound, lenM1, lenM2, lenRU0, lenRU1, lenR); err != nil {
		log.Printf("[issuance-cli] warning: could not save params.json: %v", err)
	}
	params := &credential.Params{
		Ac:     Ac,
		BPath:  "Parameters/Bmatrix.json",
		AcPath: "credential/Ac.json",
		BoundB: bound,
		RingQ:  ringQ,
		LenM1:  lenM1,
		LenM2:  lenM2,
		LenRU0: lenRU0,
		LenRU1: lenRU1,
		LenR:   lenR,
	}

	// Holder secrets (coeff domain) within bounds, sampled fresh.
	m1 := samplePackedHalf(ringQ, params.BoundB, rng, true)
	m2 := samplePackedHalf(ringQ, params.BoundB, rng, false)
	ru0 := sampleBounded(ringQ, params.BoundB, rng)
	ru1 := sampleBounded(ringQ, params.BoundB, rng)
	rPoly := sampleBounded(ringQ, params.BoundB, rng)

	// Issuer challenge.
	// Deterministic issuer challenge: RI*=1 (coeff).
	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)
	ch := issuance.Challenge{RI0: []*ring.Poly{ri0}, RI1: []*ring.Poly{ri1}}

	// Prepare commit.
	inputs := issuance.Inputs{
		M1:  []*ring.Poly{m1},
		M2:  []*ring.Poly{m2},
		RU0: []*ring.Poly{ru0},
		RU1: []*ring.Poly{ru1},
		R:   []*ring.Poly{rPoly},
	}
	com, err := issuance.PrepareCommit(params, inputs)
	if err != nil {
		log.Fatalf("prepare commit: %v", err)
	}
	log.Printf("[issuance-cli] Com rows=%d", len(com))

	// Apply challenge → R0/R1/K*/T.
	state, err := issuance.ApplyChallenge(params, inputs, ch)
	if err != nil {
		log.Fatalf("apply challenge: %v", err)
	}
	log.Printf("[issuance-cli] T[0]=%d", state.T[0])

	// Build and verify pre-sign proof.
	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: 8, Ell: 1}
	proof, err := issuance.ProvePreSign(params, ch, com, inputs, state, opts)
	if err != nil {
		log.Fatalf("prove pre-sign: %v", err)
	}
	ok, err := issuance.VerifyPreSign(params, ch, com, state, proof, opts)
	if err != nil || !ok {
		log.Fatalf("verify pre-sign failed: ok=%v err=%v", ok, err)
	}
	log.Printf("[issuance-cli] pre-sign proof verified; Fpar=%d", len(proof.FparNTT))

	// Sign T using stored trapdoor keys; save signature.
	sig, err := issuance.SignTargetAndSave(state.T, 2048, ntru.SamplerOpts{})
	if err != nil {
		log.Fatalf("sign target: %v", err)
	}
	log.Printf("[issuance-cli] signature trials_used=%d rejected=%v", sig.Signature.TrialsUsed, sig.Signature.Rejected)

	// Copy signature into credential/keys for convenience.
	if err := copySignature("ntru_keys/signature.json", "credential/keys/signature.json"); err != nil {
		log.Printf("[issuance-cli] warning: copy signature to credential/keys failed: %v", err)
	} else {
		log.Printf("[issuance-cli] signature copied to credential/keys/signature.json")
	}

	// Persist full credential state (coeffs only, no seeds).
	if err := saveCredentialState(params, inputs, state, ch, sig, "credential/keys/credential_state.json"); err != nil {
		log.Printf("[issuance-cli] warning: save credential state failed: %v", err)
	} else {
		log.Printf("[issuance-cli] credential state saved to credential/keys/credential_state.json")
	}
	// Copy NTRU keys for convenience.
	_ = copyFile("ntru_keys/public.json", "credential/ntru_keys/public.json")
	_ = copyFile("ntru_keys/private.json", "credential/ntru_keys/private.json")

	fmt.Println("[issuance-cli] done")
}

// makePolyConst returns a coeff-domain poly with all entries set to v.
func makePolyConst(r *ring.Ring, v int64) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	var coeff uint64
	if v >= 0 {
		coeff = uint64(v % q)
	} else {
		coeff = uint64((v+q)%q) % uint64(q)
	}
	for i := 0; i < r.N; i++ {
		p.Coeffs[0][i] = coeff
	}
	return p
}

// makePackedHalfConst zeros the forbidden half to respect packing, fills allowed half with v.
func makePackedHalfConst(r *ring.Ring, v int64, keepLower bool) *ring.Poly {
	p := makePolyConst(r, v)
	half := r.N / 2
	if keepLower {
		for i := half; i < r.N; i++ {
			p.Coeffs[0][i] = 0
		}
	} else {
		for i := 0; i < half; i++ {
			p.Coeffs[0][i] = 0
		}
	}
	return p
}

// copySignature copies a JSON signature file from src to dst.
func copySignature(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// copyFile copies src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

// saveCredentialState serializes holder secrets, public challenge, and signature to JSON.
func saveCredentialState(p *credential.Params, in issuance.Inputs, st *issuance.State, ch issuance.Challenge, sig *keys.Signature, path string) error {
	if p == nil || st == nil {
		return fmt.Errorf("nil params/state")
	}
	r := p.RingQ
	toCoeff := func(poly *ring.Poly) *ring.Poly {
		cp := r.NewPoly()
		ring.Copy(poly, cp)
		return cp
	}
	nttToCoeff := func(poly *ring.Poly) *ring.Poly {
		cp := r.NewPoly()
		ring.Copy(poly, cp)
		r.InvNTT(cp, cp)
		return cp
	}
	polyVec := func(vec []*ring.Poly, ntt bool) [][]int64 {
		out := make([][]int64, len(vec))
		for i, p := range vec {
			if ntt {
				p = nttToCoeff(p)
			} else {
				p = toCoeff(p)
			}
			out[i] = polyToInt64Local(p, r)
		}
		return out
	}
	state := credential.State{
		M1:     polyVec(in.M1, false),
		M2:     polyVec(in.M2, false),
		RU0:    polyVec(in.RU0, false),
		RU1:    polyVec(in.RU1, false),
		R:      polyVec(in.R, false),
		R0:     polyVec(st.R0, false),
		R1:     polyVec(st.R1, false),
		K0:     polyVec(st.K0, false),
		K1:     polyVec(st.K1, false),
		T:      st.T,
		Com:    polyVec(st.Com, true),
		RI0:    polyVec(ch.RI0, true),
		RI1:    polyVec(ch.RI1, true),
		BPath:  p.BPath,
		AcPath: p.AcPath,
	}
	// If signature is present, store s0 (preimage) as U.
	if sig != nil && len(sig.Signature.S0) > 0 {
		state.U = sig.Signature.S0
	}
	// Embed NTRU keys if available.
	if pub, err := loadKeyCoeffs("ntru_keys/public.json"); err == nil {
		state.NTRUPublic = pub
	}
	if priv, err := loadKeyCoeffs("ntru_keys/private.json"); err == nil {
		state.NTRUPrivate = priv
	}
	// Persist JSON.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return credential.SaveState(path, r, state)
}

// polyToInt64Local converts poly coeffs to centered int64.
func polyToInt64Local(p *ring.Poly, ringQ *ring.Ring) []int64 {
	out := make([]int64, ringQ.N)
	q := int64(ringQ.Modulus[0])
	half := q / 2
	for i, c := range p.Coeffs[0] {
		v := int64(c)
		if v > half {
			v -= q
		}
		out[i] = v
	}
	return out
}

// saveParamsJSON writes params.json pointing to Ac/B and lengths.
func saveParamsJSON(path, acPath, bPath string, bound int64, lenM1, lenM2, lenRU0, lenRU1, lenR int) error {
	type paramsFile struct {
		AcPath string `json:"AcPath"`
		BPath  string `json:"BPath"`
		BoundB int64  `json:"BoundB"`
		LenM1  int    `json:"LenM1"`
		LenM2  int    `json:"LenM2"`
		LenRU0 int    `json:"LenRU0"`
		LenRU1 int    `json:"LenRU1"`
		LenR   int    `json:"LenR"`
	}
	pf := paramsFile{
		AcPath: acPath,
		BPath:  bPath,
		BoundB: bound,
		LenM1:  lenM1,
		LenM2:  lenM2,
		LenRU0: lenRU0,
		LenRU1: lenRU1,
		LenR:   lenR,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(pf, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// saveAcJSON writes Ac (NTT) into coeff-domain JSON for reuse.
func saveAcJSON(path string, Ac [][]*ring.Poly) error {
	if len(Ac) == 0 {
		return fmt.Errorf("empty Ac")
	}
	rows := len(Ac)
	cols := len(Ac[0])
	acOut := make([][][]uint64, rows)
	for i := 0; i < rows; i++ {
		acOut[i] = make([][]uint64, cols)
		for j := 0; j < cols; j++ {
			p := Ac[i][j]
			cp := p.CopyNew()
			// Inverse NTT to coeff
			// We need ring; assume modulus same; use default ring from lengths.
			// Here we assume cp already coeff (since sampled in NTT); so just copy coeffs.
			acOut[i][j] = make([]uint64, len(cp.Coeffs[0]))
			copy(acOut[i][j], cp.Coeffs[0])
		}
	}
	type acJSON struct {
		Ac [][][]uint64 `json:"Ac"`
	}
	payload := acJSON{Ac: acOut}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// sampleBounded samples coefficients in [-bound, bound] uniformly.
func sampleBounded(r *ring.Ring, bound int64, rng *rand.Rand) *ring.Poly {
	p := r.NewPoly()
	q := int64(r.Modulus[0])
	mod := 2*bound + 1
	for i := 0; i < r.N; i++ {
		v := rng.Int63n(mod) - bound
		if v < 0 {
			p.Coeffs[0][i] = uint64(v + q)
		} else {
			p.Coeffs[0][i] = uint64(v)
		}
	}
	return p
}

// samplePackedHalf zeros the disallowed half (lower or upper) and samples the allowed half in [-bound,bound].
func samplePackedHalf(r *ring.Ring, bound int64, rng *rand.Rand, keepLower bool) *ring.Poly {
	p := sampleBounded(r, bound, rng)
	half := r.N / 2
	if keepLower {
		for i := half; i < r.N; i++ {
			p.Coeffs[0][i] = 0
		}
	} else {
		for i := 0; i < half; i++ {
			p.Coeffs[0][i] = 0
		}
	}
	return p
}

// loadKeyCoeffs is a no-op stub: NTRU key embedding skipped in this demo.
func loadKeyCoeffs(path string) ([][]int64, error) { return nil, fmt.Errorf("not implemented") }
