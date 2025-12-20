package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	"vSIS-Signature/issuance"
	"vSIS-Signature/ntru"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func main() {
	log.Println("[issuance-cli] starting issuance demo")

	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		log.Fatalf("load ring: %v", err)
	}
	bound := int64(8)

	// Deterministic holder secrets (coeff domain) to avoid residual drift.
	m1 := makePackedHalfConst(ringQ, 1, true)
	m2 := makePackedHalfConst(ringQ, 2, false)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	// Build Ac as identity 5x5 (NTT).
	vec := []*ring.Poly{m1, m2, ru0, ru1, rPoly}
	Ac := make(commitment.Matrix, len(vec))
	for i := range Ac {
		Ac[i] = make([]*ring.Poly, len(vec))
		for j := range Ac[i] {
			Ac[i][j] = ringQ.NewPoly()
			if i == j {
				Ac[i][j].Coeffs[0][0] = 1
			}
			ringQ.NTT(Ac[i][j], Ac[i][j])
		}
	}
	params := &credential.Params{
		Ac:     Ac,
		BPath:  "Parameters/Bmatrix.json",
		BoundB: bound,
		RingQ:  ringQ,
		LenM1:  1,
		LenM2:  1,
		LenRU0: 1,
		LenRU1: 1,
		LenR:   1,
	}

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
