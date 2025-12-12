package tests

import (
	"path/filepath"
	"testing"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// makePolyConst returns a coeff-domain poly with all entries set to v (centered).
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

// loadDefaultB loads Bmatrix.json and lifts to NTT.
func loadDefaultB(r *ring.Ring) ([]*ring.Poly, error) {
	paths := []string{"Parameters/Bmatrix.json", "../Parameters/Bmatrix.json", filepath.Join("..", "..", "Parameters", "Bmatrix.json")}
	var coeffs [][]uint64
	var err error
	for _, p := range paths {
		coeffs, err = ntrurio.LoadBMatrixCoeffs(p)
		if err == nil {
			break
		}
	}
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

func TestCredentialPreSignHappy(t *testing.T) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	bound := int64(8)

	// Witness polys.
	m1 := makePolyConst(ringQ, 1)
	m2 := makePolyConst(ringQ, 2)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	// Issuer randomness.
	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)

	// Center combine.
	r0 := ringQ.NewPoly()
	r1 := ringQ.NewPoly()
	q := int64(ringQ.Modulus[0])
	for i := 0; i < ringQ.N; i++ {
		c0 := credential.CenterBounded(int64(ru0.Coeffs[0][i])+int64(ri0.Coeffs[0][i]), bound)
		c1 := credential.CenterBounded(int64(ru1.Coeffs[0][i])+int64(ri1.Coeffs[0][i]), bound)
		if c0 < 0 {
			r0.Coeffs[0][i] = uint64(c0 + q)
		} else {
			r0.Coeffs[0][i] = uint64(c0)
		}
		if c1 < 0 {
			r1.Coeffs[0][i] = uint64(c1 + q)
		} else {
			r1.Coeffs[0][i] = uint64(c1)
		}
	}

	B, err := loadDefaultB(ringQ)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	tCoeff, err := credential.HashMessage(ringQ, B, m1, m2, r0, r1)
	if err != nil {
		t.Fatalf("hash message: %v", err)
	}

	// Build Ac as identity (5x5) in NTT.
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
	// Compute com = Ac·vec in NTT.
	vecNTT := make([]*ring.Poly, len(vec))
	for i := range vec {
		vecNTT[i] = ringQ.NewPoly()
		ring.Copy(vec[i], vecNTT[i])
		ringQ.NTT(vecNTT[i], vecNTT[i])
	}
	comNTT, err := commitment.Commit(ringQ, Ac, vecNTT)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	pub := PIOP.PublicInputs{
		Com:    comNTT,
		RI0:    []*ring.Poly{ri0},
		RI1:    []*ring.Poly{ri1},
		Ac:     Ac,
		B:      B,
		BoundB: bound,
	}
	wit := PIOP.WitnessInputs{
		M1:  []*ring.Poly{m1},
		M2:  []*ring.Poly{m2},
		RU0: []*ring.Poly{ru0},
		RU1: []*ring.Poly{ru1},
		R:   []*ring.Poly{rPoly},
		R0:  []*ring.Poly{r0},
		R1:  []*ring.Poly{r1},
		T:   tCoeff,
	}

	opts := PIOP.SimOpts{Credential: true}
	b := PIOP.NewCredentialBuilder(opts)
	proof, err := b.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	ok, err := b.Verify(pub, proof)
	if err != nil || !ok {
		t.Fatalf("verify failed: ok=%v err=%v", ok, err)
	}
}
