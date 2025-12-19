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

// makePacked halves: if keepLower, zero the upper half; else zero lower half.
func makePackedHalf(r *ring.Ring, v int64, keepLower bool) *ring.Poly {
	p := makePolyConst(r, v)
	half := r.N / 2
	q := int64(r.Modulus[0])
	zero := uint64(0)
	if r.N%2 != 0 {
		panic("ring dimension must be even for packing test")
	}
	if keepLower {
		for i := half; i < r.N; i++ {
			p.Coeffs[0][i] = zero
		}
	} else {
		for i := 0; i < half; i++ {
			p.Coeffs[0][i] = zero
		}
	}
	// Ensure centered representation still OK (no further adjustment needed since we set exact field elements).
	_ = q
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

	// Witness polys (packed halves).
	m1 := makePackedHalf(ringQ, 1, true)
	m2 := makePackedHalf(ringQ, 2, false)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	// Issuer randomness.
	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)

	// Center combine.
	r0 := ringQ.NewPoly()
	r1 := ringQ.NewPoly()
	k0 := ringQ.NewPoly()
	k1 := ringQ.NewPoly()
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
		// Stage A: carry rows exist but are not yet enforced; keep them at 0.
		k0.Coeffs[0][i] = 0
		k1.Coeffs[0][i] = 0
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
		T:      tCoeff,
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
		K0:  []*ring.Poly{k0},
		K1:  []*ring.Poly{k1},
	}

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: 8, Ell: 1}
	b := PIOP.NewCredentialBuilder(opts)
	proof, err := b.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	// Expect 5 commit residuals + 2 center-wrap + 1 hash + 2 packing + 9 membership constraints = 19.
	if got, want := len(proof.FparNTT), 19; got != want {
		t.Fatalf("unexpected Fpar constraint count: got %d want %d", got, want)
	}
	ok, err := b.Verify(pub, proof)
	if err != nil || !ok {
		t.Fatalf("verify failed: ok=%v err=%v", ok, err)
	}
}

// Packing tamper: flip a coefficient into the wrong half for M2 (upper→lower),
// while keeping T fixed, so packing constraint should fail.
func TestCredentialPreSignTamperPacking(t *testing.T) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	bound := int64(8)

	// Packed witnesses.
	m1 := makePackedHalf(ringQ, 1, true)
	m2 := makePackedHalf(ringQ, 2, false)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)
	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)

	// Center combine.
	r0 := ringQ.NewPoly()
	r1 := ringQ.NewPoly()
	k0 := ringQ.NewPoly()
	k1 := ringQ.NewPoly()
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
		k0.Coeffs[0][i] = 0
		k1.Coeffs[0][i] = 0
	}

	B, err := loadDefaultB(ringQ)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	tCoeff, err := credential.HashMessage(ringQ, B, m1, m2, r0, r1)
	if err != nil {
		t.Fatalf("hash message: %v", err)
	}

	// Identity Ac/commit.
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

	// Tamper: move one coeff of M2 into the lower half, violating packing.
	m2Tampered := ringQ.NewPoly()
	ring.Copy(m2, m2Tampered)
	m2Tampered.Coeffs[0][0] = 1 // inject non-zero into lower half

	pub := PIOP.PublicInputs{
		Com:    comNTT,
		RI0:    []*ring.Poly{ri0},
		RI1:    []*ring.Poly{ri1},
		Ac:     Ac,
		B:      B,
		T:      tCoeff,
		BoundB: bound,
	}
	wit := PIOP.WitnessInputs{
		M1:  []*ring.Poly{m1},
		M2:  []*ring.Poly{m2Tampered},
		RU0: []*ring.Poly{ru0},
		RU1: []*ring.Poly{ru1},
		R:   []*ring.Poly{rPoly},
		R0:  []*ring.Poly{r0},
		R1:  []*ring.Poly{r1},
		K0:  []*ring.Poly{k0},
		K1:  []*ring.Poly{k1},
	}

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: 8, Ell: 1}
	b := PIOP.NewCredentialBuilder(opts)
	proof, err := b.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	if ok, _ := b.Verify(pub, proof); ok {
		t.Fatalf("expected packing tamper to fail verification")
	}
}

// Packing tamper: flip a coefficient into the upper half for M1 (should be zero there).
func TestCredentialPreSignTamperPackingM1(t *testing.T) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	bound := int64(8)

	m1 := makePackedHalf(ringQ, 1, true)
	m2 := makePackedHalf(ringQ, 2, false)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)
	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)

	// Center combine.
	r0 := ringQ.NewPoly()
	r1 := ringQ.NewPoly()
	k0 := ringQ.NewPoly()
	k1 := ringQ.NewPoly()
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
		k0.Coeffs[0][i] = 0
		k1.Coeffs[0][i] = 0
	}

	B, err := loadDefaultB(ringQ)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	tCoeff, err := credential.HashMessage(ringQ, B, m1, m2, r0, r1)
	if err != nil {
		t.Fatalf("hash message: %v", err)
	}

	// Identity Ac/commit.
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

	// Tamper: move one coeff of M1 into the upper half, violating packing.
	m1Tampered := ringQ.NewPoly()
	ring.Copy(m1, m1Tampered)
	m1Tampered.Coeffs[0][ringQ.N/2] = 1

	pub := PIOP.PublicInputs{
		Com:    comNTT,
		RI0:    []*ring.Poly{ri0},
		RI1:    []*ring.Poly{ri1},
		Ac:     Ac,
		B:      B,
		T:      tCoeff,
		BoundB: bound,
	}
	wit := PIOP.WitnessInputs{
		M1:  []*ring.Poly{m1Tampered},
		M2:  []*ring.Poly{m2},
		RU0: []*ring.Poly{ru0},
		RU1: []*ring.Poly{ru1},
		R:   []*ring.Poly{rPoly},
		R0:  []*ring.Poly{r0},
		R1:  []*ring.Poly{r1},
		K0:  []*ring.Poly{k0},
		K1:  []*ring.Poly{k1},
	}

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: 8, Ell: 1}
	b := PIOP.NewCredentialBuilder(opts)
	proof, err := b.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	if ok, _ := b.Verify(pub, proof); ok {
		t.Fatalf("expected packing tamper to fail verification")
	}
}

func TestCredentialPreSignTamperT(t *testing.T) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	bound := int64(8)

	// Witness polys.
	m1 := makePackedHalf(ringQ, 1, true)
	m2 := makePackedHalf(ringQ, 2, false)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	// Issuer randomness.
	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)

	// Center combine.
	r0 := ringQ.NewPoly()
	r1 := ringQ.NewPoly()
	k0 := ringQ.NewPoly()
	k1 := ringQ.NewPoly()
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
		k0.Coeffs[0][i] = 0
		k1.Coeffs[0][i] = 0
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
		T:      tCoeff,
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
		K0:  []*ring.Poly{k0},
		K1:  []*ring.Poly{k1},
	}

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: 8, Ell: 1}
	b := PIOP.NewCredentialBuilder(opts)
	proof, err := b.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}

	pubBad := pub
	pubBad.T = append([]int64(nil), pub.T...)
	pubBad.T[0]++

	ok, _ := b.Verify(pubBad, proof)
	if ok {
		t.Fatalf("expected verification failure with tampered public T")
	}
}

func TestCredentialPreSignTamperCom(t *testing.T) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	bound := int64(8)

	m1 := makePolyConst(ringQ, 1)
	m2 := makePolyConst(ringQ, 2)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)

	r0 := ringQ.NewPoly()
	r1 := ringQ.NewPoly()
	k0 := ringQ.NewPoly()
	k1 := ringQ.NewPoly()
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
		k0.Coeffs[0][i] = 0
		k1.Coeffs[0][i] = 0
	}

	B, err := loadDefaultB(ringQ)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	tCoeff, err := credential.HashMessage(ringQ, B, m1, m2, r0, r1)
	if err != nil {
		t.Fatalf("hash message: %v", err)
	}

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
		T:      tCoeff,
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
		K0:  []*ring.Poly{k0},
		K1:  []*ring.Poly{k1},
	}

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: 8, Ell: 1}
	b := PIOP.NewCredentialBuilder(opts)
	proof, err := b.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}

	pubBad := pub
	pubBad.Com = append([]*ring.Poly(nil), pub.Com...)
	pubBad.Com[0] = pubBad.Com[0].CopyNew()
	pubBad.Com[0].Coeffs[0][0] = (pubBad.Com[0].Coeffs[0][0] + 1) % uint64(ringQ.Modulus[0])

	ok, _ := b.Verify(pubBad, proof)
	if ok {
		t.Fatalf("expected verification failure with tampered Com")
	}
}

func TestCredentialPreSignBadR0(t *testing.T) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	bound := int64(8)

	m1 := makePolyConst(ringQ, 1)
	m2 := makePolyConst(ringQ, 2)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)

	r0 := makePolyConst(ringQ, 5)
	r1 := makePolyConst(ringQ, 5)
	k0 := makePolyConst(ringQ, 0)
	k1 := makePolyConst(ringQ, 0)

	B, err := loadDefaultB(ringQ)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	// Keep hash consistent with the (bad) R0 witness so this isolates the center constraint.
	tCoeff, err := credential.HashMessage(ringQ, B, m1, m2, r0, r1)
	if err != nil {
		t.Fatalf("hash message: %v", err)
	}

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
		T:      tCoeff,
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
		K0:  []*ring.Poly{k0},
		K1:  []*ring.Poly{k1},
	}

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: 8, Ell: 1}
	b := PIOP.NewCredentialBuilder(opts)
	proof, err := b.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	ok, _ := b.Verify(pub, proof)
	if ok {
		t.Fatalf("expected verification failure with inconsistent R0/R1")
	}
}

func TestCredentialPreSignHashMismatchM2(t *testing.T) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	bound := int64(8)

	m1 := makePolyConst(ringQ, 1)
	m2 := makePolyConst(ringQ, 2)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)

	r0 := makePolyConst(ringQ, 4)
	r1 := makePolyConst(ringQ, 5)
	k0 := makePolyConst(ringQ, 0)
	k1 := makePolyConst(ringQ, 0)

	B, err := loadDefaultB(ringQ)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	tCoeff, err := credential.HashMessage(ringQ, B, m1, m2, r0, r1)
	if err != nil {
		t.Fatalf("hash message: %v", err)
	}

	// Tamper M2 but keep public T fixed (hash should fail).
	m2Bad := m2.CopyNew()
	m2Bad.Coeffs[0][0] = (m2Bad.Coeffs[0][0] + 1) % uint64(ringQ.Modulus[0])

	vec := []*ring.Poly{m1, m2Bad, ru0, ru1, rPoly}
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
		T:      tCoeff,
		BoundB: bound,
	}
	wit := PIOP.WitnessInputs{
		M1:  []*ring.Poly{m1},
		M2:  []*ring.Poly{m2Bad},
		RU0: []*ring.Poly{ru0},
		RU1: []*ring.Poly{ru1},
		R:   []*ring.Poly{rPoly},
		R0:  []*ring.Poly{r0},
		R1:  []*ring.Poly{r1},
		K0:  []*ring.Poly{k0},
		K1:  []*ring.Poly{k1},
	}

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: 8, Ell: 1}
	b := PIOP.NewCredentialBuilder(opts)
	proof, err := b.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	ok, _ := b.Verify(pub, proof)
	if ok {
		t.Fatalf("expected verification failure with hash mismatch (M2 tampered, T fixed)")
	}
}

func TestCredentialPreSignCarryOutOfRange(t *testing.T) {
	ringQ, err := credential.LoadDefaultRing()
	if err != nil {
		t.Fatalf("load ring: %v", err)
	}
	bound := int64(8)

	m1 := makePolyConst(ringQ, 1)
	m2 := makePolyConst(ringQ, 2)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)

	r0 := makePolyConst(ringQ, 4)
	r1 := makePolyConst(ringQ, 5)
	k0 := makePolyConst(ringQ, 2)
	k1 := makePolyConst(ringQ, 0)

	B, err := loadDefaultB(ringQ)
	if err != nil {
		t.Fatalf("load B: %v", err)
	}
	tCoeff, err := credential.HashMessage(ringQ, B, m1, m2, r0, r1)
	if err != nil {
		t.Fatalf("hash message: %v", err)
	}

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
		T:      tCoeff,
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
		K0:  []*ring.Poly{k0},
		K1:  []*ring.Poly{k1},
	}

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: 8, Ell: 1}
	b := PIOP.NewCredentialBuilder(opts)
	proof, err := b.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		t.Fatalf("build proof: %v", err)
	}
	ok, _ := b.Verify(pub, proof)
	if ok {
		t.Fatalf("expected verification failure with out-of-range carry K0")
	}
}
