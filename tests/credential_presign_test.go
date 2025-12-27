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

// makePolyConst returns a coeff-domain poly whose evaluation-domain values
// are all set to v (centered).
func makePolyConst(r *ring.Ring, v int64) *ring.Poly {
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

// makePackedHalf zeros halves over the first ncols evaluation points (Ω).
// Packing is enforced in the evaluation domain, so we zero halves in NTT form.
func makePackedHalf(r *ring.Ring, ncols int, v int64, keepLower bool) *ring.Poly {
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
	if ncols <= 0 || ncols > r.N {
		ncols = r.N
	}
	half := ncols / 2
	zero := uint64(0)
	if ncols%2 != 0 {
		panic("ring dimension must be even for packing test")
	}
	if keepLower {
		for i := half; i < ncols; i++ {
			pNTT.Coeffs[0][i] = zero
		}
	} else {
		for i := 0; i < half; i++ {
			pNTT.Coeffs[0][i] = zero
		}
	}
	p := r.NewPoly()
	r.InvNTT(pNTT, p)
	return p
}

func nttCopy(r *ring.Ring, p *ring.Poly) *ring.Poly {
	cp := p.CopyNew()
	r.NTT(cp, cp)
	return cp
}

// testNCols chooses a column count that respects the degree budget for
// quadratic constraints (avoid wraparound in polynomial products).
func testNCols(r *ring.Ring) int {
	if r == nil {
		return 0
	}
	// Keep ncols small enough so max constraint degree fits in ringQ.N
	// (bounds degree dominates; with B=8, degree=17).
	n := r.N / 32
	if n < 8 {
		n = 8
	}
	if n%2 != 0 {
		n--
	}
	return n
}

// centerWrapEvalDomain computes R and K using evaluation-domain values:
// RU + RI = R + (2B+1)·K with K in {-1,0,1}.
func centerWrapEvalDomain(r *ring.Ring, ru, ri *ring.Poly, bound int64) (*ring.Poly, *ring.Poly) {
	ruNTT := ru.CopyNew()
	riNTT := ri.CopyNew()
	r.NTT(ruNTT, ruNTT)
	r.NTT(riNTT, riNTT)

	rNTT := r.NewPoly()
	kNTT := r.NewPoly()
	q := int64(r.Modulus[0])
	half := q / 2
	delta := int64(2*bound + 1)

	for i := 0; i < r.N; i++ {
		a := int64(ruNTT.Coeffs[0][i])
		if a > half {
			a -= q
		}
		b := int64(riNTT.Coeffs[0][i])
		if b > half {
			b -= q
		}
		sum := a + b
		c := credential.CenterBounded(sum, bound)
		if c < 0 {
			rNTT.Coeffs[0][i] = uint64(c + q)
		} else {
			rNTT.Coeffs[0][i] = uint64(c)
		}
		k := (sum - c) / delta
		if k < 0 {
			kNTT.Coeffs[0][i] = uint64(k + q)
		} else {
			kNTT.Coeffs[0][i] = uint64(k)
		}
	}
	rOut := r.NewPoly()
	kOut := r.NewPoly()
	r.InvNTT(rNTT, rOut)
	r.InvNTT(kNTT, kOut)
	return rOut, kOut
}

// tamperEvalDomain changes one evaluation-domain slot and returns a new poly.
func tamperEvalDomain(r *ring.Ring, p *ring.Poly, idx int, delta int64) *ring.Poly {
	pNTT := p.CopyNew()
	r.NTT(pNTT, pNTT)
	q := int64(r.Modulus[0])
	if idx < 0 {
		idx = 0
	}
	idx %= r.N
	v := int64(pNTT.Coeffs[0][idx])
	v = (v + delta) % q
	if v < 0 {
		v += q
	}
	pNTT.Coeffs[0][idx] = uint64(v)
	out := r.NewPoly()
	r.InvNTT(pNTT, out)
	return out
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
	ncols := testNCols(ringQ)

	// Witness polys (packed halves).
	m1 := makePackedHalf(ringQ, ncols, 1, true)
	m2 := makePackedHalf(ringQ, ncols, 2, false)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	// Issuer randomness.
	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)
	ri0NTT := nttCopy(ringQ, ri0)
	ri1NTT := nttCopy(ringQ, ri1)

	// Center combine (evaluation domain).
	r0, k0 := centerWrapEvalDomain(ringQ, ru0, ri0, bound)
	r1, k1 := centerWrapEvalDomain(ringQ, ru1, ri1, bound)

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
		RI0:    []*ring.Poly{ri0NTT},
		RI1:    []*ring.Poly{ri1NTT},
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

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: ncols, Ell: 1}
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
	ncols := testNCols(ringQ)

	// Packed witnesses.
	m1 := makePackedHalf(ringQ, ncols, 1, true)
	m2 := makePackedHalf(ringQ, ncols, 2, false)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)
	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)
	ri0NTT := nttCopy(ringQ, ri0)
	ri1NTT := nttCopy(ringQ, ri1)

	// Center combine (evaluation domain).
	r0, k0 := centerWrapEvalDomain(ringQ, ru0, ri0, bound)
	r1, k1 := centerWrapEvalDomain(ringQ, ru1, ri1, bound)

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

	// Tamper: move one eval-domain slot of M2 into the lower half, violating packing.
	m2Tampered := tamperEvalDomain(ringQ, m2, 0, 1)

	pub := PIOP.PublicInputs{
		Com:    comNTT,
		RI0:    []*ring.Poly{ri0NTT},
		RI1:    []*ring.Poly{ri1NTT},
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

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: ncols, Ell: 1}
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
	ncols := testNCols(ringQ)

	m1 := makePackedHalf(ringQ, ncols, 1, true)
	m2 := makePackedHalf(ringQ, ncols, 2, false)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)
	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)
	ri0NTT := nttCopy(ringQ, ri0)
	ri1NTT := nttCopy(ringQ, ri1)

	// Center combine (evaluation domain).
	r0, k0 := centerWrapEvalDomain(ringQ, ru0, ri0, bound)
	r1, k1 := centerWrapEvalDomain(ringQ, ru1, ri1, bound)

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

	// Tamper: move one eval-domain slot of M1 into the upper half, violating packing.
	m1Tampered := tamperEvalDomain(ringQ, m1, ncols/2, 1)

	pub := PIOP.PublicInputs{
		Com:    comNTT,
		RI0:    []*ring.Poly{ri0NTT},
		RI1:    []*ring.Poly{ri1NTT},
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

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: ncols, Ell: 1}
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
	ncols := testNCols(ringQ)

	// Witness polys.
	m1 := makePackedHalf(ringQ, ncols, 1, true)
	m2 := makePackedHalf(ringQ, ncols, 2, false)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	// Issuer randomness.
	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)
	ri0NTT := nttCopy(ringQ, ri0)
	ri1NTT := nttCopy(ringQ, ri1)

	// Center combine (evaluation domain).
	r0, k0 := centerWrapEvalDomain(ringQ, ru0, ri0, bound)
	r1, k1 := centerWrapEvalDomain(ringQ, ru1, ri1, bound)

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
		RI0:    []*ring.Poly{ri0NTT},
		RI1:    []*ring.Poly{ri1NTT},
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

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: ncols, Ell: 1}
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
	ncols := testNCols(ringQ)

	m1 := makePolyConst(ringQ, 1)
	m2 := makePolyConst(ringQ, 2)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)
	ri0NTT := nttCopy(ringQ, ri0)
	ri1NTT := nttCopy(ringQ, ri1)

	// Center combine (evaluation domain).
	r0, k0 := centerWrapEvalDomain(ringQ, ru0, ri0, bound)
	r1, k1 := centerWrapEvalDomain(ringQ, ru1, ri1, bound)

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
		RI0:    []*ring.Poly{ri0NTT},
		RI1:    []*ring.Poly{ri1NTT},
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

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: ncols, Ell: 1}
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
	ncols := testNCols(ringQ)

	m1 := makePolyConst(ringQ, 1)
	m2 := makePolyConst(ringQ, 2)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)
	ri0NTT := nttCopy(ringQ, ri0)
	ri1NTT := nttCopy(ringQ, ri1)

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
		RI0:    []*ring.Poly{ri0NTT},
		RI1:    []*ring.Poly{ri1NTT},
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

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: ncols, Ell: 1}
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
	ncols := testNCols(ringQ)

	m1 := makePolyConst(ringQ, 1)
	m2 := makePolyConst(ringQ, 2)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)
	ri0NTT := nttCopy(ringQ, ri0)
	ri1NTT := nttCopy(ringQ, ri1)

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
	m2Bad := tamperEvalDomain(ringQ, m2, 0, 1)

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
		RI0:    []*ring.Poly{ri0NTT},
		RI1:    []*ring.Poly{ri1NTT},
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

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: ncols, Ell: 1}
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
	ncols := testNCols(ringQ)

	m1 := makePolyConst(ringQ, 1)
	m2 := makePolyConst(ringQ, 2)
	ru0 := makePolyConst(ringQ, 3)
	ru1 := makePolyConst(ringQ, 4)
	rPoly := makePolyConst(ringQ, 1)

	ri0 := makePolyConst(ringQ, 1)
	ri1 := makePolyConst(ringQ, 1)
	ri0NTT := nttCopy(ringQ, ri0)
	ri1NTT := nttCopy(ringQ, ri1)

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
		RI0:    []*ring.Poly{ri0NTT},
		RI1:    []*ring.Poly{ri1NTT},
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

	opts := PIOP.SimOpts{Credential: true, Theta: 2, EllPrime: 1, Rho: 1, NCols: ncols, Ell: 1}
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
