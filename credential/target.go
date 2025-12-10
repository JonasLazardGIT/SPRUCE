package credential

import (
	"fmt"

	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// CombinedTarget bundles the combined randomness and derived hash target.
type CombinedTarget struct {
	R0 []*ring.Poly
	R1 []*ring.Poly
	T  []int64
}

// ComputeCombinedTarget takes holder secrets and issuer challenge, combines
// randomness with center semantics, and hashes to t using explicit polynomials.
// Inputs are assumed to be in NTT domain; this helper handles the conversions.
func ComputeCombinedTarget(p *Params, h HolderState, chal IssuerChallenge) (*CombinedTarget, error) {
	if p == nil || p.RingQ == nil {
		return nil, fmt.Errorf("nil params or ring")
	}
	ringQ := p.RingQ
	if err := CheckLengths(h.M1, p.LenM1, "m1"); err != nil {
		return nil, err
	}
	if err := CheckLengths(h.M2, p.LenM2, "m2"); err != nil {
		return nil, err
	}
	if err := CheckLengths(h.RU0, p.LenRU0, "rU0"); err != nil {
		return nil, err
	}
	if err := CheckLengths(h.RU1, p.LenRU1, "rU1"); err != nil {
		return nil, err
	}
	if err := CheckLengths(chal.RI0, p.LenRU0, "rI0"); err != nil {
		return nil, err
	}
	if err := CheckLengths(chal.RI1, p.LenRU1, "rI1"); err != nil {
		return nil, err
	}

	// Convert inputs to coefficient domain.
	toCoeff := func(src []*ring.Poly) ([]*ring.Poly, error) {
		out := make([]*ring.Poly, len(src))
		for i, poly := range src {
			if poly == nil {
				return nil, fmt.Errorf("nil poly at %d", i)
			}
			cp := ringQ.NewPoly()
			ring.Copy(poly, cp)
			ringQ.InvNTT(cp, cp)
			out[i] = cp
		}
		return out, nil
	}

	m1c, err := toCoeff(h.M1)
	if err != nil {
		return nil, err
	}
	m2c, err := toCoeff(h.M2)
	if err != nil {
		return nil, err
	}
	ru0c, err := toCoeff(h.RU0)
	if err != nil {
		return nil, err
	}
	ru1c, err := toCoeff(h.RU1)
	if err != nil {
		return nil, err
	}
	ri0c, err := toCoeff(chal.RI0)
	if err != nil {
		return nil, err
	}
	ri1c, err := toCoeff(chal.RI1)
	if err != nil {
		return nil, err
	}

	r0 := make([]*ring.Poly, len(ru0c))
	r1 := make([]*ring.Poly, len(ru1c))
	for i := range ru0c {
		c, err := combinePoly(ringQ, ru0c[i], ri0c[i], p.BoundB)
		if err != nil {
			return nil, fmt.Errorf("combine r0[%d]: %w", i, err)
		}
		r0[i] = c
	}
	for i := range ru1c {
		c, err := combinePoly(ringQ, ru1c[i], ri1c[i], p.BoundB)
		if err != nil {
			return nil, fmt.Errorf("combine r1[%d]: %w", i, err)
		}
		r1[i] = c
	}

	if len(r0) == 0 || len(r1) == 0 {
		return nil, fmt.Errorf("empty randomness blocks")
	}
	// Build concatenated m1/m2 for hashing.
	if len(m1c) == 0 || len(m2c) == 0 {
		return nil, fmt.Errorf("empty m1 or m2 not supported")
	}
	if len(m1c) != 1 || len(m2c) != 1 || len(r0) != 1 || len(r1) != 1 {
		return nil, fmt.Errorf("only single-poly m1/m2/r0/r1 supported; got m1=%d m2=%d r0=%d r1=%d",
			len(m1c), len(m2c), len(r0), len(r1))
	}
	// Load B in NTT.
	bPath := p.BPath
	bCoeffs, err := ntrurio.LoadBMatrixCoeffs(bPath)
	if err != nil {
		return nil, err
	}
	toNTT := func(raw []uint64) *ring.Poly {
		poly := ringQ.NewPoly()
		copy(poly.Coeffs[0], raw)
		ringQ.NTT(poly, poly)
		return poly
	}
	B := []*ring.Poly{
		toNTT(bCoeffs[0]),
		toNTT(bCoeffs[1]),
		toNTT(bCoeffs[2]),
		toNTT(bCoeffs[3]),
	}

	// For now, hash only the first poly of each; extend when multi-block messages are defined.
	tCoeffs, err := HashMessage(ringQ, B, m1c[0], m2c[0], r0[0], r1[0])
	if err != nil {
		return nil, err
	}

	return &CombinedTarget{R0: r0, R1: r1, T: tCoeffs}, nil
}

// combinePoly applies center(a+b) coefficient-wise, returns coeff-domain poly.
func combinePoly(ringQ *ring.Ring, a, b *ring.Poly, bound int64) (*ring.Poly, error) {
	if a == nil || b == nil {
		return nil, fmt.Errorf("nil input poly")
	}
	if len(a.Coeffs[0]) != len(b.Coeffs[0]) {
		return nil, fmt.Errorf("length mismatch")
	}
	q := int64(ringQ.Modulus[0])
	half := q / 2
	out := ringQ.NewPoly()
	for i := 0; i < len(a.Coeffs[0]); i++ {
		av := int64(a.Coeffs[0][i])
		bv := int64(b.Coeffs[0][i])
		if av > half {
			av -= q
		}
		if bv > half {
			bv -= q
		}
		cv := CenterBounded(av+bv, bound)
		if cv < 0 {
			out.Coeffs[0][i] = uint64(cv + q)
		} else {
			out.Coeffs[0][i] = uint64(cv)
		}
	}
	return out, nil
}
