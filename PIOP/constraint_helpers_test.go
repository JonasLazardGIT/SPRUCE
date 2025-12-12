package PIOP

import (
	"testing"

	"github.com/tuneinsight/lattigo/v4/ring"
)

func tinyRing(t *testing.T) *ring.Ring {
	r, err := ring.NewRing(16, []uint64{65537})
	if err != nil || r == nil {
		t.Fatalf("tinyRing: %v", err)
	}
	return r
}

func TestBuildCommitConstraints(t *testing.T) {
	r := tinyRing(t)
	one := r.NewPoly()
	one.Coeffs[0][0] = 1
	r.NTT(one, one)
	Ac := [][]*ring.Poly{{one}}
	vec := []*ring.Poly{one}
	com := []*ring.Poly{one}
	res, err := BuildCommitConstraints(r, Ac, vec, com)
	if err != nil {
		t.Fatalf("commit constraints: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 residual")
	}
	if !r.Equal(res[0], r.NewPoly()) {
		t.Fatalf("expected zero residual")
	}
	// Tamper com
	com[0].Coeffs[0][0]++
	r.NTT(com[0], com[0])
	res, _ = BuildCommitConstraints(r, Ac, vec, com)
	if r.Equal(res[0], r.NewPoly()) {
		t.Fatalf("expected non-zero residual after tamper")
	}
}

func TestBuildCenterConstraints(t *testing.T) {
	r := tinyRing(t)
	ru := r.NewPoly()
	ri := r.NewPoly()
	rSum := r.NewPoly()
	ru.Coeffs[0][0] = 2
	ri.Coeffs[0][0] = 3
	rSum.Coeffs[0][0] = 5
	r.NTT(ru, ru)
	r.NTT(ri, ri)
	r.NTT(rSum, rSum)
	res, err := BuildCenterConstraints(r, 5, []*ring.Poly{ru}, []*ring.Poly{ri}, []*ring.Poly{rSum})
	if err != nil {
		t.Fatalf("center constraints: %v", err)
	}
	if len(res) != 1 || !r.Equal(res[0], r.NewPoly()) {
		t.Fatalf("expected zero residual")
	}
	// Tamper r
	rTamper := r.NewPoly()
	r.NTT(rTamper, rTamper)
	res, _ = BuildCenterConstraints(r, 5, []*ring.Poly{ru}, []*ring.Poly{ri}, []*ring.Poly{rTamper})
	if r.Equal(res[0], r.NewPoly()) {
		t.Fatalf("expected non-zero residual after tamper")
	}
}

func TestBuildSignatureConstraint(t *testing.T) {
	r := tinyRing(t)
	one := r.NewPoly()
	one.Coeffs[0][0] = 1
	r.NTT(one, one)
	A := [][]*ring.Poly{{one}}
	U := []*ring.Poly{one}
	T := make([]int64, r.N)
	T[0] = 1
	res, err := BuildSignatureConstraint(r, A, U, T)
	if err != nil {
		t.Fatalf("sig constraints: %v", err)
	}
	if len(res) != 1 || !r.Equal(res[0], r.NewPoly()) {
		t.Fatalf("expected zero residual")
	}
	T[0] = 2
	res, _ = BuildSignatureConstraint(r, A, U, T)
	if r.Equal(res[0], r.NewPoly()) {
		t.Fatalf("expected non-zero residual after tamper")
	}
}

func TestBuildBoundConstraints(t *testing.T) {
	r := tinyRing(t)
	p := r.NewPoly()
	p.Coeffs[0][0] = 3
	if err := BuildBoundConstraints([]*ring.Poly{p}, 5); err != nil {
		t.Fatalf("expected within bound: %v", err)
	}
	p.Coeffs[0][0] = 7
	if err := BuildBoundConstraints([]*ring.Poly{p}, 5); err == nil {
		t.Fatalf("expected bound violation")
	}
}
