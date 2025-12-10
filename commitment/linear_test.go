package commitment

import (
	"testing"

	ntrurio "vSIS-Signature/ntru/io"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

func randPoly(r *ring.Ring, prng utils.PRNG) *ring.Poly {
	p := r.NewPoly()
	us := ring.NewUniformSampler(prng, r)
	us.Read(p)
	return p
}

func TestCommitVerify(t *testing.T) {
	par, err := ntrurio.LoadParams("Parameters/Parameters.json", true)
	if err != nil {
		if parUp, errUp := ntrurio.LoadParams("../Parameters/Parameters.json", true); errUp == nil {
			par = parUp
		} else {
			t.Fatalf("load params: %v", err)
		}
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	prng, err := utils.NewPRNG()
	if err != nil {
		t.Fatalf("prng: %v", err)
	}

	vec := Vector{randPoly(ringQ, prng), randPoly(ringQ, prng), randPoly(ringQ, prng)}
	Ac := Matrix{
		{randPoly(ringQ, prng), randPoly(ringQ, prng), randPoly(ringQ, prng)},
		{randPoly(ringQ, prng), randPoly(ringQ, prng), randPoly(ringQ, prng)},
	}

	com, err := Commit(ringQ, Ac, vec)
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := Verify(ringQ, Ac, vec, com); err != nil {
		t.Fatalf("verify: %v", err)
	}

	// Tamper a coefficient and expect verification to fail.
	com[0].Coeffs[0][0]++
	if err := Verify(ringQ, Ac, vec, com); err == nil {
		t.Fatalf("verify should fail on tampered commitment")
	}
}

func TestCommitDimensionMismatch(t *testing.T) {
	par, err := ntrurio.LoadParams("Parameters/Parameters.json", true)
	if err != nil {
		par, err = ntrurio.LoadParams("../Parameters/Parameters.json", true)
		if err != nil {
			t.Fatalf("load params: %v", err)
		}
	}
	ringQ, err := ring.NewRing(par.N, []uint64{par.Q})
	if err != nil {
		t.Fatalf("ring: %v", err)
	}
	vec := Vector{ringQ.NewPoly(), ringQ.NewPoly()}
	Ac := Matrix{{ringQ.NewPoly()}}
	if _, err := Commit(ringQ, Ac, vec); err == nil {
		t.Fatalf("expected dimension mismatch error")
	}
}
