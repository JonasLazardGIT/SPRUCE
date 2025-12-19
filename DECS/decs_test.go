package decs

import (
	"crypto/rand"
	"math/big"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/utils"
)

func testParams(ringQ *ring.Ring, eta int, ell int) Params {
	return Params{Degree: int(ringQ.N - 1), Eta: eta, NonceBytes: 16}
}

func TestDECS_CommitEval_Accepts(t *testing.T) {
	N := 1 << 11
	moduli := []uint64{(1<<32 - (1 << 20) + 1)}
	ringQ, err := ring.NewRing(N, moduli)
	if err != nil {
		t.Fatal(err)
	}
	eta, ell := 2, 64
	params := testParams(ringQ, eta, ell)

	r := 5
	Ps := make([]*ring.Poly, r)
	prng, _ := utils.NewPRNG()
	us := ring.NewUniformSampler(prng, ringQ)
	for j := 0; j < r; j++ {
		Ps[j] = ringQ.NewPoly()
		us.Read(Ps[j])
		for i := params.Degree + 1; i < int(N); i++ {
			Ps[j].Coeffs[0][i] = 0
		}
	}
	prover := NewProverWithParams(ringQ, Ps, params)
	root, err := prover.CommitInit()
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewVerifierWithParams(ringQ, r, params)
	Gamma := verifier.DeriveGamma(root)
	R := prover.CommitStep2(Gamma)
	if !verifier.VerifyCommit(root, R, Gamma) {
		t.Fatal("VerifyCommit failed (should accept)")
	}

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	perm := rng.Perm(int(N))
	E := make([]int, ell)
	copy(E, perm[:ell])
	open := prover.EvalOpen(E)
	if !verifier.VerifyEvalAt(root, Gamma, R, open, E) {
		t.Fatal("VerifyEvalAt failed (should accept)")
	}
}

func TestDECS_Rejects_HighDegree(t *testing.T) {
	N := 1 << 11
	moduli := []uint64{(1<<32 - (1 << 20) + 1)}
	ringQ, _ := ring.NewRing(N, moduli)
	eta := 2
	params := Params{Degree: int(ringQ.N - 2), Eta: eta, NonceBytes: 16}

	r := 3
	Ps := make([]*ring.Poly, r)
	for j := 0; j < r; j++ {
		Ps[j] = ringQ.NewPoly()
	}
	Ps[0].Coeffs[0][params.Degree+1] = 1

	prover := NewProverWithParams(ringQ, Ps, params)
	root, err := prover.CommitInit()
	if err != nil {
		t.Fatal(err)
	}
	verifier := NewVerifierWithParams(ringQ, r, params)
	Gamma := verifier.DeriveGamma(root)
	R := prover.CommitStep2(Gamma)

	if verifier.VerifyCommit(root, R, Gamma) {
		t.Fatal("VerifyCommit accepted R with degree > d")
	}
}

func TestDECS_Rejects_DuplicateE(t *testing.T) {
	N := 1 << 11
	moduli := []uint64{(1<<32 - (1 << 20) + 1)}
	ringQ, _ := ring.NewRing(N, moduli)
	eta, ell := 2, 8
	params := testParams(ringQ, eta, ell)

	r := 3
	Ps := make([]*ring.Poly, r)
	prng, _ := utils.NewPRNG()
	us := ring.NewUniformSampler(prng, ringQ)
	for j := range Ps {
		Ps[j] = ringQ.NewPoly()
		us.Read(Ps[j])
		for i := params.Degree + 1; i < int(N); i++ {
			Ps[j].Coeffs[0][i] = 0
		}
	}
	prover := NewProverWithParams(ringQ, Ps, params)
	root, _ := prover.CommitInit()
	verifier := NewVerifierWithParams(ringQ, r, params)
	Gamma := verifier.DeriveGamma(root)
	R := prover.CommitStep2(Gamma)

	E := []int{3, 17, 3, 42, 99, 100, 101, 102}
	open := prover.EvalOpen(E)
	if verifier.VerifyEvalAt(root, Gamma, R, open, E) {
		t.Fatal("VerifyEvalAt accepted a duplicate E (should reject)")
	}
}

func TestDECS_Rejects_MalformedOpening(t *testing.T) {
	N := 1 << 11
	moduli := []uint64{(1<<32 - (1 << 20) + 1)}
	ringQ, _ := ring.NewRing(N, moduli)
	eta, ell := 2, 8
	params := testParams(ringQ, eta, ell)

	r := 3
	Ps := make([]*ring.Poly, r)
	for j := range Ps {
		Ps[j] = ringQ.NewPoly()
	}
	prover := NewProverWithParams(ringQ, Ps, params)
	root, _ := prover.CommitInit()
	verifier := NewVerifierWithParams(ringQ, r, params)
	Gamma := verifier.DeriveGamma(root)
	R := prover.CommitStep2(Gamma)

	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	perm := rng.Perm(int(N))
	E := make([]int, ell)
	copy(E, perm[:ell])
	open := prover.EvalOpen(E)
	if len(open.NonceSeed) == 0 {
		t.Fatal("expected nonce seed in opening")
	}
	badSeed := append([]byte(nil), open.NonceSeed...)
	badSeed[0] ^= 0x01
	open.NonceSeed = badSeed
	if verifier.VerifyEvalAt(root, Gamma, R, open, E) {
		t.Fatal("VerifyEvalAt accepted opening with tampered nonce seed")
	}

	open = prover.EvalOpen(E)
	open.NonceBytes = params.NonceBytes - 1
	if verifier.VerifyEvalAt(root, Gamma, R, open, E) {
		t.Fatal("VerifyEvalAt accepted opening with wrong nonce length metadata")
	}

	open = prover.EvalOpen(E)
	open.Pvals[0] = open.Pvals[0][:r-1]
	if verifier.VerifyEvalAt(root, Gamma, R, open, E) {
		t.Fatal("VerifyEvalAt accepted opening with short Pvals row")
	}
}

func TestParamsStrictness_DegreeOutOfRange(t *testing.T) {
	N := 1 << 11
	moduli := []uint64{(1<<32 - (1 << 20) + 1)}
	ringQ, err := ring.NewRing(N, moduli)
	if err != nil {
		t.Fatalf("ring.NewRing: %v", err)
	}
	params := Params{Degree: int(ringQ.N), Eta: 2, NonceBytes: 16}
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on invalid Degree")
		}
	}()
	_ = NewVerifierWithParams(ringQ, 3, params)
}

func Test_mulMod64_Correctness(t *testing.T) {
	q := uint64((1 << 60) - (1 << 32) + 1)
	bA := new(big.Int)
	bB := new(big.Int)
	bQ := new(big.Int).SetUint64(q)
	limit := new(big.Int).Lsh(big.NewInt(1), 64)
	for i := 0; i < 10000; i++ {
		ra, _ := rand.Int(rand.Reader, limit)
		rb, _ := rand.Int(rand.Reader, limit)
		a := ra.Uint64()
		b := rb.Uint64()
		got := mulMod64(a, b, q)
		bA.SetUint64(a)
		bB.SetUint64(b)
		want := new(big.Int).Mod(new(big.Int).Mul(bA, bB), bQ).Uint64()
		if got != want {
			t.Fatalf("mulMod64 mismatch: got=%d want=%d (a=%d b=%d q=%d)", got, want, a, b, q)
		}
	}
}
