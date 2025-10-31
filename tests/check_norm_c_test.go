package tests

import (
	"math"
	"math/big"
	"testing"
	ntru "vSIS-Signature/ntru"
)

// Minimal unit for CheckNormC showing accept/reject behavior is coherent.
func TestCheckNormC_Basic(t *testing.T) {
	par, _ := ntru.NewParams(16, big.NewInt(12289))
	opts := ntru.SamplerOpts{Alpha: 1.2, RSquare: ntru.CReferenceRSquare(), Slack: 1.042}
	// Compute gamma^2 as in CheckNormC
	qf := float64(12289)
	sigmaSq := opts.RSquare * opts.Alpha * opts.Alpha * qf
	gammaSq := opts.Slack * opts.Slack * sigmaSq * float64(par.N) * 2.0

	// Build a vector well below the bound
	// ssum = k * 1^2; choose k small
	s1 := make([]int64, par.N)
	s2 := make([]int64, par.N)
	k := int(math.Min(2, float64(par.N)))
	for i := 0; i < k; i++ {
		s1[i] = 1
	}
	if !ntru.CheckNormC(s1, s2, par, opts) {
		t.Fatalf("expected accept below gamma^2")
	}

	// Build a vector likely above the bound by increasing coefficients
	s1 = make([]int64, par.N)
	s2 = make([]int64, par.N)
	// Set a few coefficients to a large value so sum^2 exceeds gammaSq
	bigv := int64(math.Ceil(math.Sqrt(gammaSq)))
	s1[0], s2[1] = bigv, bigv
	if ntru.CheckNormC(s1, s2, par, opts) {
		t.Fatalf("expected reject above gamma^2")
	}
}

// Ensure the big-float predicate agrees with the legacy float64 path when Q fits.
func TestCheckNormC_BigFloatMatchesFloat64(t *testing.T) {
	par, _ := ntru.NewParams(16, big.NewInt(12289))
	opts := ntru.SamplerOpts{Alpha: 1.2, RSquare: ntru.CReferenceRSquare(), Slack: 1.05}
	s1 := make([]int64, par.N)
	s2 := make([]int64, par.N)
	for i := 0; i < par.N; i += 3 {
		s1[i] = int64(i % 5)
		if i+1 < par.N {
			s2[i+1] = int64((i + 1) % 4)
		}
	}
	got := ntru.CheckNormC(s1, s2, par, opts)
	want := legacyCheckNormC(s1, s2, par, opts)
	if got != want {
		t.Fatalf("CheckNormC mismatch: big=%v legacy=%v", got, want)
	}
}

// With large Q (>53 bits) the legacy check rejected outright; big-float path should accept.
func TestCheckNormC_BigQLargePrecision(t *testing.T) {
	bigQ := new(big.Int).Lsh(big.NewInt(1), 60)
	bigQ.Add(bigQ, big.NewInt(1))
	par, err := ntru.NewParams(8, bigQ)
	if err != nil {
		t.Fatalf("NewParams: %v", err)
	}
	opts := ntru.SamplerOpts{Alpha: 1.1, RSquare: ntru.CReferenceRSquare(), Slack: 1.1}
	s1 := make([]int64, par.N)
	s2 := make([]int64, par.N)
	if !ntru.CheckNormC(s1, s2, par, opts) {
		t.Fatalf("expected CheckNormC to accept zero vector for large Q")
	}
	if legacyCheckNormC(s1, s2, par, opts) {
		t.Fatalf("legacy check should reject when Q is too large")
	}
}

func legacyCheckNormC(s1, s2 []int64, par ntru.Params, opts ntru.SamplerOpts) bool {
	var sum int64
	for i := 0; i < par.N; i++ {
		sum += s1[i]*s1[i] + s2[i]*s2[i]
	}
	if opts.UseLog3Cross {
		half := par.N / 2
		for i := 0; i < half; i++ {
			sum += s1[i] * s1[i+half]
			sum += s2[i] * s2[i+half]
		}
	}
	if opts.RSquare <= 0 || opts.Alpha <= 0 || opts.Slack <= 0 {
		return false
	}
	if par.Q.BitLen() > 53 {
		return false
	}
	qf, _ := par.Q.Float64()
	sigmaSq := opts.RSquare * opts.Alpha * opts.Alpha * qf
	gammaSq := opts.Slack * opts.Slack * sigmaSq * float64(par.N) * 2.0
	return float64(sum) <= gammaSq
}
