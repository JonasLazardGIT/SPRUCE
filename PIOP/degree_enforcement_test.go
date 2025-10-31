package PIOP

import (
	"math"
	"testing"
)

type dqCase struct {
	name           string
	s              int
	ellPrime       int
	membershipDegs []int
	rangeDeg       int
	fieldTheta     int
}

func TestComputeDQFromConstraintDegrees(t *testing.T) {
	q := uint64(1038337)
	cases := []dqCase{
		{
			name:           "prime-field",
			s:              8,
			ellPrime:       3,
			membershipDegs: []int{5, 7},
			rangeDeg:       -1,
			fieldTheta:     1,
		},
		{
			name:           "range-dominates",
			s:              6,
			ellPrime:       2,
			membershipDegs: []int{3},
			rangeDeg:       9,
			fieldTheta:     1,
		},
		{
			name:           "extension-field",
			s:              5,
			ellPrime:       1,
			membershipDegs: []int{4, 6},
			rangeDeg:       -1,
			fieldTheta:     3,
		},
	}

	for _, tc := range cases {
		spec := LinfSpec{L: len(tc.membershipDegs), PDi: make([][]uint64, len(tc.membershipDegs))}
		for i, deg := range tc.membershipDegs {
			if deg < 0 {
				continue
			}
			coeffs := make([]uint64, deg+1)
			coeffs[deg] = 1
			spec.PDi[i] = coeffs
		}
		var rmSpec *RangeMembershipSpec
		if tc.rangeDeg >= 0 {
			coeffs := make([]uint64, tc.rangeDeg+1)
			coeffs[tc.rangeDeg] = 1
			rm := RangeMembershipSpec{Coeffs: coeffs}
			rmSpec = &rm
		}
		d := parallelConstraintDegree(&spec, rmSpec)
		expectedD := 2
		for _, deg := range tc.membershipDegs {
			if deg > expectedD {
				expectedD = deg
			}
		}
		if tc.rangeDeg > expectedD {
			expectedD = tc.rangeDeg
		}
		if d != expectedD {
			t.Fatalf("%s: got parallel degree %d, want %d", tc.name, d, expectedD)
		}
		dPrime := aggregatedConstraintDegree()
		span := tc.ellPrime + tc.s - 1
		expectedDQ := expectedD*span + (tc.s - 1)
		other := dPrime * span
		if other > expectedDQ {
			expectedDQ = other
		}
		dQ := computeDQFromConstraintDegrees(d, dPrime, tc.s, tc.ellPrime)
		if dQ != expectedDQ {
			t.Fatalf("%s: dQ mismatch got %d want %d", tc.name, dQ, expectedDQ)
		}

		opts := defaultSimOpts()
		opts.Theta = tc.fieldTheta
		fieldSize := math.Pow(float64(q), float64(tc.fieldTheta))
		sb := computeSoundnessBudget(opts, q, fieldSize, dQ, tc.s, opts.Ell, tc.ellPrime, opts.Eta, 64, tc.s)
		Ssize := fieldSize - float64(tc.s)
		if Ssize < 1 {
			Ssize = 1
		}
		expectedBits3 := logComb2(Ssize, tc.ellPrime) - logComb2(float64(dQ), tc.ellPrime)
		if math.IsInf(expectedBits3, -1) || expectedBits3 < 0 {
			expectedBits3 = 0
		}
		expectedEps3 := math.Pow(2, -expectedBits3)
		if math.Abs(sb.Eps[2]-expectedEps3) > 1e-12 {
			t.Fatalf("%s: eps3 mismatch got %.12e want %.12e", tc.name, sb.Eps[2], expectedEps3)
		}
	}
}
