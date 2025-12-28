package PIOP

import "testing"

const (
	linfChainWindowBits = 4
	linfChainDigits     = 5
)

func parallelConstraintDegree(spec *LinfSpec, rm *RangeMembershipSpec) int {
	d := 2 // product and magnitude constraints
	if spec != nil {
		for _, coeffs := range spec.PDi {
			if coeffs == nil {
				continue
			}
			deg := maxDegreeFromCoeffs(coeffs)
			if deg > d {
				d = deg
			}
		}
	}
	if rm != nil && rm.Coeffs != nil {
		if deg := maxDegreeFromCoeffs(rm.Coeffs); deg > d {
			d = deg
		}
	}
	return d
}

func aggregatedConstraintDegree() int {
	return 1
}

func buildSim(t *testing.T) (*simCtx, bool, bool, bool) {
	return buildSimWith(t, defaultSimOpts())
}
