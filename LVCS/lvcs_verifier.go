package lvcs

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"

	decs "vSIS-Signature/DECS"

	"github.com/tuneinsight/lattigo/v4/ring"
)

var debugLVCS = os.Getenv("DEBUG_LVCS") != ""

// VerifierState holds verifier‐side LVCS state.
type VerifierState struct {
	RingQ  *ring.Ring
	r      int
	params decs.Params
	ncols  int // tail start boundary, supplied by caller
	layout OracleLayout

	Root  [16]byte
	Gamma [][]uint64
	R     []*ring.Poly
}

// NewVerifierWithParams constructs the LVCS verifier with explicit DECS params
// and stores the caller-provided tail boundary ncols.
func NewVerifierWithParams(ringQ *ring.Ring, r int, params decs.Params, ncols int) *VerifierState {
	v := &VerifierState{RingQ: ringQ, r: r, params: params, ncols: ncols}
	v.layout = OracleLayout{
		Witness: LayoutSegment{Offset: 0, Count: r},
		Mask:    LayoutSegment{Offset: r, Count: 0},
	}
	return v
}

// CommitStep1 – §4.1 steps 1–3:
// Commit all those polynomials via DECS and record the commitment root.
func (v *VerifierState) CommitStep1(root [16]byte) [][]uint64 {
	v.Root = root
	decv := decs.NewVerifierWithParams(v.RingQ, v.r, v.params)
	v.Gamma = decv.DeriveGamma(root)
	return v.Gamma
}

// SetLayout stores the oracle layout after validating it against the expected
// number of rows r derived from the commitment.
func (v *VerifierState) SetLayout(layout OracleLayout) error {
	if err := validateLayout(v.r, layout); err != nil {
		return err
	}
	v.layout = layout
	return nil
}

// AcceptGamma allows callers to inject an explicit Γ sampled via Fiat–Shamir grinding.
func (v *VerifierState) AcceptGamma(gamma [][]uint64) {
	v.Gamma = gamma
}

// CommitStep2 stores the prover's R_k polynomials.
func (v *VerifierState) CommitStep2(R []*ring.Poly) bool {
	v.R = R
	for _, p := range R {
		// quick degree bound using coeff-form length
		if deg(p) > v.params.Degree {
			return false
		}
	}
	return true
}

// tiny local helper
func deg(p *ring.Poly) int {
	c := p.Coeffs[0]
	for i := len(c) - 1; i >= 0; i-- {
		if c[i] != 0 {
			return i
		}
	}
	return 0
}

// ChooseE – choose ℓ distinct indices on the MASKED TAIL [ncols, ncols+ℓ).
// Pass ncols := N - ℓ so E ⊆ Ω′ (the blinded coordinates), per §4.1.
func (v *VerifierState) ChooseE(ell, ncols int) []int {
	N := int(v.RingQ.N)
	if ell <= 0 || ncols < 0 || ncols+ell > N {
		return nil
	}
	tail := N - (ncols + ell)
	if tail < ell {
		return nil
	}
	E := make([]int, 0, ell)
	used := make(map[int]struct{}, ell)
	for len(E) < ell {
		x, err := rand.Int(rand.Reader, big.NewInt(int64(tail)))
		if err != nil {
			return nil
		}
		idx := int(x.Int64()) + ncols + ell
		if _, ok := used[idx]; ok {
			continue
		}
		used[idx] = struct{}{}
		E = append(E, idx)
	}
	return E
}

// EvalStep2 – §4.1 step 4:
// Verify Merkle + low-degree + linear checks, leaking only the ℓ masked positions.
func (v *VerifierState) EvalStep2(
	bar [][]uint64, // prover’s ¯v_k
	E []int, // challenge set (tail-only)
	open *decs.DECSOpening,
	C [][]uint64, // coefficient matrix
	vTargets [][]uint64, // public v_k on Ω
) bool {
	if open == nil {
		if debugLVCS {
			fmt.Println("[LVCS] FAIL: nil opening")
		}
		return false
	}
	if err := decs.EnsureMerkleDecoded(open); err != nil {
		if debugLVCS {
			fmt.Printf("[LVCS] FAIL: %v\n", err)
		}
		return false
	}
	if len(bar) == 0 || len(bar[0]) == 0 {
		if debugLVCS {
			fmt.Println("[LVCS] FAIL: empty bar")
		}
		return false
	}
	m := len(bar)
	ell := len(bar[0])
	ncols := v.ncols
	N := int(v.RingQ.N)
	maskStart := ncols
	maskEnd := ncols + ell
	if maskEnd > N {
		if debugLVCS {
			fmt.Printf("[LVCS] FAIL: mask range exceeds ring (ncols=%d ell=%d N=%d)\n", ncols, ell, N)
		}
		return false
	}
	if len(E) != ell {
		if debugLVCS {
			fmt.Printf("[LVCS] FAIL: |E|=%d != ell=%d\n", len(E), ell)
		}
		return false
	}
	tailSeen := make(map[int]struct{}, len(E))
	for _, idx := range E {
		if idx < maskEnd || idx >= N {
			if debugLVCS {
				fmt.Printf("[LVCS] FAIL: E intersects Ω ∪ Ω′ at idx=%d (ncols=%d ell=%d)\n", idx, ncols, ell)
			}
			return false
		}
		if _, dup := tailSeen[idx]; dup {
			if debugLVCS {
				fmt.Printf("[LVCS] FAIL: duplicate index %d in E\n", idx)
			}
			return false
		}
		tailSeen[idx] = struct{}{}
	}
	if len(C) != m {
		if debugLVCS {
			fmt.Println("[LVCS] FAIL: C dimension mismatch vs bar")
		}
		return false
	}
	if len(vTargets) != m {
		if debugLVCS {
			fmt.Println("[LVCS] FAIL: vTargets dimension mismatch vs bar")
		}
		return false
	}
	for k := 0; k < m; k++ {
		if len(bar[k]) != ell {
			if debugLVCS {
				fmt.Printf("[LVCS] FAIL: bar[%d] has len=%d (want %d)\n", k, len(bar[k]), ell)
			}
			return false
		}
		if len(C[k]) != v.r {
			if debugLVCS {
				fmt.Printf("[LVCS] FAIL: C[%d] has len=%d (want %d)\n", k, len(C[k]), v.r)
			}
			return false
		}
		if len(vTargets[k]) != ncols {
			if debugLVCS {
				fmt.Printf("[LVCS] FAIL: vTargets[%d] has len=%d (want %d)\n", k, len(vTargets[k]), ncols)
			}
			return false
		}
	}

	if open.EntryCount() != len(E)+ell {
		if debugLVCS {
			fmt.Printf("[LVCS] FAIL: |open.Indices|=%d (expected masked+E=%d)\n", open.EntryCount(), len(E)+ell)
		}
		return false
	}

	if err := decs.EnsureMerkleDecoded(open); err != nil {
		if debugLVCS {
			fmt.Printf("[LVCS] FAIL: EnsureMerkleDecoded: %v\n", err)
		}
		return false
	}
	maskOpen := &decs.DECSOpening{
		Indices:    make([]int, 0, ell),
		Pvals:      make([][]uint64, 0, ell),
		Mvals:      make([][]uint64, 0, ell),
		Nodes:      open.Nodes,
		PathIndex:  make([][]int, 0, ell),
		NonceSeed:  append([]byte(nil), open.NonceSeed...),
		NonceBytes: open.NonceBytes,
		R:          open.R,
		Eta:        open.Eta,
	}
	tailOpen := &decs.DECSOpening{
		Indices:    make([]int, 0, len(E)),
		Pvals:      make([][]uint64, 0, len(E)),
		Mvals:      make([][]uint64, 0, len(E)),
		Nodes:      open.Nodes,
		PathIndex:  make([][]int, 0, len(E)),
		NonceSeed:  append([]byte(nil), open.NonceSeed...),
		NonceBytes: open.NonceBytes,
		R:          open.R,
		Eta:        open.Eta,
	}
	maskSeen := make(map[int]struct{}, ell)
	tailSeenOpen := make(map[int]struct{}, len(E))
	allIdx := open.AllIndices()
	for i, idx := range allIdx {
		switch {
		case idx >= maskStart && idx < maskEnd:
			if _, dup := maskSeen[idx]; dup {
				if debugLVCS {
					fmt.Printf("[LVCS] FAIL: duplicate masked index %d in opening\n", idx)
				}
				return false
			}
			maskSeen[idx] = struct{}{}
			maskOpen.Indices = append(maskOpen.Indices, idx)
			maskOpen.Pvals = append(maskOpen.Pvals, open.Pvals[i])
			maskOpen.Mvals = append(maskOpen.Mvals, open.Mvals[i])
			maskOpen.PathIndex = append(maskOpen.PathIndex, append([]int(nil), open.PathIndex[i]...))
		case idx >= maskEnd && idx < N:
			if _, dup := tailSeenOpen[idx]; dup {
				if debugLVCS {
					fmt.Printf("[LVCS] FAIL: duplicate tail index %d in opening\n", idx)
				}
				return false
			}
			tailSeenOpen[idx] = struct{}{}
			tailOpen.Indices = append(tailOpen.Indices, idx)
			tailOpen.Pvals = append(tailOpen.Pvals, open.Pvals[i])
			tailOpen.Mvals = append(tailOpen.Mvals, open.Mvals[i])
			tailOpen.PathIndex = append(tailOpen.PathIndex, append([]int(nil), open.PathIndex[i]...))
		default:
			if debugLVCS {
				fmt.Printf("[LVCS] FAIL: opening index %d not in masked or tail region\n", idx)
			}
			return false
		}
	}
	if len(maskOpen.PathIndex) > 0 {
		maskOpen.PathDepth = len(maskOpen.PathIndex[0])
	}
	if len(tailOpen.PathIndex) > 0 {
		tailOpen.PathDepth = len(tailOpen.PathIndex[0])
	}

	if len(maskOpen.Indices) != ell {
		if debugLVCS {
			fmt.Println("[LVCS] FAIL: masked opening missing indices")
		}
		return false
	}
	if len(tailOpen.Indices) != len(E) {
		if debugLVCS {
			fmt.Println("[LVCS] FAIL: tail opening missing indices")
		}
		return false
	}
	if !equalSets(tailOpen.Indices, E) {
		if debugLVCS {
			fmt.Println("[LVCS] FAIL: tail opening indices != E")
		}
		return false
	}

	decv := decs.NewVerifierWithParams(v.RingQ, v.r, v.params)
	maskIdx := make([]int, ell)
	for i := 0; i < ell; i++ {
		maskIdx[i] = ncols + i
	}
	if !decv.VerifyEvalAt(v.Root, v.Gamma, v.R, maskOpen, maskIdx) {
		if debugLVCS {
			fmt.Println("[LVCS] FAIL: DECS.VerifyEvalAt on masked indices")
		}
		return false
	}
	if !decv.VerifyEvalAt(v.Root, v.Gamma, v.R, tailOpen, E) {
		if debugLVCS {
			fmt.Println("[LVCS] FAIL: DECS.VerifyEvalAt on tail indices")
		}
		return false
	}

	mod := v.RingQ.Modulus[0]
	for t, idx := range maskOpen.Indices {
		maskedPos := idx - ncols
		for k := 0; k < m; k++ {
			if len(maskOpen.Pvals[t]) != v.r {
				if debugLVCS {
					fmt.Printf("[LVCS] FAIL: masked Pvals length mismatch at t=%d (got %d want %d)\n", t, len(maskOpen.Pvals[t]), v.r)
				}
				return false
			}
			sum := uint64(0)
			for j := 0; j < v.r; j++ {
				sum = MulAddMod64(sum, C[k][j], maskOpen.Pvals[t][j], mod)
			}
			if sum != bar[k][maskedPos] {
				if debugLVCS {
					fmt.Printf("[LVCS] FAIL: masked linear relation mismatch at idx=%d pos=%d k=%d (sum=%d bar=%d)\n", idx, maskedPos, k, sum, bar[k][maskedPos])
				}
				return false
			}
		}
	}

	Qvals := make([]*ring.Poly, m)
	for k := 0; k < m; k++ {
		Qk, err := interpolateRow(v.RingQ, vTargets[k], bar[k], ncols, ell)
		if err != nil {
			if debugLVCS {
				fmt.Printf("[LVCS] FAIL: interpolateRow(Q_%d): %v\n", k, err)
			}
			return false
		}
		Qvals[k] = v.RingQ.NewPoly()
		v.RingQ.NTT(Qk, Qvals[k])
	}

	for t, idx := range tailOpen.Indices {
		if len(tailOpen.Pvals[t]) != v.r {
			if debugLVCS {
				fmt.Printf("[LVCS] FAIL: tail Pvals length mismatch at t=%d (got %d want %d)\n", t, len(tailOpen.Pvals[t]), v.r)
			}
			return false
		}
		for k := 0; k < m; k++ {
			lhs := Qvals[k].Coeffs[0][idx]
			rhs := uint64(0)
			for j := 0; j < v.r; j++ {
				rhs = MulAddMod64(rhs, C[k][j], tailOpen.Pvals[t][j], mod)
			}
			if lhs != rhs {
				if debugLVCS {
					fmt.Printf("[LVCS] FAIL: Q-check mismatch at idx=%d k=%d (lhs=%d rhs=%d)\n", idx, k, lhs, rhs)
				}
				return false
			}
		}
	}

	return true
}

// equalSets checks multisets equality of int slices.
func equalSets(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[int]int, len(a))
	for _, x := range a {
		seen[x]++
	}
	for _, y := range b {
		if seen[y] == 0 {
			return false
		}
		seen[y]--
	}
	return true
}
