package issuance

import (
	"fmt"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/credential"
	"vSIS-Signature/prf"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// ShowPRFInputs collects the minimal inputs to prove tag = PRF(m2, nonce).
type ShowPRFInputs struct {
	M1    []*ring.Poly // coeff-domain
	M2    []*ring.Poly // coeff-domain
	RU0   []*ring.Poly
	RU1   []*ring.Poly
	R     []*ring.Poly
	R0    []*ring.Poly
	R1    []*ring.Poly
	K0    []*ring.Poly
	K1    []*ring.Poly
	Nonce []int64    // coeffs (public), length = LenNonce
	Tag   []prf.Elem // optional precomputed tag; if nil, computed from params
}

// ProveShowPRF builds a PRF-only proof (tag binding) using the generic PIOP pipeline.
// It builds PRF trace states as column-constant polys and feeds BuildPRFConstraintSet.
func ProveShowPRF(p *credential.Params, in ShowPRFInputs, opts PIOP.SimOpts) (*PIOP.Proof, [][]*ring.Poly, error) {
	if p == nil || p.RingQ == nil {
		return nil, nil, fmt.Errorf("nil params or ring")
	}
	ringQ := p.RingQ
	prfParams, err := prf.LoadDefaultParams()
	if err != nil {
		return nil, nil, fmt.Errorf("load prf params: %w", err)
	}
	// Require base rows.
	if len(in.M1) == 0 || len(in.M2) == 0 || len(in.RU0) == 0 || len(in.RU1) == 0 || len(in.R) == 0 || len(in.R0) == 0 || len(in.R1) == 0 || len(in.K0) == 0 || len(in.K1) == 0 {
		return nil, nil, fmt.Errorf("missing base rows")
	}
	if len(in.Nonce) == 0 {
		return nil, nil, fmt.Errorf("missing nonce")
	}
	// Build key/nonce elems.
	key := coeffToElems(in.M2[0], prfParams.LenKey, ringQ)
	nonceElems := make([]prf.Elem, prfParams.LenNonce)
	for i := 0; i < prfParams.LenNonce && i < len(in.Nonce); i++ {
		v := in.Nonce[i]
		if v < 0 {
			v += int64(ringQ.Modulus[0])
		}
		nonceElems[i] = prf.Elem(uint64(v) % ringQ.Modulus[0])
	}
	// Compute tag if not provided.
	tag := in.Tag
	if tag == nil {
		tag, err = prf.Tag(key, nonceElems, prfParams)
		if err != nil {
			return nil, nil, fmt.Errorf("prf.Tag: %w", err)
		}
	}
	// Build trace.
	x0, err := prf.ConcatKeyNonce(key, nonceElems, prfParams)
	if err != nil {
		return nil, nil, err
	}
	trace, err := prf.Trace(x0, prfParams)
	if err != nil {
		return nil, nil, fmt.Errorf("prf.Trace: %w", err)
	}
	// Convert trace to coeff polys (column-constant).
	states := make([][]*ring.Poly, len(trace))
	for rIdx, st := range trace {
		lanes := make([]*ring.Poly, len(st))
		for j, val := range st {
			poly := ringQ.NewPoly()
			for i := 0; i < ringQ.N; i++ {
				poly.Coeffs[0][i] = uint64(val) % ringQ.Modulus[0]
			}
			lanes[j] = poly
		}
		states[rIdx] = lanes
	}
	// Tag public polys (one per lane, constant).
	tagPublic := make([][]int64, prfParams.LenTag)
	for j := 0; j < prfParams.LenTag; j++ {
		tagPublic[j] = make([]int64, ringQ.N)
		v := int64(tag[j])
		for i := 0; i < ringQ.N; i++ {
			tagPublic[j][i] = v
		}
	}
	// Nonce public lanes (lenNonce) as coeff slices.
	noncePublic := make([][]int64, prfParams.LenNonce)
	for j := 0; j < prfParams.LenNonce; j++ {
		noncePublic[j] = make([]int64, ringQ.N)
		if j < len(in.Nonce) {
			for i := 0; i < ringQ.N; i++ {
				noncePublic[j][i] = in.Nonce[j]
			}
		}
	}
	// Flatten states into a single row slice for constraint builder.
	var rows []*ring.Poly
	for _, st := range states {
		rows = append(rows, st...)
	}
	// Base rows in builder order.
	baseRows := []*ring.Poly{
		in.M1[0],
		in.M2[0],
		in.RU0[0],
		in.RU1[0],
		in.R[0],
		in.R0[0],
		in.R1[0],
		in.K0[0],
		in.K1[0],
	}
	startIdx := len(baseRows)
	rowsFull := append(append([]*ring.Poly{}, baseRows...), rows...)
	wit := PIOP.WitnessInputs{
		M1:  in.M1,
		M2:  in.M2,
		RU0: in.RU0,
		RU1: in.RU1,
		R:   in.R,
		R0:  in.R0,
		R1:  in.R1,
		K0:  in.K0,
		K1:  in.K1,
		Extras: map[string]interface{}{
			"prf_trace": rows,
		},
	}
	pub := PIOP.PublicInputs{
		BoundB: p.BoundB,
		Tag:    tagPublic,
		Nonce:  noncePublic,
	}
	cs, err := PIOP.BuildPRFConstraintSet(ringQ, prfParams, rowsFull, startIdx, tagPublic, noncePublic)
	if err != nil {
		return nil, nil, err
	}
	opts.Credential = true
	if opts.Theta <= 1 {
		opts.Theta = 2 // default to theta>1 for showing
	}
	// Build proof using generic pipeline.
	proof, err := PIOP.BuildWithConstraints(pub, wit, cs, opts, "PACS-Credential")
	if err != nil {
		return nil, nil, err
	}
	return proof, states, nil
}

// VerifyShowPRF rebuilds the same constraint set (using the provided states) and verifies.
// NOTE: This is a demo; a real verifier should not receive witness states. This mirrors the
// current constraint builder pattern where residuals are precomputed.
func VerifyShowPRF(p *credential.Params, states [][]*ring.Poly, tagPublic [][]int64, proof *PIOP.Proof, opts PIOP.SimOpts) (bool, error) {
	if p == nil || p.RingQ == nil {
		return false, fmt.Errorf("nil params or ring")
	}
	prfParams, err := prf.LoadDefaultParams()
	if err != nil {
		return false, err
	}
	var rows []*ring.Poly
	for _, st := range states {
		rows = append(rows, st...)
	}
	// startIdx is 0 because rows only contain the PRF trace here.
	cs, err := PIOP.BuildPRFConstraintSet(p.RingQ, prfParams, rows, 0, tagPublic, nil)
	if err != nil {
		return false, err
	}
	pub := PIOP.PublicInputs{
		BoundB: p.BoundB,
		Tag:    tagPublic,
	}
	opts.Credential = true
	return PIOP.VerifyWithConstraints(proof, cs, pub, opts, "PACS-Credential")
}

// coeffToElems converts a coeff poly to prf elems.
func coeffToElems(p *ring.Poly, want int, ringQ *ring.Ring) []prf.Elem {
	q := ringQ.Modulus[0]
	out := make([]prf.Elem, want)
	coeffs := p.Coeffs[0]
	for i := 0; i < want && i < len(coeffs); i++ {
		out[i] = prf.Elem(coeffs[i] % q)
	}
	return out
}
