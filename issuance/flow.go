package issuance

import (
	"fmt"
	"log"

	"vSIS-Signature/PIOP"
	"vSIS-Signature/commitment"
	"vSIS-Signature/credential"
	"vSIS-Signature/ntru"
	ntrurio "vSIS-Signature/ntru/io"
	"vSIS-Signature/ntru/keys"
	"vSIS-Signature/ntru/signverify"

	"github.com/tuneinsight/lattigo/v4/ring"
)

// Inputs groups the holder's secret values for issuance.
// All polynomials are expected in coefficient form (non-NTT).
type Inputs struct {
	M1  []*ring.Poly
	M2  []*ring.Poly
	RU0 []*ring.Poly
	RU1 []*ring.Poly
	R   []*ring.Poly
}

// Challenge carries the public randomness sampled by the issuer.
// All polynomials should be in NTT form (as sampled by credential.NewIssuerChallenge).
type Challenge struct {
	RI0 []*ring.Poly
	RI1 []*ring.Poly
}

// State captures the intermediate objects derived by the holder after receiving
// the issuer challenge.
type State struct {
	Com commitment.Vector // NTT
	R0  []*ring.Poly      // coeff
	R1  []*ring.Poly      // coeff
	K0  []*ring.Poly      // coeff (carry)
	K1  []*ring.Poly      // coeff (carry)
	T   []int64           // coeff
	B   []*ring.Poly      // NTT
}

// PrepareCommit computes com = Ac·[m1||m2||RU0||RU1||R].
// Expects inputs in coefficient form; Ac is taken from params (NTT).
func PrepareCommit(p *credential.Params, in Inputs) (commitment.Vector, error) {
	log.Printf("[issuance] preparing commitment")
	if p == nil || p.RingQ == nil {
		return nil, fmt.Errorf("nil params or ring")
	}
	blocks := [][]*ring.Poly{in.M1, in.M2, in.RU0, in.RU1, in.R}
	names := []string{"M1", "M2", "RU0", "RU1", "R"}
	for i, b := range blocks {
		if len(b) == 0 {
			return nil, fmt.Errorf("missing block %s", names[i])
		}
	}
	vec := make([]*ring.Poly, 0, len(blocks))
	for _, blk := range blocks {
		ntt := p.RingQ.NewPoly()
		ring.Copy(blk[0], ntt)
		p.RingQ.NTT(ntt, ntt)
		vec = append(vec, ntt)
	}
	com, err := commitment.Commit(p.RingQ, p.Ac, vec)
	if err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	log.Printf("[issuance] commitment computed with %d outputs", len(com))
	return com, nil
}

// loadB loads the B-matrix from the configured path and lifts to NTT.
func loadB(r *ring.Ring, path string) ([]*ring.Poly, error) {
	coeffs, err := ntrurio.LoadBMatrixCoeffs(path)
	if err != nil {
		alt := []string{
			"Parameters/Bmatrix.json",
			"../Parameters/Bmatrix.json",
			"../../Parameters/Bmatrix.json",
		}
		for _, pth := range alt {
			coeffs, err = ntrurio.LoadBMatrixCoeffs(pth)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("load B: %w", err)
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

// ApplyChallenge computes R0/R1 = center(RU*+RI*), carries K0/K1, and T = HashMessage.
// Inputs RU*, R*, M1/M2 are coeff; RI* and B are public/NTT.
func ApplyChallenge(p *credential.Params, in Inputs, ch Challenge) (*State, error) {
	log.Printf("[issuance] applying issuer challenge and hashing to target")
	if p == nil || p.RingQ == nil {
		return nil, fmt.Errorf("nil params or ring")
	}
	if len(ch.RI0) == 0 || len(ch.RI1) == 0 {
		return nil, fmt.Errorf("missing RI0/RI1")
	}
	r := p.RingQ
	bound := p.BoundB
	q := int64(r.Modulus[0])

	r0 := r.NewPoly()
	r1 := r.NewPoly()
	k0 := r.NewPoly()
	k1 := r.NewPoly()
	delta := int64(2*bound + 1)

	sumCarry := func(ru, ri, rOut, kOut *ring.Poly) {
		for i := 0; i < r.N; i++ {
			ruCoeff := int64(ru.Coeffs[0][i])
			if ruCoeff > int64(q/2) {
				ruCoeff -= int64(q)
			}
			riCoeff := int64(ri.Coeffs[0][i])
			if riCoeff > int64(q/2) {
				riCoeff -= int64(q)
			}
			c := credential.CenterBounded(ruCoeff+riCoeff, bound)
			if c < 0 {
				rOut.Coeffs[0][i] = uint64(c + q)
			} else {
				rOut.Coeffs[0][i] = uint64(c)
			}
			diff := ruCoeff + riCoeff - c
			k := diff / delta
			if k < 0 {
				kOut.Coeffs[0][i] = uint64(k + q)
			} else {
				kOut.Coeffs[0][i] = uint64(k)
			}
		}
	}

	sumCarry(in.RU0[0], ch.RI0[0], r0, k0)
	sumCarry(in.RU1[0], ch.RI1[0], r1, k1)

	B, err := loadB(r, p.BPath)
	if err != nil {
		return nil, err
	}
	tCoeff, err := credential.HashMessage(r, B, in.M1[0], in.M2[0], r0, r1)
	if err != nil {
		return nil, fmt.Errorf("hash message: %w", err)
	}

	log.Printf("[issuance] derived R0/R1 and T; bound=%d delta=%d", bound, delta)
	return &State{
		R0: rPolys(r0),
		R1: rPolys(r1),
		K0: rPolys(k0),
		K1: rPolys(k1),
		T:  tCoeff,
		B:  B,
	}, nil
}

// ProvePreSign builds the credential pre-sign proof (π_t) with public T.
func ProvePreSign(p *credential.Params, ch Challenge, com commitment.Vector, in Inputs, st *State, opts PIOP.SimOpts) (*PIOP.Proof, error) {
	log.Printf("[issuance] building pre-sign proof (credential mode)")
	if p == nil || p.RingQ == nil {
		return nil, fmt.Errorf("nil params or ring")
	}
	pub := PIOP.PublicInputs{
		Com:    com,
		RI0:    ch.RI0,
		RI1:    ch.RI1,
		Ac:     p.Ac,
		B:      st.B,
		T:      st.T,
		BoundB: p.BoundB,
	}
	wit := PIOP.WitnessInputs{
		M1:  in.M1,
		M2:  in.M2,
		RU0: in.RU0,
		RU1: in.RU1,
		R:   in.R,
		R0:  st.R0,
		R1:  st.R1,
		K0:  st.K0,
		K1:  st.K1,
	}
	opts.Credential = true
	if opts.Theta == 0 {
		opts.Theta = 2
	}
	if opts.NCols == 0 {
		opts.NCols = p.RingQ.N
	}
	builder := PIOP.NewCredentialBuilder(opts)
	proof, err := builder.Build(pub, wit, PIOP.MaskConfig{})
	if err != nil {
		return nil, fmt.Errorf("build proof: %w", err)
	}
	log.Printf("[issuance] pre-sign proof built (Fpar=%d, Fagg=%d)", len(proof.FparNTT), len(proof.FaggNTT))
	return proof, nil
}

// VerifyPreSign verifies the credential pre-sign proof (π_t) with public T.
func VerifyPreSign(p *credential.Params, ch Challenge, com commitment.Vector, st *State, proof *PIOP.Proof, opts PIOP.SimOpts) (bool, error) {
	log.Printf("[issuance] verifying pre-sign proof")
	if p == nil || p.RingQ == nil {
		return false, fmt.Errorf("nil params or ring")
	}
	pub := PIOP.PublicInputs{
		Com:    com,
		RI0:    ch.RI0,
		RI1:    ch.RI1,
		Ac:     p.Ac,
		B:      st.B,
		T:      st.T,
		BoundB: p.BoundB,
	}
	opts.Credential = true
	builder := PIOP.NewCredentialBuilder(opts)
	ok, err := builder.Verify(pub, proof)
	if err != nil {
		return false, fmt.Errorf("verify: %w", err)
	}
	return ok, nil
}

// SignTargetAndSave signs the provided target coefficients using the stored
// NTRU trapdoor and persists the signature to ./ntru_keys/signature.json.
// maxTrials/opts let callers tune the sampler; defaults are applied when zero.
func SignTargetAndSave(t []int64, maxTrials int, opts ntru.SamplerOpts) (*keys.Signature, error) {
	log.Printf("[issuance] signing target (len=%d) with NTRU trapdoor", len(t))
	if maxTrials == 0 {
		maxTrials = 2048
	}
	if opts.Prec == 0 {
		opts.Prec = 256
	}
	sig, err := signverify.SignTarget(t, maxTrials, opts)
	if err != nil {
		return nil, fmt.Errorf("sign target: %w", err)
	}
	if err := keys.Save(sig); err != nil {
		return nil, fmt.Errorf("save signature: %w", err)
	}
	log.Printf("[issuance] signature saved to ./ntru_keys/signature.json (trials_used=%d rejected=%v)", sig.Signature.TrialsUsed, sig.Signature.Rejected)
	return sig, nil
}

// rPolys wraps a single poly into a slice (for WitnessInputs convenience).
func rPolys(p *ring.Poly) []*ring.Poly {
	return []*ring.Poly{p}
}
