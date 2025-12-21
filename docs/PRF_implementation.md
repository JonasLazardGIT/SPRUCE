# PRF Implementation Blueprint (Spruce-And-AC §B.6)

This document specifies the PRF `F` from §B.6, how to express it in Go, and how to integrate it into the credential showing proof. It is code-architecture-agnostic but assumes the existing field/ring code from the PCS/credential stack.

## 1. Definition (paper-faithful)
Parameters:
- Field: `Fq` with modulus `q` (same as PCS), `d = smallest d≥3 with gcd(d,q−1)=1`.
- Width: `t = lenkey + lennonce`.
- Rounds: `RF` external (“full”) rounds, `RP` internal (“partial”) rounds.
- MDS matrices: `ME`, `MI` (t×t, Cauchy-style per paper).
- Round constants: `cExt[RF][t]`, `cInt[RP]` (scalar).

Permutation `P`:
`P = E_RF ∘ … ∘ E_RF/2+1 ∘ I_RP ∘ … ∘ I_1 ∘ E_RF/2 ∘ … ∘ E_1`

- External round `E_i`: `state = ME * S(state + cExt[i])`, S-box on all lanes.
- Internal round `I_i`: add `cInt[i]` to lane 0, S-box lane 0 only, linear on others, then `state = MI * state`.
- S-box: `x ↦ x^d (mod q)`.

PRF `F(k, n)`:
1. `x = k || n` (len = t).
2. `y = P(x)`.
3. `z = y + x` (feed-forward).
4. Output `tag = z[:lentag]`.

## 2. Go package layout
Suggested structure:
```
prf/
  params.go      // Params struct, validation, loaders (json/embed)
  field.go       // thin adapter to existing Fq ops (add/sub/mul/powSmall)
  permute.go     // PermuteInPlace(state []Elem)
  rounds.go      // externalRound/internalRound helpers
  prf.go         // Tag(key, nonce) wrapper + feed-forward
  trace.go       // optional: round-by-round trace for witness building
  encode.go      // hex/json decode for matrices/constants
  testdata/      // KATs from Sage
  prf_test.go    // param sanity + KATs
```

### Params representation
Store (q, d, t, lenkey, lennonce, lentag, RF, RP, ME, MI, cExt, cInt) as JSON (hex coeffs) or generated Go source. Validate:
- `len(ME)=len(MI)=t`, `len(cExt)=RF`, `len(cExt[i])=t`, `len(cInt)=RP`.
- `RF` even, `lentag ≤ t`.
- `gcd(d, q−1)=1`.

### Field adapter
Reuse existing field type (preferred): expose `Add/Sub/Mul/PowSmall(d)/Zero/One/FromUint64`. Avoid allocations; precompute `d` exponentiation using square-and-multiply.

## 3. Permutation API
`PermuteInPlace(state []Elem, params *Params)`:
- Require `len(state)==t`.
- Use preallocated scratch buffers (`tmp`, `out`) to avoid allocations.
- External round: `tmp[j] = (state[j]+cExt[i][j])^d`; `state = ME*tmp`.
- Internal round: `tmp[0] = (state[0]+cInt[i])^d`; `tmp[j]=state[j] (j>0)`; `state = MI*tmp`.
- Matrix multiply: row-major ME/MI; `out[i] = Σ_j M[i][j]*tmp[j]`.

## 4. PRF API
`Tag(key, nonce []Elem, params *Params) ([]Elem, error)`:
- Enforce `len(key)=lenkey`, `len(nonce)=lennonce`.
- Build `state := append(key, nonce)`.
- `orig := copy(state)`, `PermuteInPlace(state)`, feed-forward `state[i]+=orig[i]`.
- Return `state[:lentag]`.

## 5. Trace mode (for ZK witness)
`TracePermute(x []Elem, params) [][]Elem` returning states after each round (external/internal) to populate circuit witnesses and debug mismatches. Optional but recommended.

## 6. Parameter generation (Sage → Go)
- Use `generate_params_poseidon.sage` (or equivalent) offline with chosen `q, t, RF, RP, d` to produce:
  - `ME, MI` via Cauchy construction (1/(x_i + y_j), distinct x_i,y_j).
  - Round constants `cExt, cInt`.
- Export to JSON/hex; add a Go loader (`LoadParamsFromJSON(r io.Reader)`).
- Commit test vectors: sample `(k,n)`, compute `tag` in Sage, store in `testdata/kat.json`.

## 7. Testing strategy
- **Param sanity tests**: dimensions, `RF` even, `lentag ≤ t`, `gcd(d,q−1)=1`.
- **KATs**: Compare Go `Tag` vs Sage for fixed `(k,n)`; include small-width params for fast CI.
- **Feed-forward check**: ensure `Tag` differs from raw `P(x)` (tests should fail if feed-forward removed).
- **Trace check (optional)**: compare intermediate states vs Sage trace for a small param set.

## 8. Integration plan (showing proof)
1. Add PRF package as above; choose params matching showing requirements:
   - `lenkey = len(m2 slots)` (current packing: half = 512/2 = 256 if NCols=512).
   - Choose `lennonce`, `lentag` per security (`lentag ≥ ceil(λ/log2 q)`; with q≈2^20, `lentag ≥ 7` for 128-bit).
   - Set `t = lenkey + lennonce`; fix `RF/RP` from Poseidon2 guidance (Poseidon2 spec or Sage script).
2. Add public params to repo (json or generated Go).
3. Expose `Tag(key, nonce)` for native issuance/showing code.
4. For ZK circuit:
   - Mirror the round structure (full rounds on all lanes; partial rounds on lane 0).
   - Constrain feed-forward (`z = P(x) + x`) and truncation (`tag = z[:lentag]`).
   - If nonce/tag are public, include them in `PublicInputs`; otherwise treat as witnesses and/or add range proofs on nonce.
5. Update showing transcript/public labels:
   - Add `Nonce`, `Tag` (if public) to `BuildPublicLabels` in showing mode.
   - Add PRF constraints to the credential showing `ConstraintSet` (replace identity placeholder).
6. Tests for showing:
   - Happy path: `tag = Tag(m2, nonce)` matches circuit.
   - Tamper: flip `tag`, `nonce`, or `m2` → verify fails.
   - Bounds: ensure `m2` still bounded in `[-B,B]`; nonce/tag encoding matches field layout.

## 9. Performance considerations
- t can be large (≈ lenkey+lennonce). Optimize matrix-vector multiply (row-major, no allocs).
- Precompute `d`-power with fast exponentiation; `d` small so powSmall is cheap.
- Consider embedding params as Go source for zero-copy loads; JSON is acceptable for now.

## 10. Deliverables checklist
- `prf/params.go`: Params struct + validation + loader.
- `prf/field.go`: adapter to existing Fq ops.
- `prf/permute.go`, `prf/rounds.go`: P implementation.
- `prf/prf.go`: `Tag(key, nonce)` with feed-forward/truncation.
- `prf/trace.go`: optional traces.
- `testdata/kat.json` + `prf_test.go`: sanity + KATs.
- Docs (this file) and a short README snippet pointing to the PRF package.
