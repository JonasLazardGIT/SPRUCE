# Proving `tag = F(m2, nonce)` inside PACS (Post‑Sign, §B.6)

This note explains how to arithmetize the PRF relation
```
tag = F(m2, nonce)
```
for the showing phase, using the SmallWood/PACS machinery already in the repo. It is protocol‑faithful to Spruce‑And‑AC §B.6 and describes the witness layout and parallel constraints you need to add. It also highlights the trade‑off between higher‑degree constraints (degree‑5 S‑box) vs. quadraticized S‑boxes.

## 1. Statement to prove
- Input width: `t = lenkey + lennonce`.
- Initial state: `x^(0) = m2 || nonce`.
- Poseidon2‑like permutation `P` with `RF` external rounds (full S‑box) and `RP` internal rounds (partial S‑box on lane 0), using matrices `ME/MI`, constants `cExt/cInt`, exponent `d` (paper rule: smallest d≥3 with gcd(d,q−1)=1; current params use d=5).
- Feed‑forward: `z = P(x^(0)) + x^(0)`.
- Output: `tag = z[:lentag]`.

The NIZK needs to show: given the hidden `m2` (already tied to the signature) and a nonce (public or private), the public `tag` equals `F(m2, nonce)` under the above permutation and feed‑forward.

## 2. Witness strategy
You must carry some permutation trace as witness; composing the whole permutation as a single polynomial is infeasible.

### Minimal, degree‑5 option (recommended to start)
- Witness rows: state at each round boundary `x^(r)` for r=1..R where `R = RF + RP`. `x^(0)` is already known (m2||nonce).
- No extra rows for S‑box outputs or feed‑forward; those are enforced directly in constraints.
- Rows can be column‑constant (same value across all s columns), which is fine for PACS.

### Quadraticized option (if you must keep max degree=2)
- Introduce intermediate rows per S‑box: `x2 = x*x`, `x4 = x2*x2`, `x5 = x4*x`.
- Greatly expands witness rows; keeps constraint degree at 2.

## 3. Parallel constraints to add (for each column k)
Let lanes be indexed `ℓ∈{1..t}` and rounds `r∈{1..R}`.

### External round r (full S‑box)
For each output lane j:
```
x^(r)_j − Σ_{ℓ} ME[j,ℓ] * (x^(r−1)_ℓ + cExt[r][ℓ])^d = 0
```
Degree: d (currently 5). Uses `ME` and `cExt[r]` from params.

### Internal round r (partial S‑box on lane 1)
Define u:
```
u1 = (x^(r−1)_1 + cInt[r])^d
uℓ = x^(r−1)_ℓ  for ℓ≥2
```
Then for each output lane j:
```
x^(r)_j − ( MI[j,1]*u1 + Σ_{ℓ≥2} MI[j,ℓ]*uℓ ) = 0
```
Degree: d on the lane‑1 term; linear elsewhere.

### Feed‑forward + tag binding
For each j in [1..lentag]:
```
x^(R)_j + x^(0)_j − tag_j^public = 0
```
This ties the public tag to the final state and the original input (feed‑forward).

### Nonce binding (policy‑dependent)
- If nonce is public: add `x^(0)_{nonce lane} − nonce^public = 0` per lane.
- If nonce is private: skip equality; later add a domain/range gadget for nonce ∈ D.

All of the above are **parallel constraints** in PACS terminology.

## 4. Parameters/constants (θ) handling
`ME/MI/cExt/cInt/d/RF/RP/lentag` are public parameters (from `prf_params.json`). Treat them as constants inside constraint evaluation; the verifier must load the same params to recompute the constraints at opened points.

## 5. Impact on PACS degrees and sizes
- Using degree‑5 S‑box raises the max parallel degree to 5, which increases `d_Q` accordingly (see Eq. (3) in 2025‑1085). Proof size/time grows but remains manageable.
- Quadraticizing keeps degree at 2 but adds many witness rows; choose based on your masking budget and degree budget.

With the paper example params (t=98, RF=8, RP=10, lentag=2), the degree‑5 option adds roughly:
- Witness rows: R·t = 18·98 = 1764 (for the trace), plus existing rows for x^(0).
- Parallel constraints: R·t + lentag ≈ 1766 (plus nonce bindings if public).

## 6. Prover-side steps to build the PRF trace
1) Build `x^(0) = m2 || nonce` (reuse existing witness slots for m2).  
2) Run a **trace mode** permutation to obtain `x^(1)..x^(R)` (extend the Go PRF package with a `Trace` helper returning round states).  
3) Fill witness rows for each round state (column‑constant is acceptable).  
4) Expose `tag` as public input; if nonce is public, expose it and add equality constraints.

## 7. Verifier-side evaluation
No special handling: the verifier already evaluates parallel constraints at the opened points. Add the PRF constraints to the constraint set, load the PRF params, and evaluate them using the opened row values `P_i(e)` and public tag/nonce. The PCS, FS, and Merkle plumbing remain unchanged.

## 8. Future add-ons
- Nonce domain/range proof (if nonce is private).  
- Trace compression (if witness size becomes a bottleneck).  
- Trace exposure in the PRF package for KATs/witness debugging.  
- Optionally, a “degree‑2” arithmetization if degree‑5 proves too expensive for your masking budget.

## 9. Quick checklist to wire this in
- [ ] Extend PRF package with a trace API (round boundary states).  
- [ ] Map `m2` witness rows to PRF key lanes; add nonce lanes (public or private).  
- [ ] Add witness rows for `x^(r)` (r=1..R) as column-constant values.  
- [ ] Add parallel constraints for external/internal rounds and tag binding.  
- [ ] If nonce is public, add equality constraints; else prepare a nonce∈D gadget.  
- [ ] Load PRF params in prover and verifier; add them to constraint evaluation.  
- [ ] Update tests: happy path, tamper tag/m2/nonce; ensure verify fails when tampered.  
- [ ] Monitor degree budget (`d_Q`) and adjust masking if using degree-5 S-box.

---

## 10. Implementation plan (repo-specific, step by step)

This section turns the above design into concrete tasks in this codebase. It assumes the credential pre-sign path is already working and that the credential showing builder will reuse the generic `BuildWithConstraints/VerifyWithConstraints` pipeline.

### A) PRF package: add trace API and param loader usage
1. Add `Trace(state []Elem, params *Params) ([][]Elem, error)` in `prf/permute.go` that returns the state after each round boundary `x^(r)` for `r=0..R` (include the initial state for convenience). Keep the exact round order and constants as in `PermuteInPlace`.
2. Add a helper to load default params: `LoadDefaultParams()` that reads `prf_params.json` from the package directory (or an embedded copy).
3. Optional: add a small helper `ConcatKeyNonce(m2, nonce []Elem)` to build `x^(0)` with length checks, to avoid duplicated length logic across callers.

### B) Witness construction for showing
4. In the credential showing builder (or a new `BuildCredentialShowing`), extend the witness model to include:
   - `Key` lanes: **aliases** to the existing `m2` witness rows (no duplication).
   - `Nonce` lanes: either public inputs (if nonce is revealed) or private witness rows (if hidden). Decide policy and add binding or range constraints accordingly.
   - `Trace` rows: one row per lane per round boundary `x^(r)` for `r=1..R`. Fill them column-constant with the values from `Trace`.
5. Keep `tag` as a public input. If nonce is public, also add `nonce` to publics; otherwise keep it in witness and plan a nonce∈D gadget later.

### C) Constraint set (credential showing mode)
6. Build PRF constraints as **parallel** constraints:
   - External rounds: for each `r` external, each lane `j`, add `x^(r)_j - Σℓ ME[j,ℓ]*(x^(r-1)_ℓ + cExt[r][ℓ])^d = 0`.
   - Internal rounds: for each `r` internal, each lane `j`, add `x^(r)_j - (MI[j,1]*(x^(r-1)_1 + cInt[r])^d + Σℓ>=2 MI[j,ℓ]*x^(r-1)_ℓ) = 0`.
   - Tag binding: for `j < lentag`, `x^(R)_j + x^(0)_j - tag_j^public = 0`.
   - Nonce binding (if public): `x^(0)_{nonce lane} - nonce^public = 0`.
7. Degrees: if using raw exponent `d=5`, set the constraint degree accordingly when computing `d_Q` in the masking config; if quadraticizing, add intermediate witness rows and replace `(^d)` with chains of multiplications (degree 2).
8. Add these constraints into the `ConstraintSet` for the showing proof, alongside the existing signature/hash/center/bounds constraints.

### D) Builder plumbing
9. In the credential showing builder, load PRF params (`LoadDefaultParams` or from a path), and feed them into the constraint builder.
10. Extend `BuildWithConstraints` caller to:
    - Add the new witness rows (trace) to the LVCS rows (columnsToRows or smallfield path if theta>1).
    - Add the new parallel constraints to the F-par list.
    - Update `BuildPublicLabels` to include `Tag` (and `Nonce` if public) in a canonical order; keep personalization string (e.g., `PACS-Credential`).
11. Ensure masking config (`deriveMaskingConfig`) reflects the new `d` and increased F-par count; adjust `rho/ellPrime` if needed for degree budget.

### E) Verifier plumbing
12. Add PRF params loading in the verifier path and pass them to the constraint evaluator for the PRF constraints.
13. Bind public inputs consistently: same public label ordering (`Com, RI*, Ac, A, B, Tag, Nonce?`), same personalization.
14. Verify should recompute PRF constraints at opened points automatically through the shared constraint evaluator; no change to PCS openings, Merkle, or FS sequencing.

### F) Tests (credential showing mode)
15. Add unit/integration tests with tiny parameters (or the default t=98 if feasible):
    - Happy path: construct `m2`, choose `nonce`, compute `tag=F(m2,nonce)` via PRF package, build proof, verify OK.
    - Tamper cases: flip `tag`, flip `m2`, flip `nonce` → verify fails (PRF constraints catch it).
    - Optional: degree-2 variant if you implement quadraticization; ensure both paths behave as expected.
16. Keep PACS/credential pre-sign tests unchanged; ensure regression stays green.

### G) Optional optimizations / future work
17. Trace compression: if witness size too large, consider fewer blinding rows or batching lanes, but preserve correctness.
18. Nonce domain proof: add a range/set gadget for `nonce ∈ D` if nonce is private.
19. Embed PRF params in Go source to avoid runtime file reads if desired.

Delivering these steps will give a full showing-mode PRF proof aligned with §B.6, ready to integrate with the signature and hash constraints already present in the credential protocol.
