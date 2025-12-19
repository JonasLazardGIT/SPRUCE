# Credential Integration Progress and Next Steps

This document tracks what has been implemented so far to support the credential flow (Carsten §B.6) atop the existing PACS/PIOP stack, and outlines the remaining steps to reach a full post-signing NIZK between Holder and Verifier.

## Implemented (incremental changes)

### Credential parameter and helper layer
- `credential/params.go`: JSON-driven params loader for `Ac`, `BPath`, `BoundB`, block lengths, and ring construction. Validates `Ac` dimensions.
- `credential/types.go`: Structs for Holder state (`M1,M2,RU0,RU1,R`), Issuer challenge (`RI0,RI1`), transcript, and credential.
- `credential/bounds.go`: Bound/length checks over polynomials using the ring modulus to recenter coefficients.
- `credential/helpers.go`: `CenterBounded`, `CombineRandomness`, `HashMessage` (explicit hash to `t`), all kept in coeff-domain; single-poly restriction enforced.
- `credential/challenge.go`: Sampling `RI0/RI1` within `[-BoundB, BoundB]` and lifting to NTT.
- `credential/target.go`: Computes `R0/R1 = center(RU*+RI*)`, loads `B`, hashes to `T` (single-poly), returns combined target.
- `credential/commit.go`: Validates shapes/bounds and computes `com = Ac·[m1||m2||rU0||rU1||r]` via `commitment.Commit`.

### PIOP scaffolding and credential prover (current)
- `Credential` flag in `SimOpts`; PACS path untouched.
- Interfaces/validation:
  - `PublicInputs`, `WitnessInputs`, `StatementBuilder`; validation for single-poly blocks and Ac/Com shapes.
  - WitnessInputs extended with `R0/R1`, carry rows `K0/K1`, and optional `T/U`; credential row builder fixes ordering (pre: 9 witness rows, post: +U) and row layout/decs params.
- Constraint helpers: `BuildCommitConstraints`, `BuildCenterConstraints`, `BuildSignatureConstraint`, `BuildBoundConstraints`, plus simplified `BuildHashConstraints`.
- Public label binding: `BuildPublicLabels` (canonical order; T not public) + `LabelsDigest` bound into FS rounds; personalization `PACS-Credential`.
- Generic builder path (`BuildWithConstraints`) now:
  - commits credential rows, derives masking config, builds labels digest,
  - records constraint polys into proof (FparNTT/FaggNTT) and the truncated domain (NColsUsed/OmegaTrunc),
  - calls `runMaskFS` with credential personalization.
- `runMaskFS` fully extracted (FS rounds, mask/Q, evals, tail openings) and used by θ>1; credential proofs run through it.
- Verifier: `VerifyNIZK` respects LabelsDigest and omega/ncols overrides from proofs; `VerifyWithConstraints` backfills when missing.
- Tests: credential pre-sign happy path now passes end-to-end (θ=2) with commit/center/hash enforced; PACS suite remains green.
- Orchestration helper: new `issuance/flow.go` provides verbose helper functions (`PrepareCommit`, `ApplyChallenge`, `ProvePreSign`, `VerifyPreSign`) to stitch the issuance exchange (Holder→Issuer) using the tested pre-sign constraints.

### Documentation
- `docs/credentials.md`: Captures params schema, helper APIs, current restrictions (single-poly blocks), and TODOs.
- Tests added for flag survival, mask config, FS labels (with/without publics), validation helpers, and constraint helpers; credential path remains stubbed.

## Current behaviour
- Credential pre-sign proof: single NIZK that checks **commit residuals (F-par)**, **center wrap**, **hash residual** (cleared-denominator BBS identity with public `T`), **packing (m1 lower half / m2 upper half)**, and **in-circuit bounds**. Publics are FS-bound via `BuildPublicLabels` + `LabelsDigest`. `T` is a public input (`PublicInputs.T`) as in issuance; `Fagg` may be empty (pure F-par).
  - **Stage A+B (data model + center wrap):** the pre-sign witness row list includes carry rows `K0/K1` (single poly each) and the constraint set enforces the paper-form wrap equation:
    - `RU* + RI* − R* − (2B+1)·K* = 0`, with `K* ∈ {−1,0,1}` enforced by membership constraints (`B=1`).
  - **Stage C (bounds in-circuit, Option B):** membership-polynomial constraints `P_B(row)=0` are included in `FparNorm` for all bounded witness rows (plus `P_1(K*)=0` for carries), in addition to the existing Go-side scan (`BuildBoundConstraints`) as a fast precheck.
  - **Hash form:** pre-sign uses the paper-cleared denominator identity `(B3 - R1) ⊙ T = B0 + B1·(M1+M2) + B2·R0` with public `T`; abort-on-non-invertible is accepted as negligible (no explicit nonzero-denominator guard yet—documented assumption).
  - **Packing:** enforced in-circuit: `M1` must be zero on the upper half, `M2` zero on the lower half; new tamper tests flip coefficients across the split and are rejected.
  - **Masking/ΣΩ:** credential mode uses compensated masks (PACS style) so ΣΩ sums to zero on valid inputs; tampering is caught via residual constraints. `DEBUG_QK=1` logs non-zero QK evals if ΣΩ fails.
  - Core PACS prover/verifier unchanged; credential mode goes through generic builder. FS transcript uses credential personalization and embedded labels digest/domain; verify replays with overrides.
  - All PACS + credential pre-sign tests pass, including tamper cases (commit/center/hash/packing/bounds).

### Note on θ>1 (small-field) sum checks
- `VerifyNIZK` now checks the ΣΩ condition in the extension field for θ>1 proofs via `VerifyQK_QK`, using `proof.QKData` and `proof.MKData`.
- `runMaskFS` keeps the **original PACS mask sampling** for non-credential proofs (biasing the constant term so Eq.(7) holds), but switches to **independent masks** when `opts.Credential=true` so that ΣΩ becomes a meaningful audit for residual-style constraints (and tamper tests can reject inconsistent witnesses).

## Next: map witnesses/constraints for credential pre-/post-sign (from §B.6)

This section captures the detailed design for integrating credential constraints into the PIOP, pre- and post-signature.

### Witness rows (single-poly blocks)
- **Pre-sign (Holder→Issuer, §B.6 “π_t”)** (paper-faithful target):
  - Base rows: `M1, M2, RU0, RU1, R, R0, R1` (7 rows).
  - **Carry rows for center wrap**: `K0, K1` where each coefficient is in `{−1,0,1}` (2 rows). **Implemented in the data model and row ordering.**
  - **No `T` witness row**: in issuance, `t` is **public** and must be signed by the Issuer, so it must be bound as a public input.
  - Total: **9 witness rows**.
- **Post-sign (Holder→Verifier)** (later milestone):
  - Same as pre-sign, plus signature row `U` (1 row), and (optionally) an internal `T` row if we choose to keep the hash output internal in the showing proof.
  - Total: **10+ witness rows** depending on whether `T` is explicit.
Mask rows follow after these indices as usual.

### Publics
- **Pre-sign**: `Com, RI0, RI1, Ac, B, T` (+ extras sorted by label).
  - `T` is the **public target** `t` being sent to the Issuer and signed (Spruce‑And‑AC §B.6).
  - `A` is not needed pre-sign (signature constraint is post-sign).
- **Post-sign**: depends on whether we also want to re-bind to `Com` at showing time:
  - Minimal showing statement: `A, B, RI0, RI1` (+ nonce/tag later).
  - Optional: include `Com, Ac` if we want the showing proof to re-bind the credential to its issuance commitment.
Personalization: `PACS-Credential`.

### Constraint sets (intended)
- **Pre-sign (paper-faithful classification; “Option B” below)**:
  - **Commit (F-par, linear)**: `Ac·[M1||M2||RU0||RU1||R] = Com`.
  - **Center (F-par, linear)**: `RU0 + RI0 = R0 + (2B+1)·K0` and same for `1`, with `K* ∈ {−1,0,1}`.
  - **Hash (F-par, pre-sign linear)**: enforce the **cleared-denominator** BBS equation using **public `T`** (no inversion constraints; abort-on-non-invertible is acceptable as a negligible event).
  - **Message split (F-par, linear)**: enforce that `M1` is zero outside its allotted half (and padding), and `M2` is zero outside its allotted half (and padding) (see “m1/m2 packing” below).
  - **Bounds (F-par, in-circuit)**: enforce `[-B,B]` bounds on all witness rows (and `[-1,1]` on `K0/K1`).
  - **Aggregated constraints (F-agg)**: **empty** for the paper-faithful pre-sign issuance statement (unless we later choose an ℓ2/norm gadget that needs aggregation).
- **Post-sign**:
  - Add signature constraint `A·U = T` (linear), and decide whether commit constraints are re-included or not.

Degrees target (pre-sign): `d_par = 2B+1` (bounds), `d_agg = 0` (empty).

### Row layout
- Witness indices fixed as above:
  - Pre-sign: indices `0..8` (9 witness rows).
  - Post-sign: indices `0..(8+postExtra)` depending on whether `T` is explicit and whether `U` is included.
  - Mask rows appended after `maskRowOffset = witnessRowCount`.

### Public labels
- Canonical order (credential mode, enforced by `PIOP/fs_binding.go` `BuildPublicLabels`):
  - Pre-sign: `Com, RI0, RI1, Ac, B, T, extras (sorted)`.
  - Post-sign: `A, B, RI0, RI1, [Com,Ac optional], [Nonce/Tag later], extras (sorted)`.
- FS personalization: `PACS-Credential`.

### Implementation plan (next steps)
This plan is the “paper-faithful pre-sign issuance proof” (Spruce‑And‑AC §B.6) tailored to the current repo (PIOP/DECS/LVCS/PACS plumbing already refactored).

> **Option B (selected):** enforce coefficient bounds via the existing `RangeMembershipSpec`/`buildFparRangeMembership` machinery (degree `2B+1`), because our `B` is small enough.

#### Step 0 — Fix statement constants / packing conventions (one-time)
- Set `opts.NCols = 512` for credential pre-sign tests and builders, and require `opts.NCols` even.
- Define `half := opts.NCols/2 = 256` as the split point for `m = m1 || m2`.
- Interpret this as: the **message lives in the first `opts.NCols` coefficient slots** of the ring (degree-`512` message embedded in the default ring), with the remaining coefficients padded with `0`.
- Keep `pub.BoundB` equal to the same coefficient bound used elsewhere in PACS (we already thread `BoundB` through `PublicInputs`).

**Protocol-notation ↔ code mapping (updated generalized protocol)**
- Commitment matrix:
  - Paper: `A^{commit} ∈ R_q^{lencom × (lenmsg + 1 + lenrandpar0 + lenrandcom)}`
  - Code: `pub.Ac` (`[][]*ring.Poly`, NTT domain), with columns matching `vec = [M1, M2, RU0, RU1, RBar]`.
  - Current single-poly instantiation corresponds to:
    - commitment-side “message blocks”: `lenmsg = 2` (we commit to `m1` and `m2` as two blocks),
    - randomness blocks: `lenrandpar0 = 1`, `lenrandpar1 = 1` (the `+1` term is `r1^U`), `lenrandcom = 1`.
    - hash-side message input is still a **single polynomial** `M := M1 + M2` (see “Message split” below).
  - `lencom` corresponds to `len(pub.Com)` (number of commitment output rows).
- Commitment output:
  - Paper: `c` (Ajtai commitment)
  - Code: `pub.Com`
- Extra commitment blinding randomness:
  - Paper: `\bar{r} ∈ [-B,B]^{lenrandcom·N}`
  - Code: witness row `R` (we keep a single-poly restriction for now; conceptually this is `RBar`).
- Message split:
  - Paper: `m := m1 || m2`
  - Code: represent `m` as the **single** hash input polynomial `M := M1 + M2` where:
    - `M1` occupies coefficient indices `[0..half-1]`
    - `M2` occupies coefficient indices `[half..opts.NCols-1]`
    - coefficients outside `[0..opts.NCols-1]` are 0 (padding)
  - This is why we add **in-circuit packing constraints**: so `M1+M2` is a faithful encoding of concatenation.
- PRF parameters (showing phase; not used by pre-sign constraints):
  - Paper: `m2 ∈ F_q^{lenkey}`, `nonce ∈ D ⊂ F_q^{lennonce}`, `tag ∈ F_q^{lentag}`
  - Code plan: represent `(nonce, tag)` as public field-element vectors (embedded as polynomials or as public label bytes + θ-polys in constraints); PRF constraints start as identity and are later replaced by Poseidon/Hades constraints.
  - In our `NCols=512` instantiation, we set `lenkey = half = 256` (the number of `m2` slots inside the message encoding).
  - **MORE CONTEXT NEEDED**: concrete `lennonce`, `lentag` values and whether `nonce` is public or range-proved/hidden.

#### Step 1 — Make `t` public and FS-bound (mandatory for issuance)
**Goal:** align with §B.6: Holder sends `t` to Issuer; Issuer signs `t`. The NIZK must be bound to that same `t`.
- Update `PIOP/fs_binding.go`:
  - Extend `BuildPublicLabels(pub)` to include `pub.T` under the label `"T"` (encode int64s as little-endian bytes).
  - Keep ordering stable: `Com, RI0, RI1, Ac, B, T, ...extras`.
- Update validators:
  - `PIOP/credential_validate.go`: require `pub.T` (length = ring dimension) for **pre-sign** proofs.
  - Remove the “`T` internal only” assumption from credential-mode docs and tests for issuance.
**Note on protocol messaging:**
- The generalized protocol text mentions an initial proof `π_commit` on `(c, A^{commit})` which may be skippable.
- Our current plan implements the stronger “second” proof (the equivalent of `π_tag`) that already re-proves the commitment equation plus hash/bounds. We can optionally split later, but **paper-faithful issuance security** is already covered by the single proof.

#### Step 2 — Update witness model and row order (pre-sign)
**Goal:** make the witness rows match the paper’s variables and enable a paper-faithful center constraint.
- Extend `PIOP/builder_types.go` `WitnessInputs` with:
  - `K0 []*ring.Poly`, `K1 []*ring.Poly` (single-poly carry rows for center wrap).
- Update credential row mapping:
  - In `PIOP/credential_rows.go`, introduce an explicit pre-sign row order:
    - `M1, M2, RU0, RU1, R, R0, R1, K0, K1` (9 witness rows).
  - Remove the current “always include `T` as a witness row” path for pre-sign.
  - Keep post-sign row order as a separate function later (it likely includes `U` and maybe an internal `T` row).
- Update `PIOP/credential_validate.go`:
  - Require `K0/K1` in credential pre-sign mode.
  - Require `opts.NCols` to be even and ≥2 (needed by the m1/m2 split).

#### Step 3 — Implement paper-faithful constraint set builder (pre-sign, F-par only)
**Goal:** build a `ConstraintSet` where **all issuance identities are `Fpar`** (paper-faithful classification), and `Fagg` is empty.

Implement/replace `BuildCredentialConstraintSetPre` in `PIOP/credential_constraints.go`:

1) **Commit constraints** (`Ac·vec = Com`) as parallel residual polys
- Reuse the existing linear helper `BuildCommitConstraints(ringQ, pub.Ac, vec, pub.Com)`.
- Append its residual polys to `ConstraintSet.FparInt` (not `FaggInt`).
- `vec` ordering must match `Ac` columns: `[M1, M2, RU0, RU1, R]`.

2) **Center constraints** (`center(RU*+RI*) = R*`) via carry rows
- Replace `BuildCenterConstraints` (which currently recomputes `center()` in Go) with a linear wrap equation:
  - Let `Δ := 2*BoundB + 1` (mod q).
  - Enforce:
    - `RU0 + RI0 - R0 - Δ·K0 = 0`
    - `RU1 + RI1 - R1 - Δ·K1 = 0`
- Add bounds constraints on `K0/K1` with `B=1` (membership in `{−1,0,1}`).
- Keep `RI0/RI1` **public** and included in FS labels.

3) **Hash constraint** (BBS cleared denominator with public `T`)
- Implement a pre-sign hash residual helper in `PIOP/credential_constraints.go`:
  - Convert `pub.T` (coeff int64s) into an NTT poly `TNTT`.
  - Compute:
    - `num := B0 + B1 ⊙ (M1+M2) + B2 ⊙ R0`
    - `den := B3 − R1`
    - `F_hash := den ⊙ TNTT − num`
  - Append `F_hash` to `ConstraintSet.FparInt`.
- This is the §B.6 relation in “proof-friendly” form and is **linear** in the witness in pre-sign (since `T` is public).
- We accept “abort-on-non-invertible” as negligible: no explicit `den != 0` constraint is added.

4) **m1/m2 packing constraints (our design choice)**
We require: `m1` occupies the first half of coefficients, `m2` the second half, with `NCols=512` (and padding outside `[0..NCols-1]` is zero).
- Add two linear “half-zero” constraints:
  - For `M1`: coefficients `[half..ringQ.N-1]` must be 0.
  - For `M2`: coefficients `[0..half-1]` and `[NCols..ringQ.N-1]` must be 0.
- Implementation pattern (mirrors how bounds are checked in coeff domain):
  - `InvNTT(M*) → coeffs`
  - copy only the forbidden half into a new coeff poly; zero everything else
  - `NTT` back to an NTT poly residual, require it to be 0
- Append both residual polys to `ConstraintSet.FparInt`.

5) **Bounds inside the proof (Option B)**
- For each bounded row, append `P_B(row)` as an F-par polynomial using:
  - `spec := NewRangeMembershipSpec(q, int(pub.BoundB))`
  - `buildFparRangeMembership(ringQ, []*ring.Poly{row}, spec)`
- Apply this to: `M1,M2,RU0,RU1,R,R0,R1` with `B=pub.BoundB`, and to `K0,K1` with `B=1`.
- These constraints are what makes §B.6 condition (c) hold inside PACS.

Result: `ConstraintSet{ FparInt: allResidualsAndBounds, FaggInt: nil }`.

#### Step 4 — Allow empty aggregated constraint sets end-to-end
**Goal:** pre-sign is F-par-only; verifier must not require Eq.(4)/F-agg material.
- Update `PIOP/VerifyNIZK.go`:
  - Remove/relax the hard requirement `len(proof.FaggNTT) > 0`.
  - When `Fagg` is empty, skip Eq.(4) checks and any `GammaAgg`-dependent logic (treat aggregated count as 0).
- Ensure `runMaskFS` and `RunMaskingFS` already handle `len(FaggAll)==0` (they sample empty `GammaAgg` matrices and proceed).

#### Step 5 — Update pre-sign end-to-end tests and add tamper cases
**Goal:** confirm that commit/center/hash/packing/bounds constraints are all active in a single proof.
- In `tests/credential_presign_test.go` (or a new test file):
  - Build bounded `M1` with only first-half coeffs nonzero; `M2` with only second-half coeffs nonzero (then `NTT` them).
  - Sample bounded `RU0,RU1,R` and issuer `RI0/RI1`; compute `R0/R1 := center(RU*+RI*)`.
  - Compute `K0/K1` coefficientwise using `Δ=2B+1` (derive from the center wrap).
  - Compute `Com = Ac·[M1||M2||RU0||RU1||R]`.
  - Compute `T` via `credential.HashMessage` (test-generation only) and pass as **public** `pub.T`.
  - Prove + verify and assert success.
- Tamper cases (each must fail):
  - Flip one coeff of `Com` (commit fails).
  - Flip `RI0` or `RI1` (center/hash fails).
  - Flip `R0` or `R1` (center/hash fails).
  - Flip `M2` but keep `T` fixed (hash fails).
  - Bound violation: set a coeff in `M1` to `B+1` (bounds fail).
  - Packing violation: set one forbidden-half coeff of `M1` or `M2` nonzero (packing fails) — **implemented tests cover both halves**.

#### Step 6 — Plan the post-sign “showing” proof `π_show` (PRF = identity placeholder)
This aligns with the updated generalized protocol’s showing phase:
the Holder proves knowledge of `(u, m1, m2, r0, r1)` such that
`A·u = h_{m1||m2,(r0,r1)}(B)` and `tag = PRF(m2, nonce)` and bounds hold.

**What we will implement first (still after finishing pre-sign):**
- **Public inputs (showing):**
  - `nonce ∈ D ⊂ F_q^{lennonce}` (sent to verifier; later can be range-proved/hidden).
  - `tag ∈ F_q^{lentag}` (sent to verifier; stored for “not used yet”).
  - `A` (verification matrix), `B` (hash key).
  - Optional: `RI0, RI1` if we want to keep the same issuance randomness in the showing statement (depends on whether `r0/r1` are stored or re-derived).
  - Optional: `Com, Ac` if we decide the showing proof must re-bind to the issuance commitment `c` (not required by the baseline showing description).
  - **MORE CONTEXT NEEDED**: concrete `lennonce`, `lentag` values and whether nonce is public vs hidden.
  - Parameter sanity (from the generalized protocol text):
    - Require `lentag ≥ ceil(λ / log2(q))`.
    - Require `lenkey + lennonce − lentag > ceil(λ / log2(q))` to avoid a guessing attack on the truncated state.
    - With `q = 1038337 ≈ 2^20`, `ceil(128/20) = 7`, so `lentag ≥ 7` is the minimum at 128-bit security.
- **Witness rows (showing):**
  - `M1, M2` (same packing as issuance), `R0, R1` (centered randomness), signature witness `U` (the preimage vector), and internal hash output `T` (usually kept internal for unlinkability).
  - Optionally: carry rows `K0/K1` if we also want to prove `R0/R1` came from issuance randomness (`RU*` + `RI*`). In the baseline showing, we only need `R0/R1` bounded, not necessarily linked to the issuance transcript.
- **Constraints (showing):**
  - Signature constraint: `A·U = T` (linear).
  - Hash constraint: `T = h_{m1||m2,(R0,R1)}(B)` with **internal `T`** (quadratic / same cleared-denominator form but now `T` is a witness).
  - PRF constraint: `tag = PRF(m2, nonce)`.
    - **Identity placeholder** (to be replaced later): pick a deterministic linear relation and enforce it in-circuit:
      - Option 1: `tag = Tr(m2)` (requires `lentag ≤ lenkey`).
      - Option 2: `tag = Tr(m2 || nonce)` (requires defining how `nonce` is embedded/packed).
      - **MORE CONTEXT NEEDED**: choose which identity placeholder we standardize on so tests + public label ordering are stable.
    - Later: swap in Poseidon/Hades constraints by adding PRF state rows + constraint families (this is exactly why we invested in modular `ConstraintSet` + generic builder plumbing).
  - Bounds: `m1,m2,r0,r1` in `[-B,B]`; `U` in the configured signature bound (existing PACS gadgets).

**Why PRF identity is “safe” for engineering right now**
- It lets us finalize: (1) public label ordering, (2) witness row ordering, (3) how to represent nonce/tag in publics, and (4) how to attach a new constraint family.
- Upgrading to Poseidon/Hades later is mainly:
  - adding witness rows for the PRF internal state / round constants usage,
  - replacing the identity constraints with the Poseidon round constraints.
  - the FS/Merkle/masking plumbing stays unchanged.

### Tests (to add)
- Pre: happy path; tamper `Com`; tamper `RI*`/`R0`/`R1`; tamper `M2` vs hash; bound violations.
- Post: happy path with `U`; tamper `U`; tamper `M2`/`R0`/`R1`; bound violations; optionally tamper `Com` if re-binding commit.

### PRF/tag placeholder
- PRF remains identity; later plug PRF constraints as additional rows/constraints without changing the core layout.

## Next steps (implementation)

> **Note:** The “paper-faithful pre-sign issuance proof” plan is fully specified above (see “Implementation plan (next steps) — Option B”).  
> The sections below were written during earlier iterations (when `T` was treated as internal for pre-sign). They are kept for context but should be considered **legacy** until rewritten to match the updated pre-sign design and the future post-sign showing proof.

1) Finalize generic builder/verify wiring.
2) Implement `BuildCredentialConstraints` (pre/post).
3) Wire `credentialBuilder.Build/Verify` to the generic path.
4) Add end-to-end credential tests (happy/tamper/bounds).
5) Update docs (hash internal, public ordering, PRF TODO).

### Step 1: Finalize generic builder/verify wiring (detailed plan)
- **BuildWithConstraints (prover path)**:
  - Input: `PublicInputs`, `WitnessInputs`, `ConstraintSet`, `SimOpts`, `personalization` (default `PACS-Credential` if empty).
  - Load params/ring/Ω via `loadParamsAndOmega(opts)`.
  - Map `WitnessInputs` polys into a row list in the fixed order expected by the caller (credential builder will supply the order); build `RowLayout` and set `witnessRowCount`, `maskRowOffset`, `maskRowCount`.
  - Build `RowInput` slice from rows (coeff domain heads); call `commitRows` to get `root`, `pk`, and `oracleLayout`.
  - Assemble `FparAll/FaggAll` from `ConstraintSet` (NTT as needed); snapshot into proof later.
  - Derive masking config via `deriveMaskingConfig(opts, FparAll, FaggAll, omega)`; set `maskDegreeTarget/bound`.
  - Build `MaskingFSInput` (`ringQ, omega, root, pk, oracleLayout, rowLayout, rowInputs, witnessPolys, maskPolys (if pre-supplied), FparInt/FparNorm/FaggInt/FaggNorm, maskRowOffset/Count, maskDegreeTarget/Bound, personalization, ncols, decsParams`).
  - Call `runMaskFS` with that input; store `FparNTT/FaggNTT` and public labels (`BuildPublicLabels`) in the proof; return proof.
- **VerifyWithConstraints (verifier path)**:
  - Input: `proof`, `ConstraintSet`, `SimOpts`, `personalization`, `PublicInputs`.
  - Load params/ring/Ω via `loadParamsAndOmega(opts)`.
  - Rebuild `FparAll/FaggAll` from `ConstraintSet`; rebuild public labels via `BuildPublicLabels`.
  - Replay FS with the supplied personalization and labels; call (refactored) `VerifyNIZK` helper that accepts F-par/F-agg polys and personalization instead of rebuilding PACS constraints.
  - Return `okLin/okEq4/okSum` (or a combined bool).
- **PACS bridging**: keep PACS wrapper calling `BuildWithConstraints/VerifyWithConstraints` with PACS personalization and the PACS constraint set; credential builder will pass credential-specific rows/constraints.

1) **Publics/witnesses (1 poly each)**
   - Publics: `Com`, `RI0`, `RI1`, `Ac` (JSON like PACS; coeff or NTT as stored), `B`, optional `U`, PACS extras (salt/ctr/Ω).
     - **Pre-sign:** `T` must be **public** (issuer signs `t`), and must be FS-bound.
     - **Post-sign:** `T` is typically **internal** and enforced via hash/signature constraints.
   - Witness: `M1`, `M2`, `RU0`, `RU1`, `R` (one poly each); `R0/R1` derived inside the circuit.
   - Enforce length/shape validation; keep BoundB equal to PACS bound.

2) **Constraint set (all NTT except where noted)**
   - Commit residuals: `Ac·[M1||M2||RU0||RU1||R] - Com` via `BuildCommitConstraints`.
   - Center residuals: `center(RU0+RI0) - R0`, `center(RU1+RI1) - R1` via `BuildCenterConstraints` (coeff round-trip).
   - Hash residuals:
     - **Pre-sign (paper-faithful):** enforce the cleared-denominator BBS equation with **public `T`**.
     - **Post-sign (future):** reuse the “internal `T`” hash gadget (quadratic) to keep `T` hidden from the verifier.
   - Bound checks: apply PACS bound gadget (or `BuildBoundConstraints` for pre-scan) to all witness polys and to R0/R1 after center.
   - Optional signature residuals (if we include post-sign check): `A·U = T` via `BuildSignatureConstraint`.

3) **Credential builder wiring**
   - Implement `credentialBuilder.Build/Verify` to construct the F-poly list (commit + center + hash + bounds [+ sig]), derive masking config from its length, and route through the common Merkle/FS pipeline (via `BuildWithConstraints` once ready).
   - Add credential-mode FS personalization (e.g., `"PACS-Credential"`) and feed `BuildPublicLabels` output into the transcript.
   - Keep PACS path unchanged; `runCredential` should now return a proof instead of “not implemented.”

4) **Tests (tiny ring)**
   - Happy path: consistent Com/RI*/R0/R1, in-circuit hash produces T, proof verifies.
   - Tamper Com or RI* or hash inputs → verification fails.
   - Bound violation → fails.
   - Optional: include signature residual and tamper U/T.
   - Regression: PACS tests still pass (`Credential=false`).

5) **Docs**
   - Update `docs/credentials.md` once the builder is wired to clarify:
     - **Pre-sign issuance (§B.6):** `T` is public and signed.
     - **Post-sign showing:** `T` should be internal (typically), and `A·U=T` is proven in-circuit.
   - Keep PRF/tag marked TODO.

This keeps us aligned with B.6 (credential issuance proof) minus the PRF/tag. In particular, issuance treats `T` as **public**, while the future showing proof can keep `T` internal.

## Detailed implementation steps (builder + generic path)

A) **Public/witness normalization**
   - Enforce single-poly blocks: `M1, M2, RU0, RU1, R, R0, R1` (witness). Publics: `Com, RI0, RI1, Ac, B, U?` (no public T). Keep validators in `credential_validate.go` in sync.
   - Ensure Ac rows/cols match vec length; Com rows match Ac rows. Load/NTT Ac/B as PACS does if given in coeff form.

B) **Extract generic prover/verify core**
   - Factor the core prover/verify loop out of `buildSimWith` to accept explicit publics/witnesses and a custom constraint set (F-polys). Add credential-specific FS personalization (e.g., `PACS-Credential`) and use `BuildPublicLabels` ordering for FS binding/Merkle.
   - Implement `BuildWithConstraints(pub, wit, opts)` to:
     * load params/ring via existing utilities,
     * build mask polys via `MaskConfigFromOpts`,
     * Merklize masked F-polys,
     * bind publics + Merkle roots into FS with credential personalization,
     * return a `Proof`.
   - Implement the mirror verify path (reuse `VerifyNIZK` with supplied masked polys/Merkle root/personalization).

C) **Credential constraint set**
   - Build vec = concat(M1, M2, RU0, RU1, R) in NTT.
   - Commit residuals: `BuildCommitConstraints(ringQ, Ac, vec, Com)`.
   - Center residuals: `BuildCenterConstraints(ringQ, BoundB, RU0, RI0, R0)` and same for “1”.
   - Hash residuals: refactor PACS hash gadget into a helper to accept explicit polys `(B, M1, M2, R0, R1)` and emit F-par/F-agg polys, producing internal T; remove T from publics.
   - Bound checks: reuse PACS bound gadget on all witness polys (including R0/R1); if not exposed, use `BuildBoundConstraints` as a pre-scan plus any existing bound F-polys.
   - (Optional) Signature residuals: gated off for now.

D) **Credential builder implementation**
   - `credentialBuilder.Build`: validate inputs; build constraint polys (commit, center, hash, bounds); compute masking config from total F-poly count; call `BuildWithConstraints` with credential personalization; return `Proof`.
   - `credentialBuilder.Verify`: rebuild public labels; run generic verify path with the same constraint set; enforce any public-side bounds (RI*/Com) if needed.

E) **Tests**
   - Tiny-ring end-to-end credential-mode: consistent inputs → proof verifies.
   - Tamper Com or RI* or M1/M2/R0/R1 → fails; bound violation → fails.
   - Regression: PACS path still passes (`Credential=false`).

F) **Docs**
   - Update `docs/credentials.md` and this file once credential builder is wired and hash is internal; keep PRF/tag as TODO.

## Extending the constraint helper with the in-circuit hash gadget (post-sign / showing)

For the **post-sign Holder→Verifier proof**, we typically want `T` to remain **internal** (the verifier should not learn the hashed target), while still proving:
`T = HashMessage(B,M1,M2,R0,R1)` and `A·U = T`.

The steps below describe how to enforce the **internal-`T` hash gadget**.  
For the **paper-faithful pre-sign issuance proof (§B.6)**, we instead use the **cleared-denominator linear constraint with public `T`** (see the plan above).

1) Extract the hash gadget
   - Add `BuildHashConstraints(ringQ, B, m1, m2, r0, r1, tCoeff)` in `PIOP/credential_constraints.go` (or a dedicated file).
   - Mirror the PACS path in `PIOP/build_witness.go`: lift `m1‖m2`, `r0`, `r1` to NTT (copy first), call `vsishash.ComputeBBSHash(B, m, x0, x1)` to obtain `tNTT`.
   - Reuse the same constraint construction PACS uses (Aggregated + Parallel constraints that clear the rational hash denominators and bind to the T row). If a reusable builder doesn’t exist, re-extract the F-par/F-agg assembly from the existing PACS hash gadget.
   - Return F-par and F-agg slices (degree ≤2) and optionally the recomputed `t` coeffs.

2) Integrate into `BuildCredentialConstraintSetPre`
   - Require `pub.B` to be set; ensure length matches the hash gadget (B0/B1/B2/B3).
   - Call `BuildHashConstraints` with `pub.B`, witness rows `M1,M2,R0,R1`, and `wit.T` (coeffs). Append returned F-par to `FparInt` (or `FparNorm` as appropriate) and F-agg to `FaggInt`.
   - Keep bounds/center/commit as-is; update the helper comment to note hash is now enforced.

3) Builder/verify wiring
   - Ensure `credentialBuilder.Build/Verify` supplies `B` in publics and uses the updated constraint set. Remove any reliance on public T.
   - Snapshot full constraint polys into `proof.FparNTT/FaggNTT` (already done in `BuildWithConstraints`).

4) Tests
   - Tiny-ring happy path: compute `T` via `HashMessage`, build proof, verify.
   - Tamper `M2` or `R0/R1` while keeping `T` fixed → verification fails (hash constraints active).
