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

### PIOP scaffolding for credential mode (current)
- `Credential` flag in `SimOpts`; PACS still runs via `runPACS`.
- Builder-oriented pieces:
  - `PublicInputs`, `WitnessInputs`, `StatementBuilder` interface.
  - `MaskConfig/MaskConfigFromOpts`.
  - Constraint helpers (`BuildCommitConstraints`, `BuildCenterConstraints`, `BuildSignatureConstraint`, `BuildBoundConstraints`).
  - Deterministic FS public-label builder (`BuildPublicLabels`) with tests; T not public.
  - `pacsBuilder` wraps the existing PACS prover/verifier; `credentialBuilder` stub remains.
  - Validation helpers for credential publics/witnesses (single-poly blocks; shape checks for Ac/Com).
  - WitnessInputs extended with R0/R1/T/U slots for credential flow; credential row builder (`buildCredentialRows`) wires fixed ordering (pre: 8 rows, post: 9 rows) and derives row layout/decs params.
  - Generic builder path (`BuildWithConstraints`) now commits credential rows, derives mask config, builds public-label digest, stores constraint polys (FparNTT/FaggNTT) into the proof, and calls `runMaskFS` with `FSModeCredential` personalization.
  - Labels are bound into the FS transcript via `LabelsDigest` (proof carries it; `runMaskFS`/`VerifyNIZK` include it in FS rounds). Deterministic ordering via `BuildPublicLabels`.
  - Masking/Merkle/FS scaffold: `runMaskFS` is fully functional (FS rounds 1–3, mask/Q, tail, openings, transcript capture) and used by θ>1 path in PACS; snapshot/restore carries tail transcript. PACS tests are green.
  - Helpers carved out of `buildSimWith`: `loadParamsAndOmega` (ring/Ω setup), `commitRows` (LVCS commit wrapper), `deriveMaskingConfig` (wired).

### Documentation
- `docs/credentials.md`: Captures params schema, helper APIs, current restrictions (single-poly blocks), and TODOs.
- Tests added for flag survival, mask config, FS labels (with/without publics), validation helpers, and constraint helpers; credential path remains stubbed.

## Current behaviour
- Core PACS prover/verifier untouched; credential mode returns “not implemented.”
- Hash-to-target remains external; no hash constraints inside the circuit yet (T is still treated as public for now, contrary to B.6 intent).
- Generic verify path (`VerifyWithConstraints`) still relies on `VerifyNIZK` and needs credential constraint sets before it can verify credential proofs end-to-end.
- Full test suite still has the pre-existing `ntru/TestSampleZVecStatistics` drift (unrelated to credential scaffolding).

## Next: map witnesses/constraints for credential pre-/post-sign (from §B.6)

This section captures the detailed design for integrating credential constraints into the PIOP, pre- and post-signature.

### Witness rows (single-poly blocks)
- Pre-sign (Holder→Issuer): `M1, M2, RU0, RU1, R, R0, R1, T` (8 rows).
- Post-sign (Holder→Verifier): `M1, M2, RU0, RU1, R, R0, R1, T, U` (9 rows).
Mask rows follow after these indices as usual.

### Publics
- Always: `Com, RI0, RI1, Ac, A, B`; extras sorted by label. `T` is internal (never public).
- Post-sign may include `U` only if exposed; otherwise signature is checked internally (`A·U = T`).
Personalization: `PACS-Credential`.

### Constraint sets
- **Bounds (F-par)**: membership in [-B,B] for all witness rows (pre: 8; post: 9). Degree = 2B+1.
- **Center (F-par)**: `RU0+RI0 = R0 + K0·(2B+1)`, `RU1+RI1 = R1 + K1·(2B+1)` via `BuildCenterConstraints`; degree ≤2.
- **Hash (F-par + F-agg)**: reuse PACS hash gadget to enforce `T = HashMessage(B,M1,M2,R0,R1)` internally; degree ≤2. Feed explicit polys (mirror `BuildWitnessFromDisk` into `vsishash.ComputeBBSHash`).
- **Commit (F-agg, pre-sign only)**: `Ac·[M1||M2||RU0||RU1||R] = Com` via `BuildCommitConstraints`; degree 1.
- **Signature (F-agg, post-sign only)**: `A·U = T` via `BuildSignatureConstraint` (linear variant) or a new helper; degree 1.

Degrees: `d_par = 2B+1` (bounds dominate), `d_agg = 2` (hash or linear constraints).

### Row layout
- Witness indices fixed as above (0..7 pre, 0..8 post); mask rows appended after.
- RowLayout offsets set accordingly (witnessRowCount = 8 or 9; maskRowOffset = witnessRowCount).

### Public labels
- Canonical order: `Com, RI0, RI1, Ac, A, B, [U?], extras (sorted)`. Use `BuildPublicLabels`.
- FS personalization: `PACS-Credential`.

### Implementation plan
- **BuildCredentialConstraints(pre/post)**: assemble F-par/F-agg from helpers (bounds, center, hash, commit/signature), set `d_par/d_agg`.
- **Row/witness construction**: map input polys to rows in the fixed order; compute `T` externally via `HashMessage` and include as witness.
- **Builder wiring** (`credentialBuilder.Build/Verify`): validate shapes/bounds, load/NTT Ac/B, build constraint set, derive masking config, call `BuildWithConstraints`/`VerifyWithConstraints` with `FSModeCredential`.
- **Generic verify**: refactor `VerifyWithConstraints`/`VerifyNIZK` to accept constraint sets + personalization, and replay FS with provided public labels.

### Tests (to add)
- Pre: happy path; tamper `Com`; tamper `RI*`/`R0`/`R1`; tamper `M2` vs hash; bound violations.
- Post: happy path with `U`; tamper `U`; tamper `M2`/`R0`/`R1`; bound violations; optionally tamper `Com` if re-binding commit.

### PRF/tag placeholder
- PRF remains identity; later plug PRF constraints as additional rows/constraints without changing the core layout.

## Next steps (implementation)

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
   - Publics: `Com`, `RI0`, `RI1`, `Ac` (JSON like PACS; coeff or NTT as stored), `B`, optional `U`, PACS extras (salt/ctr/Ω). T should be *internal* (not public).
   - Witness: `M1`, `M2`, `RU0`, `RU1`, `R` (one poly each); `R0/R1` derived inside the circuit.
   - Enforce length/shape validation; keep BoundB equal to PACS bound.

2) **Constraint set (all NTT except where noted)**
   - Commit residuals: `Ac·[M1||M2||RU0||RU1||R] - Com` via `BuildCommitConstraints`.
   - Center residuals: `center(RU0+RI0) - R0`, `center(RU1+RI1) - R1` via `BuildCenterConstraints` (coeff round-trip).
   - Hash residuals: reuse existing PACS hash circuit (Aggregated/Parallel constraints in current PIOP) to enforce `T = HashMessage(B, M1, M2, R0, R1)` *inside* the circuit; T should no longer be a public input. Hook can mirror `BuildWitnessFromDisk` feeding explicit polys into `vsishash.ComputeBBSHash`.
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
   - Update `docs/credentials.md` once the builder is wired to clarify that T is no longer public, reference Spruce-And-AC §B.6, and keep PRF/tag marked TODO.

This keeps us aligned with B.6 (credential issuance proof) minus the PRF/tag, and moves the hash relation inside the NIZK instead of exposing T.

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

## Extending the constraint helper with the in-circuit hash gadget

We need `BuildCredentialConstraintSetPre` to enforce `T = HashMessage(B,M1,M2,R0,R1)` inside the circuit (no public T). Steps:

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
