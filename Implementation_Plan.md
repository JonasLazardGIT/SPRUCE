# Implementation Plan — SmallWood-Aligned Refactor

## 1. Objective

Rebuild the `vSIS-Signature-Scheme` proof system so that every layer (DECS, LVCS, PCS, PIOP, and the final NIZK) implements the SmallWood construction **exactly as described in Crypto’25 paper 2025-1085**. The end state must expose a single polynomial oracle \([P, M]\), a single LVCS→DECS commitment, and the four-round Fiat–Shamir transcript shown in Figures 2–7 of the paper. This document is the exhaustive implementation plan for that rebuild. *(Historical note: several tasks mention `Proof.OracleEval`—that snapshot was used temporarily while migrating to the merged layout and has since been removed in favour of deriving `VTargets`/`BarSets` directly from the DECS opening.)*

---

## 2. Paper Distillation (what we must reproduce)

| Paper Section | Key Requirement | Implementation Consequence |
|---------------|-----------------|----------------------------|
| §4.1 / Fig. 2 | LVCS commits a matrix \(A\) once via DECS; every row polynomial has degree ≤ \(n_{\text{cols}} + \ell - 1\); random tails \(\bar r_j\) are sampled during commit. | `LVCS/` must expose a single `CommitInitWithParams` that interpolates rows, stores the interpolants, and returns a DECS prover+verifier state. No secondary commitments. |
| §4.2 / Fig. 3 | PCS arranges each polynomial’s coefficients as LVCS rows (possibly chunked); evaluations are obtained via LVCS linear maps plus the single DECS opening. | `PIOP/` builders must construct one global LVCS matrix containing both witness rows \(P\) and mask rows \(M\). Evaluations requested later must be served from this commitment. |
| Protocol 6 (Fig. 6) | PIOP publishes oracle \([P, M]\); verifier sends Γ′, γ′; prover returns \(Q_i(X)=M_i(X)+\sum Γ′·F + \sum γ′·F′\); verifier samples evaluation set \(E′\), checks Eq. (4) and Eq. (7). | Reorder pipeline so that Mi are sampled **before** the second FS round, independent of Γ′. Ensure Eq. (4) and Eq. (7) are checked from data pulled out of the single LVCS opening. |
| §5 / Fig. 7 | Four Fiat–Shamir rounds: h1 binds DECS root; h2 binds Γ′/γ′; h3 binds Q; h4 binds evaluation queries (E′, coeff matrices, LVCS answers). The same data must be verified verbatim. | `PIOP/run.go` and `VerifyNIZK.go` must match the FS schedule exactly (hash inputs, counters, grinding). Each transcript component must be serialised exactly once. |
| Appendix A §A.1 | Zero-knowledge sources: witness tails, LVCS masks, DECS nonce tapes, PCS evaluation randomness, mask polynomials with zero sum on Ω. | Every randomness source must remain or be reintroduced; API may need to accept explicit randomness in tests. |
| Eq. (3)/(4)/(7) | Degree bounds \(d_Q\), Eq. (4) linear combination, Eq. (7) zero-sum constraint. | Degree accounting must be recalculated after every refactor; Eq. (4) verification must compare against the oracle fetched from the LVCS commitment; Eq. (7) must be checked explicitly. |

---

## 3. Present Code vs Paper — Gap Analysis

| Area | Current Implementation | Paper Requirement | Resulting Work |
|------|------------------------|-------------------|----------------|
| LVCS interface | `CommitInitWithParams` accepts raw `[][]uint64`; `CommitMasks` builds an extra DECS tree. | Single matrix with logical row layout; no second commitment. | Replace row input API; remove `CommitMasks`; store layout metadata. |
| Merkle roots | `Proof` carries `Root` and `MRoot`, each with its own opening. | Exactly one root (DECS) suffices. | Remove mask root/opening; restructure transcript. |
| Mask generation | `BuildMaskPolynomials` depends on Γ′/γ′ after FS round 2. | Mi sampled before Γ′ (subject only to ΣΩ Mi = 0). | Redesign mask builder to be Γ′-independent; recompute zero-sum condition elsewhere. |
| Oracle responses | Masks are opened via dedicated commitment; witness via LVCS. | Single oracle \([P, M]\) served by LVCS. | New `OracleResponses` matrix storing evaluations for both families; restructure evaluation logic. |
| Fiat–Shamir inputs | Additional data (mask root, trimmed MR polys) hashed; counters partly align but include legacy fields. | Hash inputs must match Fig. 7 exactly. | Reorder transcript assembly; drop legacy fields; introduce grind bits per round. |
| Verifier | `VerifyNIZK` replays two LVCS calls and a separate DECS verify for masks. | Single LVCS verification; Eq. (4) derived from oracle evaluations; Eq. (7) enforced. | Rewrite verifier flow; new helpers for decoding oracle; adapt Eq. (4)/Eq. (7) checks. |
| Docs | `docs/piop.md`, `docs/lvcs.md`, `docs/decs.md` describe two-tree structure. | Documentation must track SmallWood flow. | Rewrite documentation after refactor. |

---

## 4. Refactor Phases

### Phase 0 — Research & Parameter Crosswalk

1. **Parameter audit**: Produce a spreadsheet mapping paper notation \((s, \ell, \ell′, n_{\text{cols}}, \eta, \rho, d_Q, d, d′, m_1, m_2, \theta)\) to code variables in `PIOP/run.go` and config files.  
   - Deliverable: `Notes/param-crosswalk.md`.
2. **Figure reproduction**: Extract Fig. 2–7 equations (LVCS, PCS, PIOP, FS) into machine-readable markdown for quick reference.  
   - Deliverable: `docs/SmallWood-notes.md`.
3. **Test vector capture**: Run existing simulation on a small instance, save witness/oracle transcripts for regression once refactor completes.  
   - Deliverable: JSON fixtures under `_logs/pre-refactor/`.

### Phase 1 — LVCS Core Overhaul

1. **API redesign (LVCS)**  
   - Introduce `RowInput` {Head []uint64, Tail []uint64} and `OracleLayout` {Witness, Mask}.  
   - Update `CommitInitWithParams` signature to consume `[]RowInput`.  
   - Sample random tails iff `Tail == nil`.  
   - Store interpolants (`RowPolys`) and layout in `ProverKey`.
2. **Remove secondary DECS commitment**  
   - Delete `CommitMasks` + dependents, adjust tests.  
   - Ensure `MaskPolys` in `ProverKey` still surfaces internal DECS masks for Eq. (4) checks.
3. **Evaluation helpers**  
   - Add `EvalOracle(points []uint64, layout OracleLayout)` returning matrices for witness/mask rows.  
   - Extend `VerifierState` with `SetLayout`.
4. **Tests**  
   - Update `LVCS/lvcs_test.go` to use new API: deterministic tails, layout-based evaluation.  
   - Add new tests for `EvalOracle`, verifying zero knowledge when tails provided.

### Phase 2 — PCS Data Layout & Oracle Packaging *(refined sub-phasing)*

> **Goal:** migrate the PCS/proof schema onto the unified LVCS oracle without breaking verification mid-stream. Work through the following checkpoints sequentially; run `go test ./PIOP` after each sub-phase.

**Phase 2A – Data-model scaffolding (no behaviour change)** *(✅ completed: proof structs + snapshots carry placeholder layout/oracle fields)*  
1. **(DONE)** Add `MaskRowOffset`, `MaskRowCount`, `MaskDegreeBound`, and (legacy) `OracleEval` (with placeholder zero values) to `Proof`, `ProofSnapshot`, and associated helper structs. While touching these structs, pre-create slots for data that Phase 3 will need (`Gamma`, `GammaPrime`, `GammaAgg`, per-round counters) so we avoid repeated churn later. *(Update: the `OracleEval` payload was retired once the merged DECS opening fully replaced the explicit Ω snapshot.)*  
2. **(DONE)** Update `Snapshot()`/`Restore()` to round-trip the new fields while still serialising the legacy mask data (`MRoot`, `MRBits`, `MOpening`).  
3. **(DONE)** Emit TODOs referencing Phase 2B where the legacy fields will be removed.  
4. **(DONE)** Extend unit tests to assert that the added fields survive snapshot/restore cycles (even if still zero).  
5. **(DONE)** Document in code (comments/TODOs) how Phase 3 will start populating the new Gamma-related fields to keep reviewers aware of upcoming changes.

**Phase 2B – Dual-population of layout metadata** *(✅ completed: Flagged prover populates layout fields while legacy artefacts remain intact)*  
1. **(DONE)** In the prover pipeline (`PIOP/run.go`), populate the new layout fields (`MaskRowOffset`, etc.) using data already produced in Phase 1 while *keeping* the old mask commitment flow alive.  
2. **(DONE)** Introduce `Proof.OracleEval` and fill it alongside the current mask opening (even if not yet consumed).  
3. **(DONE)** Adjust simulation helpers/tests to expect both representations; assert that the layout metadata matches the actual LVCS matrix indices.  
4. **(DONE)** Update logging/metrics to report both old and new sizes where applicable.

**Phase 2C – Consumer migration** *(✅ completed: runtime paths prefer unified oracle data while legacy artefacts persist for replay)*  
1. **(DONE)** Refactor all internal code paths that *read* mask commitment data (Eq.(4) helpers, snapshot metrics, simulation inspection) to consume the new layout/oracle fields while still producing the legacy outputs for compatibility.  
2. **(DONE)** Once every consumer has switched, delete (or gate) the legacy reader calls to `CommitMasks` output, retaining the data structures for one more regression cycle.  
3. **(DONE)** Provide temporary adapters where necessary so the verifier still uses the old opening (Phase 4 will finish the rewrite).  
4. **(DONE)** Continue hashing legacy fields in the FS transcript until Phase 3B–3E land, so previously generated proofs remain verifiable.

**Phase 2D – Legacy removal & cleanup**  
1. Delete `MRoot`, `MRBits`, `MOpening`, `CommitMasks`, and any residual references.  
2. Simplify proof-size accounting and snapshot code to drop the mask-specific artefacts.  
3. Update docs/tests/logging to reflect the single-oracle design.  
4. Run the full `go test ./...` suite to ensure no consumers rely on the removed fields.

Completion of Phase 2D marks the milestone “M2 – PCS + Oracle restructure”.

### Phase 3 — PIOP Pipeline & Fiat–Shamir Rebuild *(feature-flag compatibility pass)*

> **Goal:** introduce the SmallWood-aligned layout while keeping the legacy transcript valid. All new behaviour lives behind a `PIOPLayoutV2` feature flag that defaults **off** until Phase 3′ completes.

**Phase 3A – Flag scaffolding & baseline capture** *(✅ completed: flag defaults off, smoke tests run both paths, docs mention `PIOP_LAYOUT_V2`)*  
1. **(DONE)** Add the `PIOPLayoutV2` toggle (CLI option + test helper) and record current proof snapshots for regression.  
2. **(DONE)** Teach `go test ./PIOP` suites to exercise both code paths (flag off/on) without duplicating fixtures.  
3. **(DONE)** Document the rollout in `Implementation_Plan.md` (and `docs/piop.md` if touched); the legacy flag has since been removed, so downstream agents rely exclusively on the merged layout.

**Phase 3B – Layout metadata plumbing (flagged)** *(✅ completed: flagged runs now populate `MaskRowOffset/Count/DegreeBound`, `simCtx` exposes layout metadata)*  
1. **(DONE)** Extend `lvcs.ProverKey`, `Proof`, and snapshots with `OracleLayout`, `MaskRowOffset/Count`, and `MaskDegreeBound`.  
2. **(DONE)** When the flag is ON, populate these fields from the existing builders; when OFF, continue emitting zero values.  
3. **(DONE)** Add smoke tests that assert layout fields round-trip only in the flagged mode.

**Phase 3C – Mask sampler groundwork (flagged)** *(✅ completed: independent mask samplers in `prover_helper.go`, flagged sims verify ΣΩ/degree)*  
1. **(DONE)** Factor mask sampling into reusable helpers (`sampleMaskCoeffs`, ΣΩ check) callable before FS hashing.  
2. **(DONE)** Keep the live prover on the legacy Γ′-dependent path when the flag is OFF; run the new helpers behind the flag only.  
3. **(DONE)** Introduce unit tests that validate ΣΩ Mi = 0 and degree ceilings using the new helpers.

**Phase 3D – Dual LVCS matrix (flagged)** *(✅ completed: Layout V2 appends independent mask rows to the LVCS oracle while keeping legacy mode byte-identical)*  
1. **(DONE)** Under the flag, append mask rows to the LVCS matrix so witness rows precede mask rows. Continue committing masks via the legacy DECS path in both modes.  
2. **(DONE)** Persist the augmented rows in `simCtx` and proof snapshots; verify row counts stay unchanged when the flag is OFF.  
3. **(DONE)** Update small-field tests to accept zero-padded coefficients for the flagged mask rows.

**Phase 3E – Regression harnesses (flagged)** *(✅ completed: delta harness, ΣΩ guards, and flag-default coverage landed in CI)*  
1. **(DONE)** Add Δ-proof assertions comparing legacy vs flagged transcripts to ensure the flag does not perturb existing outputs.  
2. **(DONE)** Harden ΣΩ/degree tests and add coverage that exercises both layouts so CI fails if invariants regress.  
3. **(DONE)** Land documentation updates describing how to run both modes; mark Phase 3 complete once CI runs both paths green.

### Phase 3′ — PIOP Pipeline & Fiat–Shamir Rebuild *(transcript migration)*

> **Goal:** flip the feature flag ON permanently, migrate each FS round to the SmallWood schedule, and delete legacy mask plumbing.

**Phase 3B′ – FS Round 1 (`h1`) migration**  
1. Introduce `fsRound(label, inputs…)` helper. **(DONE – helper landed in `PIOP/run.go`, all rounds rewired)**  
2. Recompute `h1` using only `{Root, Salt, Counter}` and persist Γ in proof/prover state; verifier replays both legacy and new storage until the flag defaults ON.

**Phase 3C′ – FS Round 2 (`h2`) & mask independence**  
1. **(DONE)** Move mask polynomial sampling ahead of `h2` for the flagged path; drop Γ′ inputs from mask builders.  
2. **(DONE)** Hash `{Root, Γ, R, χ/ζ (θ>1)}` while populating legacy hashes with zero placeholders to keep mid-flight proofs valid.  
3. **(DONE)** Add regression tests that fail if any code reads Γ′/γ′ before hashing.

**Phase 3D′ – FS Round 3 (`h3`) & Eq.(4)**  
1. Build \(Q_i\) from the unified `[P, M]` oracle data. **(DONE – flagged path now feeds `BuildQ` from unified masks, regression tightened)**  
2. Re-hash round‑3 inputs as `{Root, Γ, Γ′, ΓAgg, Q}` and remove `mRoot/mRPolys` once flagged tests pass. **(DONE – verifier now replays the round-3 transcript using `OracleEval`; flagged proofs omit the auxiliary mask commitment)**  
3. **(DONE)** Update proof-size accounting for the new serialisation.

**Phase 3E′ – FS Round 4 (`h4`) & evaluation queries**  
1. Generate evaluation descriptors keyed off the new layout and include oracle responses (`OracleEval`) in the hash. **(DONE – the prover temporarily appended `OracleEval` data to round‑4 material and the verifier replayed the same slices via `verifyMergedOracleReplay`; this machinery was later retired once we proved the merged DECS opening sufficed.)**  
2. Capture a golden transcript for the flagged path and add a verifier-side recomputation test. **(DONE – `TestVerifyNIZKSnapshotRoundTrip` tampers with oracle rows/bar sets to ensure the verifier rejects mismatched transcripts; CLI smoke tests (`pacs`, `pacs-small`) confirm end‑to‑end hashing.)**

**Phase 3F′ – Tail openings & single DECS proof**  
1. Collapse witness/mask openings into one `lvcs.EvalFinish` call; keep a compatibility shim for legacy proofs until Phase 4 finalises verification. **(DONE – flagged prover skips the standalone mask commitment and derives all mask openings through LVCS; legacy mode continues to emit MR/MOpening.)**  
2. Extend simulation tests to confirm row openings cover both witness and mask indices. **(DONE – merged-layout regressions assert `MaskRowOffset/Count`, check unified openings after snapshot restore, and cover both large- and small-field settings.)**  
3. Flip `PIOPLayoutV2` ON by default, delete legacy branches, and remove the flag. **(Default now ON; branch removal pending final cleanup.)**

### Current State & Next-Step Context

- Phase 3A–3D are now in place. The Fiat–Shamir rounds all flow through a shared `fsRound` helper, so transcript rewrites only need to update the helper.
- Layout V2 proofs now build \(Q\) from the unified `[P, M]` rows captured during LVCS commit; regression tests assert every appended mask row matches the polynomials consumed by Eq.(4).
- The merged LVCS layout is now the only supported execution mode; the legacy mask commitment path has been removed.
- `simCtx` retains both the witness rows and the appended mask rows so tests can confirm that the flagged matrix matches the sampled `maskIndependent{,K}` polynomials. Legacy runs continue to emit the witness-only layout byte-for-byte.

**Upcoming work (Phase 3E/3F focus):**

### Updated Next Steps (Post Phase 3E/3F)

1. **Retire legacy mask commitment path**  
   - Delete the `BuildMaskPolynomials`/`decs.Prover` branch used only when `!layoutV2`.  
   - Remove the legacy transcript inputs (`MRoot`, `MR`) and associated serialization helpers (`Proof.MRoot`, `Proof.MRBits`, `Proof.setMRMatrix`, etc.).  
   - Ensure `VerifyNIZK` fails when merged-oracle data is missing; the DECS mask verifier branch has been removed.  
   - Purge CLI/test fixtures that still expect the legacy commitment artefacts; regenerate baselines (e.g. `_logs` snapshots) without MR/MRoot.  
   - Ensure `ProofSnapshot` no longer serializes legacy fields; provide a migration note for any external tooling.

2. **Oracle replay robustness and diagnostics**  
   - Extend `verifyMergedOracleReplay` to return structured errors (enum or sentinel types) identifying which invariant failed (points mismatch, witness rows, mask rows). *(No longer needed after the oracle snapshot was removed, but kept here for historical completeness.)*  
   - Mirror those error codes in higher-level tests so CI surfaces clear failure messages.  
   - Add targeted tamper tests (points mismatch, permuted mask rows) in `PACS_Simulation_test.go` using the new diagnostics.  
   - Document the error taxonomy in `docs/piop.md` / `docs/lvcs.md` once stabilised.

3. **Eq.(7) / ΣΩ validation hardening**  
   - Move the ΣΩ/degree assertions from test-only helpers (`assertMaskInvariants`) into a reusable library function under `internal/smallwood` or similar.  
   - Invoke the helper from both prover (after mask sampling) and verifier (after oracle replay) to catch violations during normal execution.  
   - Add small-field regression cases that intentionally break ΣΩ or exceed the degree bound and confirm they fail before transcript hashing completes.  
   - Update the implementation plan/doc references to note the runtime checks.

4. **Snapshot/digest integrations**  
   - Enhance the digest harness to cover more fields (e.g. `FparAtE`, `FaggAtE`) and emit a machine-readable diff report (JSON) for CI pipelines.  
   - Provide a small CLI utility under `cmd/snapdiff` to compare two `ProofSnapshot` JSON dumps using the new diff logic.

5. **Documentation refresh**  
   - Rewrite `docs/piop.md`/`docs/lvcs.md` sections that still reference dual Merkle trees, replacing them with the merged-oracle narrative.  
   - Add a migration guide (`docs/Merged_Merkle.md` already created) that links from README and details how to run legacy mode via env var.  
   - Update `_logs` reporting scripts to highlight merged vs legacy size deltas and note that legacy mode is slated for removal.

6. **Phase 4 readiness checklist**  
   - Before tackling Phase 4 (full verifier rework), enumerate any remaining TODOs in `VerifyNIZK` (e.g. placeholder branches, legacy comments) and open tracking issues.  
   - Ensure the oracle replay/ΣΩ checks are robust so Phase 4 can focus on Eq.(4)/Eq.(7) error disentanglement without revisiting Phase 3 plumbing.

### Handoff Prompt for Follow-on Agent

```
You are inheriting the “Merged Merkle” rewrite of vSIS-Signature-Scheme. The codebase is already SmallWood-aligned: layout V2 is the default, a single LVCS commitment feeds both witness and mask rows, and the Fiat–Shamir transcript now hashes the merged oracle in round 4. Legacy compatibility (layout V1) still exists to unblock downstream consumers; your mandate is to remove that baggage and ensure the proof is fully non-interactive, relying solely on the unified transcript.

Current state
-------------
- Layout flag: removed. The merged LVCS commitment always executes.  
- Prover path (`PIOP/run.go`) now feeds mask data through LVCS exclusively; the standalone `decs.Prover` and `MRoot/MR` artefacts have been deleted.  
- Verifier (`PIOP/VerifyNIZK.go`) replays the merged oracle exclusively and fails fast if transcript material is missing.  
- Tests exercise the merged layout only; `assertMaskInvariants` and the merged snapshot harness cover both large- and small-field configurations without flag plumbing.  
- Docs (`docs/Merged_Merkle.md`, `docs/piop.md`) now describe the merged-only flow; legacy references persist only for historical context.

Required outcomes
-----------------
1. **Eliminate legacy mask commitment** *(✅ done)*  
   - Delete the `!layoutV2` branch in `PIOP/run.go`: stop constructing the standalone `decs.Prover`, remove `Proof.MRoot/MR`, and prune helper methods (`setMRMatrix`, `MRMatrix`, packing bits).  
   - Simplify `BuildQ` consumption so it always uses `BuildQLayout` inputs; remove `BuildQLayout.LayoutV2` toggles once only one path remains.  
   - Rip out legacy-specific fields from `Proof`, `ProofSnapshot`, serialization helpers, and size accounting.  
   - Update `PIOP/PACS_Statement.go` and any utilities that still expect `MRoot/MOpening`.  
   - Ensure `verifyMergedOracleReplay` remains the sole path in `VerifyNIZK`; the DECS mask verifier branch has been removed and proofs without oracle data now fail fast. *(Superseded by the current `verifyLVCSConstraints` flow.)*

2. **Transcript-only NIZK** *(✅ done)*  
   - Audit `VerifyNIZK` for any reliance on external randomness/state. After legacy removal, every check must be derived from `{Root, Γ, Γ′, ΓAgg, Q, \bar v, v, Tail}` (i.e., transcript material only).  
   - Review helper functions (`verifyLVCSConstraints`, `checkEq4OnTailOpen`, ΣΩ checks) to confirm they only consume transcript material.  
   - Remove flag plumbing from tests; rewrite assertions so the only supported configuration is the merged layout.

3. **Tooling & docs** *(✅ done)*  
   - Update `docs/piop.md` / `docs/lvcs.md` to drop legacy references and point to `docs/Merged_Merkle.md` for historical context.  
   - Trim `_logs` scripts and measurement code to match the single-root proof format.  
   - Regenerate any fixture JSON or measurement snapshots once the legacy path is gone.

Suggested task breakdown
------------------------
1. Remove legacy fields from structs, snapshots, and serialization.  
2. Delete legacy builder/verifier branches; refactor `BuildQ`, `verifyMergedOracleReplay`, and related helpers to assume the merged layout. *(Today the verifier no longer calls `verifyMergedOracleReplay`, but the surrounding refactor remains relevant.)*  
3. Clean up tests: drop layout toggles, ensure small-field suites only target merged mode, expand tamper coverage if needed.  
4. Refresh documentation and measurement tooling; add migration notes where appropriate.  
5. Run full validation: `go test ./...`, `go run ./cmd/ntrucli pacs-small`, `go run ./cmd/ntrucli pacs`. Document results.

Deliverables
------------
- Codebase free of `PIOP_LAYOUT_V2`, `MRoot`, `MR`, legacy mask commitment, or dual layout logic.  
- Tests and docs updated to describe and exercise only the merged LVCS oracle flow.  
- Implementation plan (this file) amended to mark Phase 2D and any relevant subtasks as complete.  
- Optional: open issues for any follow-on Phase 4 work (Eq.(4)/Eq.(7) diagnostics) discovered during cleanup.
```


### Phase 4 — Verifier & Eq. Checks

1. **LVCS verify**  
   - Instantiate `VerifierState` with layout; replay FS rounds using transcript digests.  
   - Reconstruct Γ, Γ′, ΓAgg from transcript and check `CommitStep2`.
2. **Oracle replay**  
   - Recompute \(v_k(Ω)\) and \(\bar v_k\) from the DECS masked-prefix opening using the stored coefficient matrix; compare with `Proof.VTargets`/`Proof.BarSets`.  
   - Re-evaluate \(Q_i\) at \(E′\) and ensure Eq. (4) holds using the tail opening (no Ω snapshot needed).
3. **Zero-sum check Eq. (7)**  
   - Evaluate mask and Q polynomials on Ω using stored row polynomials (first `ncols` entries) and enforce ΣΩ Qi(ω) = 0 for each i.  
   - For θ>1, convert K-limbs back to F when required.
4. **DECS opening**  
   - Use single `RowOpening` to validate both mask and witness rows at tail points; rebuild `lvcs.VerifyEval` accordingly.
5. **Eq.(7) failure diagnostics**  
   - Provide error types enumerating which constraint failed (Γ′, Eq. (4), Eq. (7), LVCS). Useful for testing.

### Phase 5 — Surrounding Infrastructure

1. **Helper modules**  
   - Add `internal/smallwood` package to encapsulate shared formulas: Eq. (3) degree computation, Ω sum check, mask sampler, etc.  
   - Provide deterministic test hooks (seeded RNG) for reproducibility.
2. **Metrics & logging**  
   - Update `_logs` aggregation scripts to reflect new proof structure.  
   - Add measurement for single `RowOpening` size vs old `MOpening`.
3. **Documentation**  
   - Rewrite `docs/decs.md`, `docs/lvcs.md`, `docs/piop.md` to mirror Fig. 2–7 order.  
   - Document new APIs (`RowInput`, `OracleLayout`, `OracleResponses`).  
   - Include FS round diagrams with input lists.
4. **User-facing README**  
   - Summarise SmallWood alignment, note removal of second Merkle root.  
   - Mention compatibility considerations (old proofs incompatible).

### Phase 6 — Validation

1. **Unit tests**  
   - `go test ./LVCS ./PIOP ./DECS` with new cases:  
     - LVCS witness+mask rows.  
     - PIOP Eq.(4)/Eq.(7) tampering rejection.  
     - Fs transcripts (invalid counters, wrong roots).  
2. **Integration**  
   - Re-enable `go test ./...` (accept updated fixtures).  
   - Provide deterministic simulation harness reproducing paper’s parameter tables.
3. **Soundness experiments**  
   - Randomly corrupt witness rows/mask rows to ensure verification fails with high probability.  
   - Compare measured ε vs \(1/|F|^\rho\) bound.
4. **Performance snapshot**  
   - Benchmark proof generation/verification across ncols ∈ {4,8,16}.  
   - Record new proof size for baseline lattice parameters (Kyber512, Dilithium).  
   - Add results to `_logs/post-refactor/*.txt`.

---

## 5. File-Level Task Breakdown

| File(s) | Tasks |
|---------|-------|
| `LVCS/lvcs_prover.go` | Redefine `CommitInitWithParams`, remove `CommitMasks`, add layout storage, `EvalOracle`, deterministic tails. |
| `LVCS/lvcs_verifier.go` | add `SetLayout`, extend `EvalStep2` to consume combined oracle openings, expose helper to compute LVCS evaluations without revealing masks. |
| `PIOP/run.go` | Major rewrite: pipeline order, FS rounds, mask sampling, `OracleEval`, single opening, new transcript fields. |
| `PIOP/VerifyNIZK.go` | Mirror paper verification steps, single opening, Eq.(4)/Eq.(7) enforcement, updated snapshot handling. |
| `PIOP/prover_helper.go` | New mask sampling routine (ΣΩ M = 0), restructure `BuildQ`, extract evaluation helpers to reuse in verifier. |
| `PIOP/*_test.go` | Update tests, add tampering tests for Eq.(4)/Eq.(7), transcript mismatch, tail mismatch. |
| `docs/*` | Document restructure, include figure references, update to single-oracle view. |
| `_logs/` scripts | Adjust proof size reporting (drop MRoot/MOpening). |
| `Implementation_Plan.md` | (this document) persisted; update as tasks complete. |

---

## 6. Risk & Mitigation

| Risk | Mitigation |
|------|------------|
| Miscomputed Eq.(4)/Eq.(7) due to coefficient ordering | Add exhaustive unit tests mirroring Protocol 6; cross-check with symbolic math in Python prototype (`scripts/check_eq4.py`). |
| Zero-knowledge regression (mask zero-sum vs random) | Derive Mi following Appendix A guidance; include tests verifying distribution of LVCS outputs remains uniform. |
| Breaking θ>1 (extension field) support | Keep multi-limb code path first-class; add dedicated tests with θ=2 verifying Eq.(4) in K. |
| Transcript incompatibility with existing proofs | Bump proof schema version; reject old proofs explicitly with descriptive error. |
| Complexity of FS reordering | Implement helper `fsRound(label string, inputs ...[]byte)` to keep call sites uniform and auditable. |

---

## 7. Deliverables & Milestones

| Milestone | Artifacts | Target |
|-----------|-----------|--------|
| M0 – Research complete | `Notes/param-crosswalk.md`, `_logs/pre-refactor/fixtures.json` | Week 1 |
| M1 – LVCS rework | Updated LVCS code + tests | Week 2 |
| M2 – PCS + Oracle restructure | `Proof` struct updated, old mask commitment removed | Week 3 |
| M3 – PIOP pipeline aligned | `run.go`, `VerifyNIZK.go` refactored, FS order validated | Week 5 |
| M4 – Documentation & metrics | Updated docs/logs, README | Week 6 |
| M5 – Validation & benchmarking | New tests, benchmark reports | Week 7 |

Progress should be tracked in the repo via TODO comments referencing these milestones and through updates to this plan.

---

## 8. Post-Refactor Actions

1. **Code audit**: schedule internal review comparing implementation against Figures 2–7 line-by-line; document deviations (if any).  
2. **External reproducibility**: publish scripts to reproduce proof sizes shown in Table 4 of the paper.  
3. **Future work**: evaluate replacing LVCS random tails with pseudorandom streams (paper remark) or integrating VOLE-friendly transcript compression.

---

## 9. References

- Thibauld Feneuil & Matthieu Rivain. *SmallWood: Hash-Based Polynomial Commitments and Zero-Knowledge Arguments for Relatively Small Instances*. Crypto 2025. (2025-1085.pdf)
- Figures 2–7, Equations (3), (4), (7) from the above.

This plan should remain in the repository root (`Implementation_Plan.md`) and be updated as tasks are completed.
