# LVCS Package Documentation

## Call Flow and Paper Mapping

Section 4.1 of `docs/2025-1085.pdf` introduces the **linear-map vector commitment scheme (LVCS)** that lifts DECS commitments to authenticate linear relations. Figure 2 (“SmallWood-LVCS”) shows the prover and verifier message flow: rows are padded with random masks, committed via DECS, and later opened on a masked tail together with masked linear combinations. The Go implementation in `LVCS/` mirrors that specification via the following control flow:

- **Commit phase (paper: Fig. 2 “Prover”, steps 1–3).**
  1. `CommitInitWithParams` (`LVCS/lvcs_prover.go:55`) corresponds to steps 1–2 of the prover: it samples per-row mask vectors, interpolates each row-plus-mask tuple into a polynomial, and runs `decs.CommitInit` to obtain the Merkle root of the DECS commitment.
  2. Both parties derive the challenge matrix Γ by calling `decs.DeriveGamma`, while the prover caches the DECS state (`ProverKey`) for later openings.
  3. When ready to close the commit phase, the prover forwards Γ to `CommitFinish` (`LVCS/lvcs_prover.go:143`), which delegates to `decs.CommitStep2` to compute the masked polynomials `R_k`.
- **Oracle snapshot (paper: Fig. 3 / Protocol 6, Implementation_Plan §3F′).**
  1. `SetLayout` (`LVCS/lvcs_prover.go:279`) records how the committed rows split between witness rows `[P]` and PCS mask rows `[M]`, giving both parties the segmentation required by the single-oracle transcript in Crypto’25 paper 2025-1085.
  2. `EvalOracle` (`LVCS/lvcs_prover.go:291`) replays the committed polynomials on any caller-provided point set (the PIOP always supplies Ω) and returns `OracleResponses` whose witness/mask slices respect that layout. This helper now serves diagnostics and tests only—the PACS prover no longer serialises the snapshot, preventing Ω-evaluations of witness rows from leaving the prover.

- **Evaluation phase (paper: Fig. 2 “Eval”, steps 1–4).**
  1. For each linear query specified by coefficients `C[k][·]`, the prover computes masked sums `\bar v_k = Σ_j C[k][j]·\bar r_j` using `EvalInitMany` (`LVCS/lvcs_prover.go:167`), matching step 1 in the figure.
  2. The verifier samples a tail challenge set `E` inside the masked coordinates via `ChooseE` (`LVCS/lvcs_verifier.go:71`) and sends it to the prover (step 2).
  3. The prover replies with DECS openings for the requested indices using `EvalFinish` (`LVCS/lvcs_prover.go:196`). In practice this is invoked once for the masked prefix `[ncols, ncols+ℓ)` and once for the challenged tail set `E`; the two openings are then merged before transmission (step 3).
  4. The verifier runs `EvalStep2` (`LVCS/lvcs_verifier.go:99`): it splits the opening between masked and tail segments, verifies both via `decs.VerifyEvalAt`, checks the masked linear relations, interpolates the public linear-combination polynomials `Q_k`, and ensures that each challenged tail position satisfies `Q_k(ω^idx) = Σ_j C[k][j]·P_j(ω^idx)` (step 4 in the figure).

The remainder of this document dives into each component, detailing how the implementation realises the LVCS protocol and how it composes with DECS.

---

## 1. Overview

The LVCS package builds on DECS to authenticate linear relations between rows of a matrix `R ∈ F_q^{r×ncols}`. At commit time, each row is extended with `ℓ` random tail entries (`mask_j`) and interpolated into a polynomial evaluated over the first `ncols + ℓ` roots of unity. The prover uses DECS to commit to these polynomials (both the masked rows and the DECS masking polynomials `M_i`). During evaluation, the verifier challenges the prover on a set of tail indices `E` and asks for masked linear combinations `v_k = ⟨C[k], R⟩`. The prover reveals `\bar v_k = ⟨C[k], mask⟩` and opens the relevant DECS evaluations so the verifier can check both linear relations and low-degree constraints.

The package exposes helper routines for the PACS/PIOP layers but can also be used standalone to commit to matrices with authenticated linear queries, as outlined in Section 4.1 of the paper.

---

## 2. Prover-Side Components

### 2.1 `ProverKey`

`ProverKey` (`LVCS/lvcs_prover.go:42`) captures all prover state spanning commit and evaluation phases:

- `RingQ` – reference to the cyclotomic ring (`github.com/tuneinsight/lattigo/v4/ring`) for modulus and NTT operations.
- `DecsProver` – the underlying `decs.Prover` instance, storing the Merkle tree, NTT caches, and nonce seed.
- `RowData` – original row vectors (never sent to the verifier).
- `MaskData` – sampled mask vectors `\bar r_j`.
- `RowPolys` – NTT representations of the interpolated row polynomials, built for reuse in higher layers (PACS).
- `MaskPolys` – NTT versions of the DECS mask polynomials `M_i`, copied from the DECS prover.
- `Gamma` – the Fiat–Shamir challenge matrix Γ obtained from the DECS root.
- `Params` – the DECS parameters used (degree bound, η, nonce length).

### 2.2 `CommitInitWithParams`

This function (`LVCS/lvcs_prover.go:55`) implements the first two steps of the prover in Fig. 2:

1. **Mask sampling**: for each row, sample `ell` fresh mask entries uniformly in `[0, q)` using `crypto/rand.Int`. Basic validation ensures:
   - Each row is non-empty.
   - `ncols + ell ≤ N` (ring size), so the interpolated polynomial fits within the evaluation domain.
2. **Interpolation**: call `interpolateRow` (Section 4) to construct polynomials `P_j(X)` of degree `< ncols+ell` matching the row over the first `ncols` roots of unity and the mask over the next `ell` positions.
3. **DECS commitment**: instantiate `decs.NewProverWithParams`, execute `CommitInit`, and store the resulting root and prover state. Derive Γ using `decs.DeriveGamma(root, params.Eta, nrows, q0)`.  
4. **NTT caching**: convert the interpolated polynomials and the DECS mask polynomials into NTT form (`ringQ.NTT`) so later PACS layers can combine them without re-running interpolations.

The function returns the Merkle root and the `ProverKey`, which encapsulates all state needed for `CommitFinish`, `EvalInit`, and `EvalFinish`.

### 2.3 `SetLayout`, `OracleLayout`, and `EvalOracle`

To expose the single `[P, M]` oracle required by Protocol 6, the prover must remember how committed rows map to witness vs PCS-mask segments:

- `LayoutSegment` / `OracleLayout` (`LVCS/lvcs_prover.go:16–34`) describe contiguous row slices. `validateLayout` rejects overlaps, out-of-range offsets, and negative lengths.
- `ProverKey.SetLayout` (`LVCS/lvcs_prover.go:279`) stores the layout after a successful commit. `buildSimWith` (`PIOP/run.go:2064–2094`) calls it with `Witness = [0, witnessRowCount)` and `Mask = [maskRowOffset, maskRowOffset+maskRowCount)` so both parties agree on the merged layout described in Implementation_Plan §3F′.
- `EvalOracle` (`LVCS/lvcs_prover.go:291–348`) replays the committed polynomials at any caller-supplied point set (in practice Ω) by transforming each stored row polynomial back to coefficient form and evaluating it per point. The result is an `OracleResponses` struct containing the sampled points plus two matrices (`Witness`, `Mask`) that respect the recorded layout.

Earlier layouts serialised this structure into `Proof.OracleEval` and hashed it into Fiat–Shamir round 3. The current implementation no longer transmits these evaluations; instead, `VerifyNIZK` reconstructs the necessary linear relations directly from the merged DECS opening (masked prefix + random tail) and rejects any inconsistency between `BarSets`, `VTargets`, and the committed rows.

### 2.4 `CommitFinish`

`CommitFinish` (`LVCS/lvcs_prover.go:143`) finalises the commit phase by delegating to `DecsProver.CommitStep2`, which generates the masked polynomials `R_k` (identical to DECS.Commit step 3). The resulting slice is sent to verifiers so they can enforce degree bounds and masked relations.

### 2.5 `EvalInitMany`

`EvalInitMany` (`LVCS/lvcs_prover.go:167`) implements §4.1 step 1 for multiple queries:

- For each `EvalRequest` (coefficient vector `Coeffs`), it checks the coefficient length matches the number of committed rows.
- For every mask entry `mask_j[i]` it accumulates `Coeffs[j]·mask_j[i] (mod q)` to obtain `\bar v_k`.
- The helper `EvalInit` wraps a coefficient matrix `C` into requests and calls `EvalInitMany`.

The output is a slice of masked vectors `bar[k]`, each of length `ell`, matching the masked tail coordinates used during interpolation.

### 2.6 `EvalFinish`

`EvalFinish` (`LVCS/lvcs_prover.go:196`) is a thin wrapper around `DecsProver.EvalOpen(E)`. It returns a DECS opening for exactly the indices listed in `E`; callers usually invoke it twice (once for the masked prefix, once for the tail challenge) and merge the resulting structures (cf. `PIOP/run.go:2179`). The raw opening keeps residues and paths unpacked so numerical checks can run before optionally calling `decs.PackOpening` for serialization.

---

## 3. Verifier-Side Components

### 3.1 `VerifierState`

`VerifierState` (`LVCS/lvcs_verifier.go:16`) stores verifier context:

- `RingQ`, `r`, `params` – mirror the prover’s ring and DECS configuration.
- `ncols` – number of public coordinates per row; the masked tail begins at index `ncols`.
- `layout` – the same `OracleLayout` recorded by the prover; callers set it via `SetLayout` (`LVCS/lvcs_verifier.go:49`), allowing the verifier to interpret witness/mask slices exactly like the prover.
- `Root`, `Gamma`, `R` – commitment root, challenge matrix, and masked polynomials received from the prover.

`NewVerifierWithParams` initialises the state with a caller-provided `ncols` so the verifier knows where masked indices begin.

`SetLayout` performs the same `validateLayout` checks as the prover variant and is invoked by higher layers (e.g., `buildSimWith` in `PIOP/run.go:2064–2094`) before any evaluations are emitted. Sharing the layout is crucial for interpreting the merged DECS opening and coefficient matrix: `MaskRowOffset/Count` tell the verifier which subset of rows correspond to PCS masks when rechecking `BarSets` and interpolating the public `VTargets`.

### 3.2 `CommitStep1` and `CommitStep2`

- `CommitStep1` (`LVCS/lvcs_verifier.go:34`) records the Merkle root and re-derives Γ using `decs.NewVerifierWithParams`. This matches the verifier’s first interaction in Fig. 2 (recording the commitment and computing the challenge).
- `CommitStep2` (`LVCS/lvcs_verifier.go:48`) stores the masked polynomials `R` and enforces a coarse degree bound via `deg(p)`, ensuring all coefficients beyond `params.Degree` are zero. A stricter check happens during `EvalStep2` via DECS verification.

### 3.3 `ChooseE`

`ChooseE` (`LVCS/lvcs_verifier.go:71`) samples `ell` distinct indices from the masked tail `[ncols+ell, N)`. It ensures the sample fits within bounds and avoids duplicates. This matches Fig. 2 step 2, where the verifier selects hidden coordinates to test.

### 3.4 `EvalStep2`

`EvalStep2` (`LVCS/lvcs_verifier.go:99`) executes the full evaluation verification workflow (Fig. 2 step 4):

1. **Sanity checks**: ensure the opening is non-nil, decode packed paths via `decs.EnsureMerkleDecoded`, validate dimensions of `bar`, `C`, and `vTargets`, enforce `open.EntryCount() = ell + |E|`, and check that `E` lies entirely in the tail region with no duplicates.
2. **Split opening**: iterate over `open.AllIndices()`, partitioning indices into:
   - `maskOpen` – indices `[ncols, ncols+ell)` (masked positions).
   - `tailOpen` – indices in the tail (`≥ ncols+ell`), which must match the sampled set `E`.
3. **DECS verification**: instantiate a DECS verifier and run `VerifyEvalAt` on both subsets:
   - For `maskOpen`, the expected index set is contiguous `[ncols, ncols+ell)`.
   - For `tailOpen`, the expected indices are `E` (enforced via the `equalSets` helper).
4. **Masked linear relations**: for each masked index and query `k`, recompute `Σ_j C[k][j]·P_j(e)` using the opened `Pvals` and compare against the prover’s `bar[k]`, which should equal the masked sum `\bar v_k`.
5. **Public polynomial reconstruction**: using `interpolateRow`, rebuild each `Q_k(X)` from `vTargets[k]` (public linear combination over the prefix) and `bar[k]` (masked tail). Transform to NTT (`ringQ.NTT`) for efficient evaluation.
6. **Tail linear relations**: at each challenged tail index `e`, recompute `Σ_j C[k][j]·P_j(e)` from `tailOpen.Pvals` and ensure it matches `Q_k(e)`. This confirms the opened rows and the claimed `Q_k` align.

Any failure prints diagnostic messages when `DEBUG_LVCS` is set. The modular arithmetic relies on helpers in `LVCS/mod64.go`.

### 3.5 `AcceptGamma`

`AcceptGamma` (`LVCS/lvcs_verifier.go:43`) allows a verifier to inject a precomputed Γ (e.g., if the Fiat–Shamir transcript is handled externally). Otherwise, `CommitStep1` provides the default derivation.

---

## 4. Interpolation Mechanics

`interpolateRow` (`LVCS/Interpolate.go:10`) constructs the unique polynomial `P` of degree `< ncols+ell` satisfying:

- `P(ω^i) = row[i]` for `0 ≤ i < ncols`.
- `P(ω^(ncols+i)) = mask[i]` for `0 ≤ i < ell`.

Implementation outline:

1. **Domain points**: use the NTT of `X` to obtain `ω^i` for `i = 0..N-1`, then slice the first `m = ncols+ell` points (`xs`).
2. **Vanishing polynomial**: compute `T(X) = ∏_{j=0}^{m-1} (X - xs[j])`.
3. **Lagrange-style accumulation**:
   - For each `i`, perform synthetic division to obtain `Q_i(X) = T(X)/(X - xs[i])`.
   - Compute the denominator `denom_i = ∏_{j≠i} (xs[i] - xs[j])` and invert it modulo `q`.
   - Add `(y_i · denom_i^{-1}) · Q_i(X)` to the accumulating coefficients.
4. **Pack coefficients**: fill a new `ring.Poly` with the resulting coefficients, zeroing the remaining slots up to `N`.

This routine underpins both `CommitInitWithParams` (row interpolation) and the verifier’s reconstruction of `Q_k(X)` in `EvalStep2`.

---

## 5. Modular Arithmetic Helpers

`LVCS/mod64.go` provides constant-time helpers:

- `MulAddMod64(sum, a, b, mod)` – returns `(sum + a·b) mod mod`.
- `MulMod64(a, b, mod)` – pure multiplication modulo `mod`.
- `AddMod64(a, b, mod)` – modular addition.

These wrappers mirror the DECS verifier’s arithmetic and avoid repeated `% mod` patterns, reducing error-prone manual modulus handling when checking linear relations.

---

## 6. Testing

`lvcs_test.go` includes `TestEvalInitManyRoundTrip`, which:

1. Builds a ring and sample rows.
2. Runs `CommitInitWithParams` to obtain a prover key and commitment root.
3. Sets up a verifier, replays the commitment (`CommitStep1`, `AcceptGamma`, `CommitStep2`).
4. Calls `EvalInitMany` with sample coefficient queries.
5. Recomputes the expected masked sums directly and compares them to the function output.

This test validates the core mask-accumulation logic and ensures the prover’s masked data matches manual computation.

Additional tests in higher layers (e.g., PACS and the PIOP integration) exercise the full protocol flow, including the pattern of calling `EvalFinish`, merging openings, and running `EvalStep2`.

---

## 7. Extension Guidelines

When modifying LVCS:

1. Ensure any change to the interpolation logic keeps `interpolateRow` aligned with both the commit phase and verifier reconstruction; mismatches will break soundness.
2. Preserve the division between masked prefix `[ncols, ncols+ell)` and tail indices, as this underpins challenge selection and set-binding checks.
3. Keep an unpacked copy of any DECS opening that will be fed to `EvalStep2`; the verifier reads `Pvals`/`Mvals` directly after `EnsureMerkleDecoded`, so packed 20-bit matrices must be unpacked before the check.
4. If adding new evaluation types (e.g., field extensions via `EvalRequest.KPoint`), update both `EvalInitMany` and the verifier’s linear checks to cover new domains.
5. Maintain consistency with DECS parameters: LVCS assumes `params.Eta = ell′` (number of DECS mask polynomials) and relies on the same nonce, degree, and modulus constraints.
6. Update or add unit tests whenever modifying mask accumulation, interpolation, or verification logic to avoid regressions.

By adhering to these guidelines and cross-referencing Figure 2 in the paper, contributors can extend LVCS while preserving compatibility with the DECS commitment layer and higher-level PIOP constructions.
