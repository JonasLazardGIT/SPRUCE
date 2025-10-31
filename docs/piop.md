# PIOP Package Documentation – Phase 1

## Call Flow and Paper Mapping

Section 4 and Protocol 6 of `docs/2025-1085.pdf` describe how the prover turns public NTRU parameters and a signature bundle into the witness tuples `(w₁,w₂,w₃)` over the evaluation set `Ω`. The Go implementation realises this pipeline through the following entry points:

- `BuildWitnessFromDisk` → `BuildWitness` (`PIOP/build_witness.go`) reproduces Eq.(4) on concrete polynomials, checks the proof-friendly identities from the paper, and outputs the witness vectors.
- `EvalPoly`, `BuildThetaPrime`, `BuildThetaPrimeSet` (`PIOP/PACS_Statement.go`) interpolate public coefficient tables into Ω-aligned polynomials Θ′ exactly as in Fig. 2.
- `RunSimulation` (`PIOP/run.go`) orchestrates fixture loading, witness construction, Ω derivation, and row layout bookkeeping before any gadgets are appended for constraint enforcement.
- Supporting utilities in `PIOP/path.go` and `PIOP/prover_helper.go` provide filesystem indirection and field arithmetic / interpolation primitives that mirror the algebraic manipulations assumed in the paper.

The remainder of this phase documents these components in detail, focusing on witness construction and Ω before norm or PACS gadgets come into play.

---

## Witness Construction (`PIOP/build_witness.go`)

### Helper Primitives

- `zeroPoly`, `copyPoly`, `addInto`, and `mulScalarNTT` (`PIOP/build_witness.go:19`) offer light-weight wrappers over the Lattigo ring API. They keep all polynomials in NTT form, matching the paper’s assumption that all prover computations happen in the evaluation domain.
- These helpers are reused throughout witness checks and later in constraint builders; keeping them in one place avoids repeated boilerplate and ensures consistent modulo-`q` semantics.

### `BuildWitness`

`BuildWitness` (`PIOP/build_witness.go:35`) takes the public matrices `(A,b₁,B₀)` and the private tuples `(s,x₁,u,x₀)` and verifies the *proof-friendly equation* from the SmallWood paper before assembling the witness vectors:

1. **Sanity guards** enforce the expected dimensions (e.g., `A` must be 1×2, `s` has two rows). These mirror the parameter sizes in §3 of the paper.
2. **Left-hand side**: computes `(b₁ ⊙ A)·s` and `(A·s)·x₁` directly in the NTT domain (lines 61–88).
3. **Right-hand side**: evaluates `B₀(1;u;x₀)` (lines 91–114), matching Eq.(4) after lifting the message and masks into the polynomial ring.
4. **Equality check**: subtracts both sides and fails fast if any coefficient disagrees (lines 118–147). The debug dump mimics the symbolic inspection done in the paper to ensure consistency.
5. **Witness assembly**: concatenates `w₁ = (s, u, x₀)`, sets `w₂ = x₁`, and computes `w₃[i] = w₁[i]·x₁` (lines 149–170), exactly as required by the quadratic constraint gate.

The function returns `(w₁,w₂,w₃)` in NTT form, ready for interpolation onto Ω.

### `BuildWitnessFromDisk`

`BuildWitnessFromDisk` (`PIOP/build_witness.go:176`) reconstructs the witness from fixture files, matching the concrete instantiation used in simulations:

1. **Parameter loading**: uses `resolve` (documented later) to find `Parameters/Parameters.json`, then instantiates `ringQ` with `N` and `q` from the file.
2. **Fixture preparation**: `ensureNTRUFixtures` checks for keys and signatures under `./ntru_keys` and generates defaults if missing, providing a reproducible baseline (§5 of the paper relies on these fixtures for tests).
3. **Public matrix assembly**:
   - Recreates `A = [1, -h]` from `public.json`, lifting the coefficient rows into NTT form (lines 214–255).
   - Loads the `B` columns from `Bmatrix.json` and converts each to NTT (lines 258–293).
4. **Nonce/compression vector**: derives ρ-values via `utils.NewPRNG` (lines 295–303), mirroring the pseudo-randomness used in the protocol.
5. **Signature bundle**: loads `signature.json`, regenerates message `m` and masks `x₀,x₁` from their seeds, and converts them to NTT form (lines 307–365).
6. **Signature checks**: replays the BBS hash and confirms `A·s` agrees with the stored challenge `c₁` (lines 370–423). Any mismatch triggers regeneration to match the soundness assumptions from the paper.
7. **Witness**: calls `BuildWitness` with the freshly reconstructed polynomials, returning `(w₁,w₂,w₃)` as used by higher layers.

This function embodies the data-ingestion pipeline described around Fig. 2: starting from NTRU fixtures, recovering all public/private components, and validating the core equation before proceeding.

---

## Public Polynomial Interpolation (`PIOP/PACS_Statement.go`)

### `EvalPoly`

`EvalPoly` (`PIOP/PACS_Statement.go:24`) evaluates polynomials in coefficient form using Horner’s method modulo `q`. It is the workhorse for translating coefficient-domain tables into evaluation-domain values, and it underpins both Θ′ interpolation and Ω-based checks later in the protocol.

### `BuildThetaPrime`

`BuildThetaPrime` (`PIOP/PACS_Statement.go:41`) interpolates a single public coefficient column over Ω:

1. Computes coefficient-domain values on Ω by calling `Interpolate` (see below) and packs them into a new `ring.Poly`.
2. Switches the result to NTT form so it can be multiplied directly with witness polynomials.

This mirrors the construction of Θ′ in the paper, guaranteeing degree `< |Ω|` and exact agreement on all evaluation points.

### `BuildThetaPrimeSet`

`BuildThetaPrimeSet` (`PIOP/PACS_Statement.go:60`) lifts the entire set of public tables:

- Iterates over each row of `A`, `b₁`, `B₀,const`, `B₀,msg`, `B₀,rnd`.
- Invokes `EvalPoly` on coefficient-domain copies to sample their values on Ω.
- Calls `BuildThetaPrime` to obtain NTT polynomials ready for later constraint checks.

The resulting struct holds Θ′ polynomials aligned with the witness rows, exactly as required when forming the integer constraints (later phases).

---

## Simulation Bootstrap (`PIOP/run.go`)

Before any norm gadget is attached, `buildSimWith` (invoked by `RunSimulation`) performs several preparatory steps:

1. **Witness reuse**: if fixtures are available, `BuildWitnessFromDisk` populates `(w₁,w₂,w₃)` (line 941). Optionally, tests can mutate these rows via `SimOpts.Mutate`.
2. **Ω derivation**: constructs `P(X)=X`, runs an NTT, and copies the first `ncols` points to form `omega` (`PIOP/run.go:1008`). This directly matches the paper’s definition of Ω as the first s roots of unity in the evaluation domain.
3. **Row layout metadata**: the `RowLayout` struct (`PIOP/run.go:1706`) records how `w₁` is partitioned into signature, message, and randomness rows so verifiers can later reconstruct per-row values. At this stage `SigCount`, `MsgCount`, and `RndCount` are set; gadget offsets are filled in subsequent phases.
4. **Message/randomness re-interpolation**: for each constant message or randomness row, the code rebuilds an Ω-aligned polynomial using `buildValueRow` (lines 1678–1701). This ensures every row of `w₁` is a degree-`<|Ω|+ℓ` polynomial with fresh blinding, as mandated by Protocol 6.
5. **Product witness refresh**: recalculates `w₃[i] = w₁[i]·w₂` after the re-interpolation (lines 1703–1705), keeping the quadratic relation intact.

These preparatory steps complete the “witness construction from inputs” stage before norm gadgets and PACS batching enlarge the system.

---

## Supporting Utilities

### Filesystem Resolution

`resolve` (`PIOP/path.go:5`) first tests the provided path relative to the current working directory, then falls back to `..`. This allows simulations and tests to run either from the repo root or inside `PIOP/` without patching file paths.

### Field Arithmetic and Interpolation

`PIOP/prover_helper.go` provides the finite-field primitives relied on during witness assembly:

- `modAdd`, `modSub`, `modMul`, and `modInv` (`PIOP/prover_helper.go:44`) implement constant-time arithmetic modulo `q`, used by interpolation and random sampling.
- `Interpolate` (`PIOP/prover_helper.go:642`) performs explicit Lagrange interpolation over Ω∪R, guaranteeing the degree and root structure required by the protocol.
- `BuildRowPolynomial` (`PIOP/prover_helper.go:676`) turns a witness row and blinding parameters into an NTT polynomial of degree ≤ `|Ω|+ℓ−1`, returning the random evaluation points and their values. This routine is used later when the simulator converts column-wise witnesses into row-wise polynomials for LVCS commits.
- `buildValueRow` (`PIOP/prover_helper.go:662`) is a convenience wrapper for re-interpolating constant rows on Ω, used during the bootstrap stage in `run.go`.

Together, these helpers mirror the algebraic manipulations outlined in the paper: they ensure every polynomial that enters the protocol is an actual Ω-interpolant with the correct blinding and that all arithmetic respects the prime modulus.

---

Phase 1 covers the complete data-ingestion pipeline, from fixture loading to Ω-aligned witness vectors. Subsequent phases will layer constraint gadgets and PACS batching on top of this foundation. Any modification to the witness-building functions should be cross-checked against the formal identities in Protocol 6 to maintain correctness.

---

# Phase 2 – Constraint Gadgets and Polynomial Relations

Once the witness rows are available, the prover augments `(w₁,w₂,w₃)` with constraint gadgets that enforce the algebraic relations required by SmallWood’s LVCS/PACS design (§4.1 and Fig. 2). This phase documents those constructions.

## Bound Specifications (`bound_spec.go`)

- **`LinfSpec`** stores the parameters of the membership-chain ℓ∞ gadget: radix `R = 2^W`, digit count `L`, per-digit bounds `DMax`, precomputed membership polynomials `PDi`, and the maximum representable magnitude `MaxAbs`. It matches the digit decomposition used in the paper to prove per-row ∞-norm bounds.
- **`NewLinfChainSpec`** (`bound_spec.go:32`) constructs `LinfSpec` from `(q, W, L, ell, β)`:
  - Digit 0 uses a balanced window `[-2^{W-1}, 2^{W-1}-1]` to keep residues centered, as required by the chain gadget.
  - Higher digits are unsigned in `[0, R-1]`.
  - Computes `MaxAbs` via the geometric series described in §4.1 and precomputes `R^i mod q` for later scalar assembly.
- **`RangeMembershipSpec`** and `NewRangeMembershipSpec` (`bound_spec.go:78`) build the vanishing polynomial `P_B(X) = ∏_{i=-B}^B (X - i)` used for per-coordinate range checks (message, randomness, and `x₁` rows).

These specifications are the blueprints for the polynomials evaluated in subsequent files.

## ℓ∞ Chain Gadget (`norm_wire_linf.go`, `prover_fill.go`, `fpar_linf.go`)

### Chain metadata and setup

- `LinfChainAux` (`norm_wire_linf.go:9`) records where the chain’s magnitude/digit rows start within `w₁`, enabling verifiers to interpret the augmented witness.
- `minimalChainDigits` computes the minimum digit count needed to cover a bound `β` given window size `W`; it mirrors the range analysis performed in the paper to keep the chain compact.
- `appendChainDigits` (`prover_fill.go:18`) allocates the chain rows: one magnitude poly `M_t` and `L` digit polys `D_{t,i}` per original signature row.

### Filling chain rows

- `ProverFillLinfChain` (`prover_fill.go:41`) evaluates each witness row on `Ω`, decomposes the absolute values into base-`R` digits with the balancing rules from `LinfSpec`, and interpolates them back into polynomials via `buildValueRow`. It tracks measurement counters when `measure.Enabled` is true.
- The helper `liftToField` maps signed integers into `[0, q)`; `EvalPoly` is reused to evaluate the coefficient polynomials before decomposition.

### Parallel constraints for the chain

`buildFparLinfChain` (`fpar_linf.go:11`) emits the parallel constraints that certify the chain:

1. `M_t^2 - P_t^2 = 0` ties the magnitude to the original witness row.
2. `M_t - Σ_i R^i·D_{t,i} = 0` reassembles the digits.
3. For each digit, `P_{D_i}(D_{t,i}) = 0` enforces membership in the allowed set using the polynomials from `LinfSpec`.

These polynomials end up in the `Fpar` list used by PACS and Eq.(4) checks.

### Gadget wiring

`makeNormConstraintsLinfChain` (`norm_wire_linf.go:54`) orchestrates the entire gadget:

- Computes the observed maximum over the relevant rows (including optional extra rows such as `w₂`).
- Chooses digit count via `minimalChainDigits` when not specified.
- Calls `NewLinfChainSpec`, `appendChainDigits`, and `ProverFillLinfChain`.
- Appends the chain rows to `w₁` and records offsets in `RowLayout`.
- Returns the `Fpar` fragment corresponding to the chain together with auxiliary metadata for later verification.

This function is invoked near line 1718 of `run.go`, right after the base witness is prepared.

## Range Membership (`fpar_membership.go`, `norm_wire_linf.go`)

`buildFparRangeMembership` (`fpar_membership.go:11`) composes the range polynomial `P_B` with each target row (message, randomness, and `x₁`) by evaluating `P_B(P_t(X))` coefficient-wise. The resulting polynomials are appended to `Fpar` and ensure each coordinate lies within the seed-dependent bounds, mirroring the inequalities in §3.4 of the paper.

`makeNormConstraintsLinfChain` integrates these membership checks (lines 1750–1774 in `run.go`), adding offsets `MsgRangeBase`, `RndRangeBase`, and `X1RangeBase` to the row layout.

## Core Constraint Builders (`PACS_Statement.go`)

### Fpar polynomials

- `buildFpar` (`PACS_Statement.go:521`) generates `Fpar_k = w₃[k] - w₁[k]·w₂` for each base witness row, enforcing the quadratic relationship from Step 6 of Protocol 6.
- `buildIntegerRowsOnOmega` (`PACS_Statement.go:543`) evaluates the proof-friendly equality on Ω by combining Θ′ polynomials with witness rows, yielding the integer constraints `F'_j`. Its wrapper `buildFparInteger` exposes these rows to callers.

Together with the norm gadgets and range checks, these functions populate the complete `Fpar` and `Fagg` lists before PACS aggregation (Phase 3).

### Interplay with Θ′

The Θ′ polynomials built in Phase 1 are consumed inside `buildIntegerRowsOnOmega`: they allow the prover to multiply public coefficient polynomials with witness rows entirely in the evaluation domain while keeping the degree below `|Ω|+ℓ−1`, as required by the DECS verifier’s degree bound.

## Tests and Validation

- `membership_spec_test.go` validates that the digit membership polynomials vanish on all allowed digits and reject out-of-range values.
- `degree_enforcement_test.go` and related unit tests in `PIOP_test.go` ensure that the quadratic gate and norm gadgets produce the expected number of rows and degrees.
- Continuous logging via the `measure` package records sizes (`piop/Fpar/…`) to catch regressions in chain size or range checks.

## Summary

Phase 2 extends the witness with polynomial gadgets that encode all algebraic constraints mandated by the SmallWood LVCS/PACS construction:

- `LinfSpec` and chain helpers supply bounded digit decompositions for ℓ∞ constraints.
- Range membership polynomials enforce bounded message and randomness coefficients.
- `Fpar` and `Fagg` builders turn these gadgets into polynomials ready for aggregation in Phase 3.

Any modification to these components should be checked against §§4.1–4.2 of `docs/2025-1085.pdf` to ensure the constraint system remains sound and degree-bounded.

---

# Phase 3 – PACS Orchestration & Transcript Handling

With witness rows and constraint polynomials in place, the prover runs the Polynomial Argument for Committed Statements (PACS) as described in SmallWood §5–§6 (see Figure 5 and the PACS instantiation in §6). This phase documents how the Go implementation assembles mask polynomials, drives the Fiat–Shamir transcript, and packages/validates the final proof.

## Mask Polynomials and Aggregation (`prover_helper.go`)

### Mask Generation over F

- `BuildMaskPolynomials` (`prover_helper.go:779`) samples `ρ` random polynomials `M_i(X)` of degree ≤ `d_Q` such that the Ω-sum of each corresponding `Q_i` is zero, as required by the PCS binding argument (SmallWood §6.1). The routine:
  1. Randomly selects coefficients for degrees `1..d_Q`.
  2. Solves for the constant term using the precomputed Ω-sums of `F_par` and `F'_agg` (`sumFpar`, `sumFagg`), enforcing `Σ_{ω∈Ω} Q_i(ω)=0`.
  3. Panics if Ω has duplicates or if `|Ω|` shares factors with `q`, reflecting the soundness assumptions in the paper.

- `BuildMaskPolynomialsK` (`prover_helper.go:376`) extends the same idea to the extension field `K ≅ F^{θ}` when θ>1. It uses the `kf.Field` helpers to ensure the K-polynomial masks obey the same Ω-sum constraint but in the multi-limb representation required by the “K-PCS” discussed in §6.2 of the paper.

### K-field Helpers

`prover_helper.go` defines types `KScalar`, `KVec`, `KMat`, and `KPoly` to store elements and polynomials over `K`. Key routines include:

- `addScaledFPolyToKPoly` (`prover_helper.go:323`) lifts F-polynomials into `K[X]` by scaling each limb according to `Φ(g)` (the embedding map in §6.2).
- `BuildQK` (`prover_helper.go:344`) mirrors `BuildQ` but works over `K`, combining mask polynomials with `F_par`/`F_agg` using K-scaled Γ′ coefficients.
- Conversion utilities such as `firstLimbToFPoly`, `kPolyToBytes`, and `bytesToKPoly` support serialization.

These helpers align with the “θ>1” generalization in the paper, where the PCS operates over an extension field to amortize constraints.

### Aggregated Polynomials

- `BuildQ` (`PACS_Statement.go:482`) computes `Q_i(X) = M_i(X) + Σ_j Γ'_{i,j}·F_j(X) + Σ_u γ'_{i,u}·F'_u(X)` in F. The implementation follows Protocol 6, ensuring each term remains in NTT form for efficiency.
- Evaluation routines (`evalAtF`, `evalAtK`, `evalPolySetAtIndices`) scattered throughout `prover_helper.go` and `run.go` support checks on Ω and the tail set `E`, enabling the Eq.(4) verifications.

## Fiat–Shamir Orchestration (`fs_helpers.go`, `prover_helper.go`)

- `FS`, `FSParams`, and `Shake256XOF` (`fs_helpers.go`) encapsulate the four grinding rounds described in SmallWood §6.1. Each call to `GrindAndDerive`:
  1. Computes `Hash(label || salt || transcript || counter)`.
  2. Applies κ-bit grinding by requiring a zero prefix.
  3. Returns both the accepted digest and derived challenge bytes (e.g., seeds for Γ or evaluation points).

- `newFSRNG` (`prover_helper.go:200`) derives deterministic PRNG streams from FS seeds and labels; this matches the paper’s insistence that the prover and verifier sample identical random coins (Γ, Γ′, evaluation points, etc.).

These utilities guarantee that every random choice in the protocol is transcript-bound, satisfying the ROM modeling in Theorems 1–4.

## End-to-End Simulation (`run.go`)

The heart of the PACS prover is `buildSimWith` (`PIOP/run.go`), whose control flow mirrors Protocol 6 and Figure 5 of `docs/2025-1085.pdf`:

1. **Options and context** – `SimOpts.applyDefaults` fixes `(ρ, ℓ, ℓ′, η, θ, κ)` plus gadget knobs, while `simCtx` records measurements and copies of the witness rows for later tamper tests (`run.go:120–190`).

2. **Witness and constraints** – Phases 1–2 populate the base witness (`w₁,w₂,w₃`), ℓ∞ chain rows, range checks, and the integer/parallel constraint polynomials `Fpar`/`Fagg` (roughly `run.go:1620–1890`), staying within the degree budgets of §4.

3. **Merged LVCS commitment & layout (FS round 0)** – Witness rows are converted to evaluation form via `columnsToRows`, Γ-independent PCS mask rows are sampled with `SampleIndependentMaskPolynomials`, and both families are concatenated before calling `lvcs.CommitInitWithParams` (`run.go:2000–2085`). The resulting root is fed to `fsRound(fs, proof, 0, "Gamma", root[:])`, which derives Γ exactly as in §6.1. Immediately afterwards the prover records the `[P, M]` layout via `pk.SetLayout` and stores `MaskRowOffset`, `MaskRowCount`, and `MaskDegreeBound` inside `Proof` so verifiers know how to partition witness rows when recomputing the masked linear relations.

4. **Γ′/γ′ sampling (FS round 1)** – The transcript `transcript2 = {root, Γ, R, (χ, ζ)}` is hashed by `fsRound(fs, proof, 1, "GammaPrime", …)` to derive Γ′ and γ′ (`run.go:2124–2202`). Extension-field runs additionally carry `GammaPrimeK`/`GammaAggK`, matching §6.2.

5. **Mask polynomials and `Q`** – `BuildMaskPolynomials{,K}` generate the PCS masks `M/MK` that satisfy the ΣΩ constraints, `BuildQLayout` wires the witness/mask slices the same way the LVCS layout does, and `BuildQ`/`BuildQK` assemble the aggregated polynomials required by Eq.(4) (`run.go:2203–2267`). Snapshots of these polynomials (`proof.QNTT`, `proof.MKData`, `proof.QKData`) end up in the proof.

6. **(No oracle leakage)** – Earlier revisions exported an explicit `[P, M]` snapshot prior to FS round 2. The current prover keeps the layout metadata (`MaskRowOffset`, `MaskRowCount`) but does not serialise Ω evaluations, ensuring witness heads never leave the prover. The merged DECS opening obtained later suffices to bind both `VTargets` and `BarSets` to the commitment.

7. **LVCS evaluation challenges & masked sums (FS round 2)** – `fsRound(fs, proof, 2, "EvalPoints", …)` derives either:
   - extension-field points and coefficient blocks (`buildKPointCoeffMatrix`) when θ>1, or
   - base-field evaluation points `points` plus random coefficient vectors otherwise.  
   Each request is passed to `lvcs.EvalInitMany`, which returns the masked sums `barSets` (the `\bar v_k` of Fig. 2). `computeVTargets` derives the public `v_k(Ω)` rows, and every matrix is stored in the proof (`proof.CoeffMatrix`, `proof.setBarSets`, `proof.setVTargets`, `proof.KPoint`). At this stage Γ″ and all linear forms are transcript-bound but the verifier has not yet seen the tail challenge.

8. **Tail sampling & single LVCS opening (FS round 3)** – The prover concatenates `{root, Γ, Γ′, eval points/KPoint, CoeffMatrix, BarSets, VTargets}` into `transcript4` and runs `fsRound(fs, proof, 3, "TailPoints", …)` (`run.go:2338–2394`). The resulting seed produces the tail set `E ⊂ [ncols+ℓ, N)` exactly as in Fig. 2. Two `lvcs.EvalFinish` calls open the masked prefix `[ncols, ncols+ℓ)` and the random tail `E`; `combineOpenings` merges them into the single `Proof.RowOpening`, meaning no second Merkle tree is ever constructed. For Eq.(4) checks the prover also records the raw tail evaluations of the PCS masks in `Proof.MOpening` via `makeMaskTailOpening` (`run.go:2450–2468`); this structure carries values only, not Merkle data.

9. **Verifier replay and Eq.(4)** – `VerifyNIZK` (`PIOP/VerifyNIZK.go:193–360`) replays all four Fiat–Shamir rounds and then reconstructs the masked/tail DECS openings directly from `Proof.RowOpening`. `verifyLVCSConstraints` enforces the masked linear relations (comparing `BarSets` against the masked prefix) and interpolates `VTargets` together with the random tail subset to bind the Ω evaluations without ever revealing them. `checkEq4OnTailOpen` (`run.go:3265–3348`) consumes `Proof.MOpening` to check Eq.(4) over the tail indices in both the base field and the extension-field limbs, and `VerifyQ` ensures ΣΩ Q=0 (Eq.(7)).

The entire flow therefore matches Figures 2–7 of Crypto’25 paper 2025-1085: only one LVCS commitment exists, the `[P, M]` oracle is transcript-bound before tail sampling, and every verifier check is derived from that single commitment without auxiliary Merkle trees. Ancillary bookkeeping (`SoundnessBudget`, `SimReport`, and the `set*/ensure*` packing helpers) continues to log size and soundness budgets, but the merged-oracle narrative above captures the key data dependencies needed for verification.


## Transcript Layout for `VerifyNIZK`

The non-interactive verifier expects a `Proof` populated with all data needed to replay the Fiat–Shamir transcript and re-run LVCS/DECS checks. The following tables summarise every field.

### Transcript Metadata

| Field            | Type           | Purpose                                                                                 |
|------------------|----------------|-----------------------------------------------------------------------------------------|
| `Root`           | `[16]byte`     | Merkle root of the LVCS commitment (FS round 0 input).                                  |
| `Salt`           | `[]byte`       | 256-bit Fiat–Shamir salt shared across all rounds.                                      |
| `Ctr[4]`         | `[4]uint64`    | Grinding counters for rounds 0..3.                                                      |
| `Digests[4]`     | `[4][]byte`    | Accepted hashes after grinding per round.                                               |
| `Kappa[4]`       | `[4]int`       | Grinding difficulty (bits) per round.                                                   |
| `Theta`          | `int`          | Extension field dimension θ (1 ⇒ base field).                                           |
| `Chi`, `Zeta`    | `[]uint64`     | Extension-field minimal polynomial and ω^{s−1} limb (θ>1 only).                         |
| `Tail`           | `[]int`        | Tail challenge indices `E` sampled in FS round 3.                                       |

### LVCS / DECS Objects

| Field             | Type                    | Description                                                                          |
|-------------------|-------------------------|--------------------------------------------------------------------------------------|
| `R`               | `[][]uint64`            | Coefficient snapshots of masked polynomials `R_k` (`lvcs.CommitFinish`).             |
| `RowOpening`      | `*decs.DECSOpening`     | Combined DECS opening for masked prefix and tail challenge.                         |
| `VTargets`        | packed via `VTargetsBits` | Public linear-combination evaluations `v_k(Ω)`.                                      |
| `BarSets`         | packed via `BarSetsBits`  | Masked sums `\bar v_k` over the appended positions.                                 |
| `CoeffMatrix`     | `[][]uint64`            | Linear coefficients used to form `v_k` (round 3 challenge).                          |
| `KPoint`          | `[][]uint64`            | Evaluation points in `K` when θ>1.                                                   |
| `RowLayout`       | `RowLayout`             | Metadata to interpret witness rows (signature/message/randomness offsets, chains).  |
| `MaskRowOffset`, `MaskRowCount`, `MaskDegreeBound` | `int` trio | Describe the merged `[P, M]` layout so verifiers know which rows correspond to PCS masks and which degree bound was enforced. |
| `MOpening`        | `*decs.DECSOpening`     | Dense tail evaluations of the PCS masks; consumed solely by `checkEq4OnTailOpen` (no Merkle paths). |

### Aggregated Polynomials

| Field        | Type                | Description                                                       |
|--------------|---------------------|-------------------------------------------------------------------|
| `FparNTT`    | `[][]uint64`        | NTT snapshots of `F_par` rows.                                   |
| `FaggNTT`    | `[][]uint64`        | NTT snapshots of `F_agg` rows.                                   |
| `QNTT`       | `[][]uint64`        | NTT snapshots of aggregated `Q` polynomials.                     |
| `MKData`     | `[]KPolySnapshot`   | Serialized `K`-polynomials for masks (θ>1).                      |
| `QKData`     | `[]KPolySnapshot`   | Serialized `K`-polynomials for aggregated constraints (θ>1).     |
| `GammaPrime` | `[][]uint64`        | Γ′ scalars over F (θ=1).                                         |
| `GammaAgg`   | `[][]uint64`        | γ′ scalars over F (θ=1).                                         |
| `GammaPrimeK`| `[][]KScalar`       | Γ′ scalars over K (θ>1).                                         |
| `GammaAggK`  | `[][]KScalar`       | γ′ scalars over K (θ>1).                                         |

### ASCII Diagram

```
Proof
├─ Fiat–Shamir Transcript
│  ├─ Salt
│  ├─ Rounds[0..3]:
│  │   ├─ Root / Γ         (round 0)
│  │   ├─ Γ′, γ′           (round 1)
│  │   ├─ Eval points / coefficients (round 2)
│  │   └─ Tail points + CoeffMatrix/BarSets/VTargets (round 3)
│  ├─ Counters (Ctr[4])
│  └─ Digests, Kappa
├─ LVCS Commitment
│  ├─ Root
│  ├─ R-polynomials (R)
│  ├─ RowOpening (DECS)
│  ├─ RowLayout metadata
│  └─ MaskRowOffset / MaskRowCount / MaskDegreeBound
├─ Mask Tail Data
│  └─ MOpening (DECS)
├─ Aggregated Polynomials
│  ├─ FparNTT / FaggNTT / QNTT
│  ├─ GammaPrime / GammaAgg
│  ├─ (θ>1) GammaPrimeK / GammaAggK
│  └─ (θ>1) MKData / QKData snapshots
└─ Evaluation Data
   ├─ Tail indices E
   ├─ CoeffMatrix
   ├─ KPoint (θ>1)
   ├─ VTargets (packed)
   └─ BarSets (packed)
```

This layout mirrors Figure 5 in `docs/2025-1085.pdf`: each block corresponds to a transcript phase or polynomial batch. `VerifyNIZK` expects every field to be present and coherent; it unpacks bitstreams, replays FS rounds, and re-invokes LVCS/DECS verifiers accordingly, binding `VTargets`/`BarSets` through the merged DECS opening rather than a standalone oracle snapshot.
