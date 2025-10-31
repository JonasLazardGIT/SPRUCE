# DECS Package Documentation

## Call Flow and Paper Mapping

Figure 1 of `docs/2025-1085.pdf` (Section “DECS.Commit / DECS.Eval”) spells out the three-pass commitment protocol and the two-pass evaluation protocol. The Go implementation mirrors that control flow via the following function calls:

- **Commit phase (paper: DECS.Commit, prover passes 1–3).**
  1. `NewProverWithParams` (`DECS/decs_prover.go:66`) validates parameters against the constraints listed in Figure 1 and instantiates the prover state.  
  2. `CommitInit` (`DECS/decs_prover.go:84`) implements the first pass: it samples the η masking polynomials, NTTs inputs and masks, derives nonce seeds, and builds the Merkle tree exactly as required by lines 1–4 of DECS.Commit.  
  3. Both parties call `DeriveGamma` (`DECS/decs_prover.go:337`)—this corresponds to pass 2 where the challenge matrix Γ is deterministically derived from the commitment root, matching the “γ ← Hash(root)” step in the figure.  
  4. `CommitStep2` (`DECS/decs_prover.go:153`) realises pass 3 by materialising the masked polynomials `R_k = M_k + Σ_j Γ[k][j]·P_j`, aligning with the final prover message shown in the paper.

- **Evaluation phase (paper: DECS.Eval, prover passes 1–2 and verifier check).**
  1. `EvalOpen` (`DECS/decs_prover.go:174`) corresponds to the prover’s response in DECS.Eval: it gathers `P |E`, `M |E`, the nonce material, and the Merkle authentication paths for the challenge set `E`. Optional compact encodings (`PackOpening`) are an implementation detail that compresses this message.  
  2. On the verifier side, `NewVerifierWithParams` (`DECS/decs_verifier.go:21`) sets the shared parameters, and `DeriveGamma` (`DECS/decs_verifier.go:39`) recomputes Γ from the root as mandated by Figure 1.  
  3. `VerifyCommit` (`DECS/decs_verifier.go:80`) checks the degree constraint and Γ binding, matching the “Verify Γ, deg Rk ≤ d” step in DECS.Commit.  
  4. `VerifyEvalAt` (`DECS/decs_verifier.go:333`) invokes `VerifyEval` (`DECS/decs_verifier.go:99`): it first reconstructs any frontier-encoded paths via `EnsureMerkleDecoded` (`DECS/decs_frontier.go:153`), re-derives nonces with `deriveNonce`, authenticates each Merkle path using `VerifyPath` (`DECS/merkle.go:71`), and finally enforces the masked relation `NTT(R_k)[e] = M_k(e) + Σ_j Γ[k][j]·P_j(e)` exactly as described in the verifier checks of DECS.Eval.

This call graph provides a blueprint for navigating the code while cross-referencing the formal description in `docs/2025-1085.pdf`. The remainder of this document dives into each component in more detail.

---

This document provides an in-depth description of the **Degree-Encoded Commitment Scheme (DECS)** implementation that lives under `DECS/`. It explains the protocol roles, internal data structures, Merkle commitment machinery, compact encodings, and supporting utilities so that future contributors can reason about behaviour, verify correctness, and extend the codebase with confidence.

The documentation mirrors the code layout and follows the prover/ verifier workflow from `DECS/decs_prover.go`, `DECS/decs_verifier.go`, the shared type definitions in `DECS/decs_types.go`, and auxiliary helpers in companion files.

---

## 1. Protocol Overview

DECS is a polynomial commitment-with-openings primitive used inside the PIOP. At a high level:

1. The **prover** receives a set of input polynomials `P_j`, samples masking polynomials `M_k`, and commits to the evaluation table of both families by hashing them into a Merkle tree (degree bounded by `Params.Degree`).
2. Both parties derive the linear-combination coefficients `Γ` from the Merkle root, allowing the prover to publish masked polynomials `R_k = M_k + Σ_j Γ[k][j]·P_j`.
3. During an evaluation round, the verifier challenges the prover on a subset of indices `E`. The prover returns the evaluations of `P` and `M` on `E`, authenticating them with compact Merkle paths plus nonce data; the verifier recomputes the masked relation in the NTT domain and checks the Merkle authentication.

The lifecycle is split into **Commit** and **Eval** stages with strict parameter validation on both sides (see `DECS/decs_prover.go:84`, `DECS/decs_verifier.go:21`).

---

## 2. Core Data Structures

### 2.1 Protocol Parameters

`Params` (defined in `DECS/decs_types.go:90`) bundles the static configuration:

- `Degree` – maximum allowed polynomial degree (`d ≤ N-1`). Used by both prover and verifier to zero out high coefficients and reject oversized commitments.
- `Eta` – number of masking polynomials. This is the height of the `Γ` matrix and the length of `M`/`R`.
- `NonceBytes` – length of per-leaf nonces `ρ_e`. Raising this increases quantum security margin for binding openings to the commitment.

`DefaultParams` (`DECS/decs_types.go:97`) captures legacy defaults (degree `4095`, `η=2`, `NonceBytes=24`), preserving compatibility while strengthening nonce size.

### 2.2 Openings

`DECSOpening` (`DECS/decs_types.go:3`) models everything the prover sends during `Eval`. It is intentionally flexible to support multiple encodings:

- **Index metadata** (`MaskBase`, `MaskCount`, `Indices`) separates a contiguous mask range from an explicit tail. Packing helpers (`IndexBits`, `TailCount`) allow compressing 13-bit tails compactly (see `DECS/decs_indices.go:19`).
- **Residue storage**: evaluations of `P` and `M` appear either as raw matrices (`Pvals`, `Mvals`) or packed 20-bit streams (`PvalsBits`, `MvalsBits`). The `R` and `Eta` fields record column counts required to decode the packed format.
- **Merkle multiproof**: `Nodes` holds the deduplicated sibling hashes, with `PathIndex` mapping each opened index to the path. Space-optimized representations use `PathBits`/`PathBitWidth`/`PathDepth` or the frontier encoding (`FrontierNodes`, `FrontierProof`, `FrontierLR`, `FrontierRefsBits`).
- **Nonce binding**: either explicit per-entry `Nonces` or a shared `NonceSeed` plus `NonceBytes` for deterministic reconstruction.

Utility methods on `DECSOpening` provide convenience:

- `EntryCount` and `IndexAt` iterate logical indices, blending the mask prefix with decoded tails (`DECS/decs_types.go:42`).
- `AllIndices` materialises the full set, unpacking tails when necessary (`DECS/decs_types.go:68`).

---

## 3. Prover Lifecycle

The prover is encapsulated by the `Prover` struct in `DECS/decs_prover.go:52`, which stores:

- `ringQ` – the Cyclotomic ring over modulus `q` (single-modulus enforced).
- `P` – input polynomials in coefficient form.
- `M` – sampled mask polynomials.
- `Pvals`/`Mvals` – the NTT form cached for answering evaluation queries.
- `nonceSeed` and `mt` – per-commit nonce seed and Merkle tree.
- `R` – masked polynomials prepared during commit step 2.

### 3.1 Commit Step 1 – `CommitInit`

`CommitInit` (`DECS/decs_prover.go:84`) carries out:

1. **Parameter validation**: ensures degree bounds, positive `η`, and single modulus.
2. **Mask sampling**: uses `ring.NewUniformSampler` to sample each `M_k`, truncating coefficients above `Degree` to zero (lines `96–104`).
3. **NTT preparation**: transforms both `P_j` and `M_k` into the NTT domain (`107–116`), caching results for openings and masked-relation checks.
4. **Leaf building**: for each evaluation point `i ∈ [0, N)` it concatenates:
   - `P_j(i)` for all `j`
   - `M_k(i)` for all `k`
   - The index `i` encoded as `uint16`
   - A nonce `ρ_i = deriveNonce(nonceSeed, i, NonceBytes)`

   This buffer becomes the leaf payload passed to the Merkle tree (`118–144`).
5. **Merkle tree construction**: `BuildMerkleTree` (`DECS/merkle.go:18`) pads the leaf layer to the next power of two, prefixes each hashing stage (leaf prefix `0x00`, node prefix `0x01`), and stores every layer for later path extraction. The Merkle root is returned alongside the built tree (`146–149`).

The nonce seed is randomly sampled from `crypto/rand` before leaf construction to guarantee per-commit uniqueness (`120–123`).

### 3.2 Commit Step 2 – `CommitStep2`

Given the challenge matrix `Γ`, `CommitStep2` (`DECS/decs_prover.go:153`) computes each masked polynomial:

```
R_k(X) = M_k(X) + Σ_j Γ[k][j] · P_j(X)
```

Implementation details:

- The prover keeps `M_k` in NTT form to avoid repeated forward transforms; for each `k`, it inverts `Mvals[k]` back to coefficient form (`161–163`).
- For every `P_j`, it inverts the cached NTT (`164–166`), scales by `Γ[k][j]` with modular multiplication, and accumulates into `R[k]` (`166–168`).
- Output polynomials remain in coefficient form for the verifier to NTT as needed (comment on `169–170`).

### 3.3 Evaluation Opening – `EvalOpen`

`EvalOpen` (`DECS/decs_prover.go:174`) constructs `DECSOpening` for a challenge set `E`:

1. Copies the indices and fills metadata (`176–187`).
2. Extracts `Pvals`/`Mvals` rows from the cached NTT tables (`203–210`).
3. Builds per-leaf path index arrays by walking up the Merkle tree layers, deduplicating sibling hashes to populate `Nodes` and referencing them by integer IDs (`210–222`).

At this stage the opening is uncompressed. Callers can invoke `PackOpening` to enable the compact encodings described below.

### 3.4 Opening Packing – `PackOpening`

`PackOpening` (`DECS/decs_prover.go:227`) is an optional optimisation pass:

- `packResidues20`: packs evaluation matrices into 20-bit streams (row-major), inferring column counts if not set (`DECS/decs_prover.go:242`).
- `packTailIndices`: uses 13-bit packing when tail indices fit below `2¹³`, falling back to explicit storage otherwise (`DECS/decs_indices.go:19`).
- `packFrontier`: converts the full multiproof into the frontier format (see §5.2).
- `packPathIndexBits`: stores sibling IDs with a fixed bit width when the ID range fits within 32 bits (`DECS/decs_prover.go:295`).
- If a nonce seed is present, any explicit `Nonces` slice is discarded because verifiers can derive the nonces deterministically (`235–238`).

When the environment variable `DEBUG_DECS_OPENINGS` is set, `PackOpening` also emits detailed size statistics via `logOpeningMetrics` (`DECS/decs_metrics.go:50`).

---

## 4. Verifier Lifecycle

`Verifier` (defined at `DECS/decs_verifier.go:14`) mirrors the prover’s parameters and ring context. It enforces the same degree/eta/nonce constraints at construction (`DECS/decs_verifier.go:23`).

### 4.1 Deriving Γ

The verifier calls `DeriveGamma` (`DECS/decs_verifier.go:39`), which delegates to the shared helper (`DECS/decs_prover.go:337`). The routine reads the Merkle root and a monotonically increasing counter into SHA-256, performing rejection sampling to obtain each coefficient uniformly in `[0, q)` (ensuring the same `Γ` for both parties).

### 4.2 `VerifyCommit`

`VerifyCommit` (`DECS/decs_verifier.go:80`) validates:

1. The `Γ` provided by the prover matches the root-derived matrix (ensuring binding between commit and Γ).
2. Each output polynomial `R_k` has zero coefficients above `Params.Degree`.

Any mismatch results in immediate rejection.

### 4.3 `VerifyEval`

`VerifyEval` (`DECS/decs_verifier.go:99`) performs the main evaluation checks:

1. **Opening sanity**: ensures non-nil input, consistent slice lengths, and matching `Γ`/`R` dimensions.
2. **Merkle decoding**: calls `EnsureMerkleDecoded` to recover `Nodes`/`PathIndex` if the prover supplied a frontier-only proof (`DECS/decs_frontier.go:153`).
3. **NTT of `R`**: for each `R_k`, computes the NTT form once upfront (`144–148`).
4. **Per-index loop**:
   - Validates that the index is within `[0, N)`.
   - Retrieves `P` and `M` evaluations (using `getPval`/`getMval`, which handle both packed and unpacked representations; see `DECS/decs_verifier.go:241`).
   - Reconstructs the nonce, preferring explicit `Nonces` when provided or regenerating it from `NonceSeed` and `NonceBytes` (`166–177`).
   - Rebuilds the Merkle path from `PathIndex` and `Nodes`, and verifies it against the commitment `root` using `VerifyPath` (`DECS/merkle.go:71`).
   - Checks the masked relation in the NTT domain:

     ```
     lhs = Re[k].Coeffs[0][idx]
     rhs = Mvals[t][k] + Σ_j Γ[k][j] · Pvals[t][j] (mod q)
     ```

     Modular arithmetic uses helper routines `mulMod64` and `addMod64` (`DECS/decs_verifier.go:45`, `DECS/decs_verifier.go:53`).

`VerifyEval` returns `true` only if all indices pass every sub-check.

### 4.4 `VerifyEvalAt`

`VerifyEvalAt` (`DECS/decs_verifier.go:333`) adds a set-binding check: it compares the decoded indices from the opening to the challenge set `E`, rejecting if there are duplicates, missing entries, or extra indices. Once the set matches, it delegates to `VerifyEval`.

---

## 5. Merkle Commitments & Multiproof Compression

### 5.1 Merkle Tree Mechanics

`BuildMerkleTree` (`DECS/merkle.go:18`) is the shared constructor for commitments:

- Pads the leaf layer to a power of two to maintain a complete tree.
- Applies `leafPrefix`/`nodePrefix` bytes to domain-separate hashes.
- Uses SHAKE-256 truncated to 16 bytes (`shake16`) for all hashes.
- Stores every layer so the prover can recompute paths quickly and deduplicate siblings.

`VerifyPath` (`DECS/merkle.go:71`) authenticates a single leaf by replaying the hash chain with the provided sibling list and index parity.

### 5.2 Frontier-Based Multiproofs

Standard openings carry `PathIndex` tables referencing `Nodes`. For bandwidth efficiency, `packFrontier` (`DECS/decs_frontier.go:14`) transforms this structure into:

- `FrontierNodes`: the union of unique sibling hashes encountered across all paths.
- `FrontierProof`: a bitmap indicating which leaf-level pairs required proof nodes (i.e., when the sibling was not present in the active set).
- `FrontierLR`: parity bits storing whether the active node was a left or right child at each level.
- Optional `FrontierRefsBits`: packed references into the union table when reused nodes appear multiple times; this keeps the proof canonical without duplicating bytes.

The algorithm simulates peeling the tree level by level, tracking active nodes (`frontierActive`) and recording metadata needed to reconstruct per-leaf paths later (`DECS/decs_frontier.go:69` onwards). After packing, the explicit `Nodes` and `PathIndex` slices are cleared to avoid redundancy (`DECS/decs_frontier.go:140`).

When a verifier (or any consumer) needs explicit paths again, `EnsureMerkleDecoded` (`DECS/decs_frontier.go:153`) replays the frontier proof:

1. Computes leaf hashes using `computeLeafHash`, which mirrors the prover’s leaf layout and handles either packed or unpacked residues (`DECS/decs_frontier.go:337`).
2. Iteratively rebuilds the tree layers, deciding whether to use stored frontier nodes or sibling hashes already in the active set (`DECS/decs_frontier.go:208`).
3. Collects per-leaf paths, deduplicates them back into `Nodes`, and regenerates `PathIndex`.

Bit-level helpers in `DECS/decs_pathbits.go` provide dynamic-width packing for path IDs, ensuring the packed form is lossless and easy to decode.

---

## 6. Packing & Encoding Utilities

Optimisations minimise bandwidth when transmitting openings:

### 6.1 Tail Indices

`packTailIndices` (`DECS/decs_indices.go:19`) encodes the explicit tail of index positions using 13-bit entries (`indexBitsPerValue = 13`). This covers indices `< 8192`, which aligns with current ring sizes. If any index exceeds this range, the function leaves the explicit slice untouched to avoid truncation.

Supporting functions `tailIndexAt`, `decodeTailInto`, `packIndexBits13`, and `unpackIndexAt` provide random access over the packed representation (`DECS/decs_indices.go:48`, `DECS/decs_indices.go:59`, `DECS/decs_indices.go:86`, `DECS/decs_indices.go:110`).

### 6.2 Residue Matrices

`packResidues20` (`DECS/decs_prover.go:242`) compresses evaluation matrices into 20-bit streams because the modulus `q` is strictly below `2²⁰`. The general-purpose wrappers in `DECS/packing.go:8` expose this capability outside the prover. The verifier uses `getPval`/`getMval` and `unpackU20` to read packed data without materialising the full matrix (`DECS/decs_verifier.go:241`).

### 6.3 Generic Matrix Packing

`PackUintMatrix` and `PackUintMatrixWithWidth` (`DECS/packing.go:35`) generalise the encoding with a 10-byte header (rows, columns, bit width). The body uses arbitrary widths up to 64 bits (`DECS/packing.go:115`). This is useful for serialising matrices whose entries may exceed `2²⁰`, maintaining compatibility with other components.

### 6.4 Path Matrices

`packPathMatrix` and `unpackPathMatrix` (`DECS/decs_pathbits.go:21`, `DECS/decs_pathbits.go:47`) allow packing integer matrices row-by-row with a minimal bit width computed via `pathBitWidth`. This underpins both `PathBits` and `FrontierRefsBits`.

---

## 7. Nonce & Γ Binding

### 7.1 Nonce Derivation

`deriveNonce` (`DECS/decs_prover.go:17`) and its public wrapper `DeriveNonce` (`DECS/decs_nonce.go:3`) generate per-leaf nonces deterministically from:

```
SHA256("decs-nonce" || nonceSeed || idx)
```

If `NonceBytes` exceeds 32, the function extends the hash using counter-based expanders. This approach:

- Guarantees consistent reconstruction between prover and verifier.
- Binds each evaluation leaf to the commitment, preventing path swapping or index permutation attacks.

### 7.2 Γ Derivation

`DeriveGamma` (`DECS/decs_prover.go:337`) uses SHA-256 as a PRF keyed by the Merkle root. Each coefficient is produced via rejection sampling over the 64-bit hash output, ensuring exact uniformity modulo `q`. The verifier replays the same logic (`DECS/decs_verifier.go:39`) to confirm that any provided Γ is bound to the original commitment.

---

## 8. Interaction with the Ring API

Both prover and verifier rely on `github.com/tuneinsight/lattigo/v4/ring`:

- The ring is enforced to have a single modulus to simplify packing and arithmetic (`DECS/decs_prover.go:78`, `DECS/decs_verifier.go:33`).
- Prover operations mix coefficient and NTT domains deliberately:
  - Inputs `P_j` arrive in coefficient form, are cached in NTT form (`CommitInit`).
  - Masked results `R_k` are produced in coefficient form to avoid double transforms.
- The verifier recomputes NTT(R) once (`DECS/decs_verifier.go:144`) and performs modular arithmetic via `mulMod64`/`addMod64`.

These invariants should be documented when extending DECS to multi-modulus rings or alternative residue number system layouts.

---

## 9. Instrumentation & Diagnostics

`openingMetrics` (`DECS/decs_metrics.go:7`) and `computeOpeningMetrics` break down the size contribution of each component inside an opening: indices, residues, Merkle payload, nonces. When `DEBUG_DECS_OPENINGS` is set, `logOpeningMetrics` prints a concise summary showing the effect of packing strategies (`DECS/decs_metrics.go:50`).

This facility is valuable for regression tracking: any unexpected size increase flags potential packing regressions or unbounded data structures.

---

## 10. Testing & Validation

Unit tests in `DECS/` validate critical behaviour:

- `decs_test.go`: end-to-end commit/eval acceptance, degree rejection, duplicate index detection, malformed openings, edge cases for parameter validation (`DECS/decs_test.go:10`).
- `decs_indices_test.go`: packing/unpacking symmetry for tail indices and path matrices (`DECS/decs_indices_test.go:5`).
- `decs_metrics_test.go`: ensures metric accounting matches expectations for packed/unpacked openings (`DECS/decs_metrics_test.go:5`).

These tests serve as executable specifications. Any change to encodings or protocol steps should include corresponding test coverage updates.

---

## 11. Extension Guidelines

When modifying or extending DECS:

1. Preserve parameter checks and invariants in both prover and verifier constructors.
2. Update `DECSOpening` documentation to reflect new fields or alternative encodings.
3. Maintain the pairing between packed and unpacked representations—if a new packing mode is added, ensure verifiers can read it without ambiguity.
4. Keep Merkle leaf layout aligned between `CommitInit` and `computeLeafHash`, as any divergence breaks `EnsureMerkleDecoded`.
5. Extend tests and, when necessary, instrumentation to highlight regressions in size or verification logic.

By following these guidelines alongside the detailed component breakdown above, contributors can confidently evolve the DECS package while preserving protocol soundness.






### Can we optimize our current merkle tree construction into a GGM Tree construction : 


- GGM tree allows to generate a lot of randomness from a small seed + PRG AESCTR.