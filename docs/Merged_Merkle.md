# Merged Merkle Transcript Migration

## Overview

Phase 3′ of the implementation plan set the goal of collapsing the prover/verifier flow onto a single LVCS commitment, eliminating the legacy mask Merkle tree, and aligning the Fiat–Shamir transcript with the SmallWood schedule. This document captures the engineering steps that landed in this iteration, the tests used to validate them, and the remaining compatibility shims.

## Transcript Changes

### Round 3 (`h3`) – Baseline and current state

- **Before:** Layout V2 proofs already populated `Proof.OracleEval`, but the prover continued to hash the legacy mask Merkle artefacts (`MRoot`, trimmed `MRPolys`) into round 3. The verifier replay therefore depended on `MR/MRoot`, keeping the old commitment alive.
- **After:** The prover now hashes exactly `{Root, Γ, Γ′, ΓAgg, Q}` for round 3; merged proofs omit mask‑commitment material entirely. `VerifyNIZK` mirrors the new hashing order and rejects any proof that lacks the merged oracle transcript.

### Round 4 (`h4`) – Work completed

1. **Prover:** Layout V2 proofs no longer append the LVCS oracle snapshot prior to grinding the tail challenge; `transcript4` now contains only `{root, Γ, Γ′, eval points/KPoint, C, \bar v, v}`.
2. **Verifier:** Round 4 replay mirrors the new material list. Once the tail set is derived, `verifyLVCSConstraints` rebuilds the masked-prefix/tail openings from `Proof.RowOpening` and ensures both `BarSets` and `VTargets` are consistent with the commitment.
3. **Regression:** `TestVerifyNIZKSnapshotRoundTrip` tampers with `VTargets`/`BarSets` directly to prove the verifier rejects inconsistent transcripts (`PIOP/PACS_Simulation_test.go`).

## Mask Commitment Merge

### Prover pipeline

- Mask polynomials remain a first-class concept. `BuildQLayout` now always supplies the witness and mask slices consumed by `BuildQ`, mirroring the LVCS layout exactly.
- The standalone `decs.Prover` and legacy Merkle artefacts have been removed. `Proof` now relies on the merged LVCS transcript (`RowOpening`, `MOpening`, and mask metadata) to expose mask openings—no separate `OracleEval` payload is sent.

### Verifier adjustments

- `VerifyNIZK` uses the merged DECS opening (`Proof.RowOpening`) as the sole source of row evaluations, enforcing both masked-prefix and tail relations without revealing Ω witness values. The legacy mask commitment verifier has been deleted.

### Test coverage

- `TestMergedLayoutMetadata`, `TestMergedLayoutProofSnapshot`, and `TestVerifyNIZKSmallFieldRoundTrip` exercise the merged transcript end to end.
- Small-field suites (`TestSmallFieldGammaKBinding`, `TestSmallFieldRowLayoutAndQueries`) assert ΣΩ and coefficient invariants using the unified mask rows only.

## Validation Summary

| Command | Purpose |
|---------|---------|
| `go test ./PIOP` | Runs the full suite against the merged layout. |
| `go run ./cmd/ntrucli pacs-small` | Small-field CLI smoke test. |
| `go run ./cmd/ntrucli pacs` | Full PACS CLI smoke test. |

These checks provide coverage across both layout modes and guarantee the merged commitment path works end-to-end.

## Remaining Work

- Proof snapshots and metrics now target the merged layout exclusively. Follow-on diagnostics for Eq.(4) and Eq.(7) remain tracked in the implementation plan.
