# Credential Module (Issuance) — Current State

This document captures the credential issuance flow (Spruce-And-AC §B.6), the supporting helpers, and the enforced constraints in the current codebase. It is aligned with the working pre-sign proof and `cmd/issuance` demo.

## Core packages and APIs
- **Params** (`credential/params.go`): JSON-driven loader for `Ac`, `BPath`, `BoundB`, block lengths (`LenM1/LenM2/LenRU0/LenRU1/LenR`). Loads ring from `Parameters/Parameters.json` (`N=1024, q=1038337`). `Ac` JSON: rows × cols × coeffs; lifted to NTT and dimension-checked.
- **Types** (`credential/types.go`): holder state (`M1,M2,RU0,RU1,R`), issuer challenge (`RI0,RI1`), transcript/credential structs.
- **Bounds** (`credential/bounds.go`): coeff-centering bound check and length check helpers.
- **Helpers** (`credential/helpers.go`): `CenterBounded/CombineRandomness`, `HashMessage` (explicit BBS hash on coeff inputs, B in NTT, returns centered coeffs), `LoadDefaultRing`.
- **Commitment** (`credential/commit.go`): validates shapes/bounds, flattens `[M1‖M2‖RU0‖RU1‖R]`, lifts to NTT, calls `commitment.Commit`.
- **Challenge** (`credential/challenge.go`): samples `RI0/RI1` in `[-BoundB,BoundB]`, NTT-lifted.
- **Target** (`credential/target.go`): coeff-side `R0/R1 = center(RU*+RI*)`, loads `B`, hashes to `T` (single-poly message blocks).
- **Issuance orchestration** (`issuance/flow.go`): `PrepareCommit`, `ApplyChallenge` (computes `R0/R1/K0/K1`, loads B, hashes to `T`), `ProvePreSign`/`VerifyPreSign`, `SignTargetAndSave`.
  - Demo: `go run ./cmd/issuance` builds deterministic inputs, proves/verifies pre-sign, signs `T`, copies signature to `credential/keys/signature.json`.
  - Recommended opts for pre-sign: `Theta=2, EllPrime=1, Rho=1, NCols=8, Ell=1, Credential=true`.

## Pre-sign credential PIOP (π_t)
- **Witness rows (single poly, fixed order)**: `M1, M2, RU0, RU1, R, R0, R1, K0, K1`. Carries `K*` encode wrap (`RU*+RI* = R* + (2B+1)·K*`, `K* ∈ {-1,0,1}`).
- **Publics**: `Com, RI0, RI1, Ac, B, T, BoundB` bound into FS via `BuildPublicLabels` + `LabelsDigest` (personalization `PACS-Credential`). `T` is public in issuance.
- **Constraints (all F-par; F-agg empty)**:
  - Commit: `Ac·[M1‖M2‖RU0‖RU1‖R] = Com`
  - Center wrap: `RU* + RI* = R* + (2B+1)·K*`
  - Hash (cleared denominator, public `T`): `(B3 − R1) ⊙ T − (B0 + B1·(M1+M2) + B2·R0) = 0` (nonzero-denominator accepted as negligible abort)
  - Packing: `M1` zero on upper half of the ring, `M2` zero on lower half (N=1024 ⇒ half=512)
  - Bounds: membership `P_B(row)=0` for all witness rows; `P_1(K*)=0` for carries; Go-side scan also checks bounds.
- **Masking / ΣΩ**: θ>1 uses compensated masks (PACS style) so ΣΩ=0 on valid inputs; tampering is caught by non-zero residuals. `DEBUG_QK=1` logs QK mismatches if ΣΩ fails.
- **Verifier**: `VerifyNIZK` replays FS with LabelsDigest and OmegaTrunc/NColsUsed overrides; ΣΩ via `VerifyQK_QK`. An implementation guard additionally rejects if any Fpar residual row is non-zero in the provided domain.

## Constants
- Ring: `N=1024`, `q=1038337` (`Parameters/Parameters.json`).
- B matrix: `Parameters/Bmatrix.json`.
- BoundB: from params, should match PIOP bound used in credential proofs.

## NTRU signing
- `signverify.SignTarget(tCoeffs, maxTrials, opts)` signs `T` with stored trapdoor keys (`./ntru_keys`).
- CLI: `go run ./cmd/issuance` for end-to-end; `cmd/ntrucli`/`cmd/ntru_sign` remain available for ad-hoc signing.

## Remaining work
- Post-sign (showing): add row `U`, constraint `A·U = T`, decide whether to re-bind to `Com/Ac`, and add PRF/tag gadget (PRF currently identity).
- Optional: explicit nonzero-denominator guard in the hash gadget instead of relying on negligible abort.
