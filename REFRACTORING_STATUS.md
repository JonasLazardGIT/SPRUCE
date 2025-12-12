# Refactoring Status and Plan (Credential Integration, §B.6)

This document summarizes the changes made so far, why the work is taking time, current status relative to Spruce-And-AC §B.6 (excluding PRF/tag), and what remains. It also explains why finishing the PIOP refactor will make adding further constraints (e.g., PRF) straightforward.

## What’s been done (updated)

- **Credential helpers/types**: Added parameter loaders, bounds/helpers, and witness/commit functions (`credential/params.go`, `credential/helpers.go`, `credential/commit.go`). Defined `PublicInputs`/`WitnessInputs` and constraint helpers (`BuildCommitConstraints`, `BuildCenterConstraints`, `BuildSignatureConstraint`, `BuildBoundConstraints`) to mirror the credential issuance flow (commit, center combine, hash) from §B.6.
- **FS/public binding**: Added deterministic public-label builder (`BuildPublicLabels`), removed T from publics to keep the hash internal (per §B.6), and kept constraints data-driven.
- **Credential scaffolding**: Added a `Credential` flag to `SimOpts`, stubs for `credentialBuilder`/`BuildWithConstraints`, placeholders for a generic masking/FS driver (`RunMaskingFS`), and validation helpers for single-poly inputs.
- **PIOP refactor groundwork (now largely complete)**:
  - Extracted ring/Ω setup (`loadParamsAndOmega`), LVCS commit wrapper (`commitRows`), and masking config helper (`deriveMaskingConfig`).
  - Introduced carrier structs `maskFSArgs`/`maskFSOutput` and a `runMaskFS` helper. `runMaskFS` now covers FS init, Rounds 1–3 (Gamma/GammaPrime/GammaAgg, eval sampling), mask/Q generation, tail sampling/openings, proof field population, and stores the prover’s tail transcript.
  - `buildSimWith` (θ>1) delegates to `runMaskFS`; snapshot/restore carries `TailTranscript`; round-3 digest mismatch is fixed. PACS path remains green.
- **Documentation**: `docs/credential_progress.md` and `docs/masking_fs_refactor.md` track the plan and staged extraction steps.

## Why it’s taking time

- The masking/Merkle/FS loop in `buildSimWith` is large and tightly coupled to PACS-specific state: small-field handling (Theta>1), mask/Q generation, FS transcript packing, proof field population, and downstream verification (okLin/okEq4/okSum, ctx fields). Extracting it without regressing tests requires staged moves and careful plumbing of intermediate data (barSets, coeffMatrix, kPoints, openings, vTargets).
- We’re preserving the current PACS behaviour and tests. Each refactor step is small and validated with `go test ./PIOP ./tests` to avoid behavioural drift.
- Aligning with §B.6 (commit + center + hash internal, PRF later) while keeping the PACS prover/verifier intact until the generic path is ready adds complexity.

## Current status relative to §B.6 (excluding PRF/tag)

- Credential-side helpers and constraint skeletons exist; T is intended to be internal, matching §B.6’s requirement to prove the hash.
- PIOP refactor: setup/helpers extracted; `runMaskFS` is fully functional and used by θ>1 (small-field) path. PACS tests pass.
- Generic builder/verify and credential constraint wiring are still pending. Hash constraints are still external in PACS; PRF/tag constraints are not added yet.

## Why finishing the refactor eases adding PRF/other constraints

- With `buildSimWith` delegating to `runMaskFS` via a generic `BuildWithConstraints`, the prover will accept explicit constraint sets (F-par/F-agg). Adding a new constraint (e.g., PRF, range checks) becomes:
  1. Build residual polys for the constraint and add to `ConstraintSet`.
  2. Feed the set into the generic builder; masking/FS/Merkle handle it uniformly.
- Verification will likewise be data-driven once `VerifyWithConstraints` is in place; supplying the F-polys and public labels enforces new constraints without hand-coded paths.
- PRF/tag from §B.6 can then plug in as an additional constraint family without structural rewrites.

## Remaining steps (updated)

1) **Generic builder/verify path**
   - Implement `BuildWithConstraints` to drive `runMaskFS` with explicit publics/witnesses/constraint sets and a personalization string.
   - Implement `VerifyWithConstraints` (or extend `VerifyNIZK`) to accept personalization/public labels and supplied F-par/F-agg polys; keep PACS as a thin wrapper using PACS personalization.

2) **Credential constraint set and builder**
   - Build vec = concat(M1, M2, RU0, RU1, R) (NTT).
   - Constraints: commit (Ac·vec=Com), center (center(RU*+RI*)=R*), in-circuit hash T=HashMessage(B,M1,M2,R0,R1) using the existing PACS hash gadget, bounds; optional signature residual later.
   - Implement `credentialBuilder.Build/Verify` on top of `BuildWithConstraints` with `FSModeCredential`; update `run_credential`.

3) **Hash/PRF integration**
   - Refactor PACS hash gadget into a helper that takes explicit polys (B, M1, M2, R0, R1) and emits F-par/F-agg; remove public T.
   - Add PRF/tag constraints per §B.6 once the credential path is stable.

4) **Tests/Docs**
   - Add credential-mode tests (happy/tamper/bounds); ensure PACS regression stays green.
   - Update docs (`docs/credentials.md`, `docs/credential_progress.md`, `docs/masking_fs_refactor.md`) to reflect the generic builder, credential constraint set, and remaining PRF work.

With the refactor complete, adding PRF/tag and other constraints becomes an additive change to the constraint set rather than a structural rewrite.

## Commitment package (what exists today)

- **Purpose**: Bind all user material `(m1 || m2 || rU0 || rU1 || r)` into a linear commitment `com = Ac · vec` (NTT domain), as required by §B.6 message 1.
- **Implementation**: `credential/commit.go` uses `commitment.Commit` (from `commitment/linear.go`) over a public matrix `Ac` to produce `com`. Shapes/bounds are validated: single-poly blocks, `cols(Ac) == len(vec)`, `rows(Ac) == len(com)`, and coefficients within `[-BoundB, BoundB]`.
- **Parameters**: `Ac` is loaded via `credential/params.go`, which parses JSON, builds `commitment.Matrix` (NTT), and checks dimensions. `BoundB` matches PACS bounds; single-poly restriction enforced.
- **Functioning**: Caller builds `vec` by concatenating the witness polys, validates lengths/bounds, then calls `Commit(p.Ac, vec)` to get `com`. The resulting commitment is used as a public in the credential transcript and will be tied into constraints (`BuildCommitConstraints`) in the credential NIZK.
