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

### PIOP scaffolding for future credential mode
- Added `Credential` flag to `SimOpts`; `RunOnce` branches to `runCredential` (stub) while PACS runs via `runPACS`.
- Introduced builder-oriented stubs:
  - `PublicInputs`, `WitnessInputs`, `StatementBuilder` interface.
  - `MaskConfig/MaskConfigFromOpts`.
  - Stub constraint helpers (`BuildCommitConstraints`, `BuildCenterConstraints`, `BuildSignatureConstraint`).
  - Stub FS public-label builder (`BuildPublicLabels`).
  - `pacsBuilder` wraps the existing PACS prover/verifier behind `StatementBuilder`; `credentialBuilder` stub exists.

### Documentation
- `docs/credentials.md`: Captures params schema, helper APIs, current restrictions (single-poly blocks), and TODOs.
- Tests added for flag survival and mask config; credential path remains stubbed.

## Current behaviour
- Core PACS prover/verifier untouched; credential mode returns “not implemented.”
- Hash-to-target remains external; no hash constraints inside the circuit yet.
- Full test suite still has the pre-existing `ntru/TestSampleZVecStatistics` drift (unrelated to credential scaffolding).

## Next steps toward the Holder→Verifier NIZK (post-signing)

1) **Finalize public/witness ordering and FS binding**
   - Implement `BuildPublicLabels` to encode publics in a deterministic order (Com, RI*, Ac, B, T, U, existing PACS publics) and feed FS personalization.

2) **Constraint helpers**
   - Replace stubs with real gadgets:
     - Linear form equality `Ac·vec = Com` (NTT domain) returning residual polys.
     - Center wrap gadget: per-coeff `(RU+RI) recentered to R` modulo `2*B+1`.
     - Signature check `A·U = T` (optional, if included in the Holder→Verifier proof).
     - Reuse existing bound gadgets for all witness polys.

3) **Credential builder**
   - Implement `credentialBuilder` to accept explicit publics/witnesses and produce/verify proofs through the common masking/prover pipeline.
   - Factor masking/degree setup into a reusable function that takes a list of F-polys (commit/center/sig) to be masked and included in Merkle commits; reuse DECS/LVCS parameters from PACS.

4) **Integrate into RunOnce**
   - On `SimOpts.Credential`, build publics/witnesses from the credential inputs, instantiate `credentialBuilder`, and run the prover/verifier, populating `SimReport` accordingly.

5) **End-to-end NIZK (post-signing)**
   - Target showing proof between Holder and Verifier should check:
     - `Com` commitment to (m1,m2,rU0,rU1,r) is consistent.
     - `R0/R1 = center(RU*+RI*)`.
     - (Optional) `A·U = T` to bind the signature to `T`.
     - Bounds on all secret vectors.
   - `T` may remain an external public input if hash constraints are deferred.

6) **Testing**
   - Deterministic happy-path: build Com, RI*, R0/R1, external T, signature U; prove/verify in credential mode.
   - Tampering tests: change Com, RI*, U/T, or violate bounds → verification fails.
   - Ensure existing PACS tests continue to pass.

7) **Docs update**
   - Update `docs/credentials.md` with finalized public ordering, constraint set, and usage examples once the credential builder is wired.

With these steps, the codebase will support a modular credential statement and a post-signing NIZK that enforces the commitment and randomness identities, ready to be extended with hash/signature checks as needed.
