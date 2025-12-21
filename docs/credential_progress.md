# Credential Integration Progress

This doc summarizes what is implemented for the credential issuance proof (Spruce-And-AC §B.6) and what remains to reach full showing (post-sign) support.

## Implemented
- **Credential helpers**: params loader, bounds/length checks, commitment builder, challenge sampler, `HashMessage`, and combined target (`R0/R1/K*/T`).
- **Constraint helpers**: commit, center wrap, signature (linear), bounds, hash (cleared-denominator BBS), packing (M1 lower half, M2 upper half).
- **PIOP refactor**:
  - Credential builder path (`BuildWithConstraints`) commits rows, derives masking, binds publics via `BuildPublicLabels` + `LabelsDigest`, records `OmegaTrunc/NColsUsed`, runs `runMaskFS` with `PACS-Credential` personalization.
  - `runMaskFS` fully extracted (FS rounds, masks/Q/QK, evals, tail openings) and used for θ>1; uses compensated masks (PACS style).
  - Verifier replays FS with labels digest and omega/ncols overrides; ΣΩ via `VerifyQK_QK`. An implementation guard rejects proofs with non-zero Fpar rows in the provided domain.
- **Pre-sign statement (working)**:
  - Witness rows: `M1, M2, RU0, RU1, R, R0, R1, K0, K1` (single poly each).
  - Publics: `Com, RI0, RI1, Ac, B, T, BoundB`.
  - Constraints: commit, center wrap (`RU*+RI* = R* + (2B+1)·K*`), hash (cleared denominator, public `T`), packing (m1 lower, m2 upper), bounds (`P_B`, `P_1(K*)`). All in F-par; F-agg empty.
  - Masking: compensated masks; tamper caught by residual constraints. Tests (commit/center/hash/packing/bounds) are green for θ=2, `NCols=8`, `EllPrime=1`, `Rho=1`, `Ell=1`.
- **Orchestration**: `issuance/flow.go` (`PrepareCommit`, `ApplyChallenge`, `ProvePreSign`, `VerifyPreSign`, `SignTargetAndSave`); demo `go run ./cmd/issuance`.
- **Docs**: `docs/credentials.md` as the primary reference for current behaviour.

## Current behaviour notes
- Packing uses full ring split (`N=1024`, half=512): `M1` must be zero on upper half, `M2` zero on lower half.
- Hash accepts negligible abort for non-invertible denominators (no explicit guard).
- Fpar zero guard in verifier is an implementation hardness check; PCS ΣΩ still runs.

## Post-sign (showing) protocol — what to add
Goal: Holder proves knowledge of `(U, M1, M2, R0, R1 [,RU*,R*,K*])` such that `A·U = T` and `T = h_{m1‖m2,(R0,R1)}(B)` (T internal), and optionally `PRF(m2, nonce) = tag` (PRF currently identity).

### Witness rows (single poly, fixed order)
- `M1, M2` (packing enforced)
- `RU0, RU1, R` (optional if re-binding to commit)
- `R0, R1`
- `K0, K1` (if re-proving center wrap)
- `T` (hash output, internal)
- `U` (signature preimage)
- Optional future rows: PRF state if we replace identity PRF

### Public inputs (showing)
- Always: `A` (signature matrix), `B` (hash key), `RI0/RI1` (if we keep issuance randomness), `BoundB`, personalization `PACS-Credential`.
- Optional: `Com, Ac` if re-binding to issuance commitment.
- Nonce/tag (later): nonce public or range-proved; tag public or enforced via PRF constraints.

### Constraints (all F-par unless noted)
1) Signature: `A·U = T` (linear).
2) Hash: `T = HashMessage(B, M1, M2, R0, R1)` (cleared denominator, now bilinear because `T` is a witness).
3) Center (optional): `RU* + RI* = R* + (2B+1)·K*`, `K* ∈ {-1,0,1}`.
4) Packing: `M1` zero on upper half, `M2` zero on lower half.
5) Bounds: `P_B(row)=0` for all witness rows (`M1, M2, RU*, R, R0, R1, T, U`); `P_1(K*)` for carries.
6) Commit re-binding (optional): `Ac·[M1‖M2‖RU0‖RU1‖R] = Com`.
7) PRF/tag (identity placeholder): `tag = m2` (or `tag = m2 || nonce`); later swap in Poseidon/Farfalle gadget.

### Public labels (showing)
Canonical order suggestion: `A, B, RI0, RI1, [Com, Ac], [Nonce, Tag], extras...`; `T` stays witness.

### Degrees / masking
- `d_par = max(2B+1, 2)`; `d_agg` can remain 0. Compensated masks OK; ΣΩ enforced via PCS.

### Testing plan (post-sign)
- Happy path: deterministic vectors, `A·U = T`, `T` internal; verify succeeds.
- Tampering: flip `U`, flip `M2` or `R0/R1`, packing/bound violations, optional `Com` tamper if re-binding.

## Next steps (implementation)
1) Extend `WitnessInputs` to support post-sign rows (`T` internal, `U` present); adjust row builder.
2) Build post-sign `ConstraintSet` (signature + hash + bounds + packing, optional center/commit/PRF).
3) Update public labels to the showing order; keep personalization `PACS-Credential`.
4) Add end-to-end post-sign tests (happy/tamper) with identity PRF placeholder.
