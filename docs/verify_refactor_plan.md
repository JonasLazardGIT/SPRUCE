# Verification Refactor Plan (PACS/SmallWood faithfulness)

Goal: make the verifier evaluate constraint functions on opened witness rows (as in ePrint 2025/1085), instead of trusting prover-supplied F-polys. This single change fixes soundness for both pre-sign (issuance) and post-sign (showing/PRF) proofs.

## Overview
- Expose witness row evaluations at FS-sampled points to a constraint evaluator.
- Add a verifier-side evaluator hook: given row evals + public params/metadata, compute constraint residuals at each point and batch them into Q for Eq.(4)/ΣΩ.
- Carry layout metadata (row ordering, PRF layout) so the evaluator can map rows to variables.
- Keep prover/proof format mostly intact; verifier recomputes constraint values, binding them to the commitment.

## Step-by-step modifications

### 1) Proof/metadata
- Add PRFLayout (already present) and, if needed, pre-sign layout metadata to `ConstraintSet`/`Proof` so the verifier knows row ordering (startIdx, LenKey/LenNonce, RF/RP, LenTag).
- Optionally add a flag to skip using stored FparNTT/FaggNTT for constraints covered by evaluator.

### 2) Expose row openings to verification
- In `VerifyNIZK`, after LVCS/DECS openings, collect `Pvals` at the FS evaluation points (E'). Currently they are only used internally for subset checks; make them available to a new constraint-eval path.
- Provide these as a slice per point: `[][]uint64` or `[]*ring.Poly` evaluations of all committed rows.

### 3) Constraint evaluator hook
- Define an interface/helper (e.g., `evalConstraintsAtPoint(evals []uint64, layout, pub) -> (parVals, aggVals)`) that:
  - Uses row evals + public params to compute constraint residuals at a single point.
  - Returns the batched contribution under Γ′/γ′ or the raw residual vector.
- Integrate this into Eq.(4): instead of using stored Fpar/Fagg polynomials, compute Q(e) with the evaluator outputs.

### 4) Implement evaluators
- Pre-sign evaluator:
  - Map rows to M1,M2,RU0,RU1,R,R0,R1,K0,K1 (use fixed ordering).
  - Compute commit residuals with Ac/Com, center wrap with RI*/K*, hash with B/T, packing/bounds as needed.
- Post-sign/PRF evaluator:
  - Use PRFLayout to locate x^(r)_j rows.
  - For each eval point: compute external/internal round residuals with public ME/MI/cExt/cInt/d, tag binding, nonce binding (public).
- Both: accumulate under Γ′/γ′; no need to materialize full residual vectors.

### 5) Wire into verifier
- In `VerifyWithConstraints` for Credential/showing mode, bypass stored FparNTT for constraints covered by evaluator; run the evaluator at each FS point to build Q(e) before ΣΩ/Eq4.
- Keep existing path for legacy constraints if needed; make showing use the evaluator.

### 6) Prover adjustments
- Prover still commits rows and runs masking/FS; no need to change commitments.
- Optionally stop snapshotting FparNTT/FaggNTT for PRF constraints to avoid confusion; keep for others.
- Ensure layout metadata is included in `ConstraintSet`/proof for the verifier.

### 7) Theta support
- Decide whether to support θ>1 immediately; if yes, ensure evaluator can handle small-field openings (convert to base field or evaluate consistently). Otherwise, gate showing verifier to θ=1 until extended.

### 8) Testing
- Pre-sign tamper: flip a row coeff (e.g., R0) -> evaluator recomputes non-zero residual -> verify fails.
- Post-sign PRF tamper: flip trace row/tag/nonce -> PRF residual non-zero -> fail.
- Honest proofs still pass.

## Files likely touched
- `PIOP/VerifyNIZK.go`: expose openings, integrate evaluator into Eq.(4).
- `PIOP/generic_builder.go` / `VerifyWithConstraints`: select evaluator path for Credential/showing.
- `PIOP/credential_constraints.go` (or new evaluator file): implement pre-sign evaluator functions.
- `PIOP/showing_builder.go` / `PIOP/credential_constraints.go` (PRF): implement PRF evaluator using `PRFLayout`.
- `PIOP/builder_types.go`: carry layout metadata in `ConstraintSet`/`Proof`.

## Notes
- This keeps ZK: only opened values at FS points are used, as in the paper’s oracle model.
- The key change is in the verifier: constraint values come from evaluating public functions on opened witness rows, not from prover-supplied F-polys.
