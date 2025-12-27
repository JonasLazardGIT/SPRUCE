# Verification Refactor Plan (PACS/SmallWood faithfulness)

Goal: make the verifier’s checks match the “oracle” model of ePrint 2025/1085. In the paper, the constraint polynomials \(F_j\) are *definitionally* \(f_j(P,\Theta)\) and \(Q_i\) is checked against *opened evaluations* of \(P\) and \(M\) at the FS-chosen evaluation points \(E'\). In our compiled/PCS setting we must give the verifier enough (masked) information at \(E'\) to recompute the RHS of Eq.(4) and compare to the prover’s \(Q(e)\) without leaking the witness.

## What the paper does (binding intuition)
- Prover fixes witness polynomials \(P_i\) (and masks \(M_i\)); \(F_j\) is defined as \(f_j(P,\Theta)\).
- Verifier samples batching randomness \(\Gamma',\gamma'\), prover sends \(Q\).
- Verifier samples \(E'\) via FS *after* seeing \(Q\), queries oracle for \(P(e),M(e)\), computes \(F_j(e)=f_j(P(e),\Theta(e))\), and checks Eq.(4) at those points plus the \(\Sigma_\Omega\) sum.
- Masking and random extension points ensure HVZK: evaluations outside \(\Omega\) are simulatable; \(Q\) is masked by \(M\).

## How to realize this in our code (without breaking ZK)
- Do **not** dump raw \(P_i(e)\) at \(E'\): that would leak witness. Instead, open enough masked data so the verifier can reconstruct the RHS of Eq.(4) at \(E'\) without isolating \(P\).
- Use the existing masks \(M\): at \(E'\), provide \(M_i(e)\) and either:
  - the masked rows \(P_i(e)\) together with a clear recipe to derive \(f_j(P(e),\Theta(e))\); or
  - directly provide the prover’s claimed \(F_j(e)\) and allow the verifier to recompute expected \(Q(e)\) from \(M(e),F(e),\Gamma',\gamma'\).
- Check consistency: reconstructed \(Q(e)\) must match the committed \(Q\) at each \(e\in E'\); if not, reject before \(\Sigma_\Omega\).

## Prover-side changes
1) **Capture data at PCS eval points \(E'\):**
   - In `runMaskFS` (round 3, after FS sampling of eval points), evaluate mask polys \(M_i(e_t)\) and either:
     - (a) evaluate witness rows \(P_i(e_t)\) and derive \(F_j(e_t)=f_j(P(e_t),\Theta(e_t))\) on the prover side, or
     - (b) evaluate \(P_i(e_t)\) and let the verifier derive \(F_j(e_t)\). For ZK, prefer (a) and send masked values only.

2) **Embed into openings/proof (current status):**
   - Extend `DECSOpening`/`RowOpening` or add a new proof field to carry, for each \(e_t\):
     - `EvalPoints` = \(E'\) (FS-derived).
     - `MvalsEval[t][i] = M_i(e_t)` (mask evals).
     - Either `FvalsEval[t][j]` (prover-computed \(F_j(e_t)\)) or `PvalsEval[t][i]` (row evals) if we let the verifier compute \(F\).
   - Pack/unpack (similar to PvalsBits).
   - Update `combineOpenings` if reusing DECS openings; adjust proof serialization/size accounting.
   - **Implemented for θ>1 K‑points:** `PvalsKEval` is populated from committed rows (`pk.RowPolys`) and stored in the proof, so the verifier can replay constraints at K‑points without relying on precomputed F‑polys.

3) **Q commitment unchanged:**
   - Prover still sends \(Q\) polynomials as before (NTT/barSets/etc.); the extra data is only for consistency checking.

## Verifier-side changes
4) **Unpack eval data:**
   - In `VerifyNIZK` (or a credential/showing wrapper), after FS rounds, unpack `EvalPoints`, `MvalsEval`, and `FvalsEval` (or `PvalsEval` if verifier computes \(F\)).
   - Map rows to variables using layout metadata (pre-sign fixed order; showing via `PRFLayout`).

5) **Recompute expected \(Q(e)\):**
   - For each \(e_t\):
     - If prover provided `FvalsEval`: use them directly.
     - If prover provided `PvalsEval`: compute \(F_j(e_t)=f_j(P(e_t),\Theta(e_t))\) using public params.
     - Compute \(Q^{\text{exp}}_i(e_t) = M_i(e_t) + \sum_j \Gamma'_{i,j}(e_t)F_j(e_t) + \sum_j \gamma'_{i,j}F'_j(e_t)\).
     - Compare \(Q^{\text{exp}}_i(e_t)\) to the prover’s \(Q_i(e_t)\) (evaluate committed \(Q\) at \(e_t\)).
     - If any mismatch, reject early.

6) **Proceed with PCS checks:**
   - If consistency holds at all \(E'\), run \(\Sigma_\Omega\)/Eq.(4) as today on the prover’s \(Q/M\) polynomials.

## Layout/metadata
- Ensure `ConstraintSet`/`Proof` carry:
  - Pre-sign row order (M1,M2,RU0,RU1,R,R0,R1,K0,K1,...).
  - Showing `PRFLayout` (startIdx, LenKey, LenNonce, RF, RP, LenTag) to map PRF trace rows.
  - `EvalPoints` so both sides align evaluations.

## Theta / small-field
- θ=1: values are in base field; straightforward.
- θ>1: evals may be in small-field limbs (barSets/vTargets). Decide whether to convert to base field for consistency check or evaluate in the extension field; adjust packing accordingly.

## Current status (as of latest refactor)
- **Row head aliasing fixed**: each `RowInput.Head` is copied (no shared backing array), which fixed ΣΩ mismatches.
- **K‑point replay integrated**: `EvaluateConstraintsOnKPoints` is wired for credential pre‑sign and uses `PvalsKEval`.
- **Constraints rebuilt from committed rows**: pre‑sign constraints are rebuilt from `pk.RowPolys` so \(F_j=f_j(P,\Theta)\) includes LVCS tails.

## Next concrete steps
1) **Extend K‑point replay to showing/PRF**: add a PRF K‑point evaluator and wire it in the showing builder.
2) **Eval‑domain replay (E′)**: expose eval‑point row openings for θ>1 and use the same evaluator path on E′ (no reliance on prebuilt F‑polys).
3) **Remove remaining legacy checks** once the evaluator path is fully in place (Eq.(4) replay should be the primary check, ΣΩ remains as in the paper).

## Files to touch
- `PIOP/run.go` / `masking_fs_helper.go`: capture \(E'\), evaluate \(M\) (and \(P/F\) as needed) at \(E'\), store in proof.
- `LVCS`/`DECS`: extend openings/packing for eval tables.
- `Proof` struct (PIOP/run.go): add EvalPoints/MvalsEval/FvalsEval (or PvalsEval) fields; update serialization/size counters.
- `VerifyNIZK.go`: unpack eval data; for credential/showing, recompute \(Q^{exp}(e)\) and compare to prover’s \(Q(e)\) before running \(\Sigma_\Omega\).
- Evaluator helpers: functions to compute pre-sign residuals and PRF residuals at a point from row evals/public params.

## Testing
- Honest proofs: reconstructed \(Q(e)\) matches prover’s; PCS checks still pass.
- Tamper rows/F/Q: consistency check at \(E'\) fails.
- ZK: only masked data revealed at \(E'\); do not expose raw witness without masks.
