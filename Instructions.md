# Credential Issuance Augmentation – Implementation Guide

This guide describes how to implement the augmented Holder–Issuer protocol from **docs/Spruce-And-AC.pdf** (§B.6) using the existing DECS/LVCS/PCS/PACS PIOP stack. It references current code, docs, constants, and proposes progressive steps with tests. Fill in any **MORE CONTEXT NEEDED** items before coding.

---

## 0. Existing code & docs to reuse
- **Signer/target pipeline**: `ntru/signverify/signverify.go` (`SignTarget`, `Verify`), `ntru/hash_bridge.go` (`ComputeTargetFromSeeds`), `vSIS-HASH/vSIS-BBS.go` (hash), docs `docs/NTRU.md`, `docs/preimage_sampling_docs.md`.
- **PIOP stack**: `PIOP/run.go`, `PIOP/PACS_Statement.go`, `PIOP/VerifyNIZK.go`, DECS/LVCS under `DECS/`, `LVCS/`; Merkle/packing docs `docs/Merged_Merkle.md`; CLI overview `docs/CLI.md`, `cmd/pacs_sweep/README.md`.
- **Commitment helper**: `commitment/linear.go` (+ `docs/commitment.md`), `credential/helpers.go` (`CombineRandomness`, `HashMessage`, `CenterBounded`, `LoadDefaultRing`; docs `docs/credential.md`).
- **Witness/hash recomputation**: `PIOP/build_witness.go` (shows how `vsishash.ComputeBBSHash` is wired into constraints).
- **Constants**: default ring from `Parameters/Parameters.json` (`n=1024`, `q=1038337`), B-matrix `Parameters/Bmatrix.json`. Bounds `BoundB` for new vectors must be specified (**MORE CONTEXT NEEDED - Use the same ones as used in the bound B for the PIOP when checking the bounds of the Message**).

---

## 1. Parameters & data modeling
1.1 Create `credential/params.go`
- Struct fields: `AcPath`, `BPath` (default `Parameters/Bmatrix.json`), `BoundB`, lengths `LenM1, LenM2, LenRU0, LenRU1, LenR`, optional `APath`.
- Loader: read `AcPath` JSON, fall back to parent dirs (mirror `loadParams` in `ntru/signverify`). Parse into `commitment.Matrix` (NTT domain expected).
- Validation: `cols(Ac) == LenM1 + LenM2 + LenRU0 + LenRU1 + LenR` else error.
- **MORE CONTEXT NEEDED - Make the most logical schema**: JSON schema/path for `Ac` (format, domain).

1.2 Create `credential/types.go`
- `HolderState { M1, M2, RU0, RU1, R []*ring.Poly }`
- `IssuerChallenge { RI0, RI1 []*ring.Poly }`
- `Transcript { Com []*ring.Poly; PiCom PiCom; T []int64; PiT PiT; U []int64 }`
- `Credential { U []int64; M1, M2, R0, R1 []*ring.Poly; Com []*ring.Poly; Meta (params ID, B file) }`

---

## 2. Bound helpers
2.1 Add `credential/bounds.go`
- `CheckBound(vec []*ring.Poly, bound int64) error` scanning coeffs (similar to `ntru/CenterModQToInt64` checks).
- `CheckLengths(vec []*ring.Poly, want int, name string)`.
- Use `BoundB` for all (m1, m2, rU0, rU1, r, rI0, rI1, r0, r1).

---

## 3. Commitment circuit (Message 1)
3.1 Build `ProveCom`/`VerifyCom`
- Flow: validate shapes/bounds → `commitment.Commit(ringQ, Ac, vec)` where `vec = [M1||M2||RU0||RU1||R]`.
- Circuit: new PIOP statement (e.g., `PIOP/commit_statement.go`):
  - Publics: `Ac`, `Com`.
  - Witness: `vec`.
  - Constraints: `Ac·vec = Com` (component-wise ring equality), bounds on each coeff.
  - Reuse gadgets: infinity-norm/coeff bounds from `PIOP/fpar_linf.go`, `PIOP/fpar_membership.go`; polynomial handling from `PIOP/run.go`.
  - Use existing FS/grinding/masking pattern (`PIOP/run.go`/`PACS_Statement.go`).
- APIs:
  - `ProveCom(params, holderState) (Com []*ring.Poly, PiCom, error)`
  - `VerifyCom(params, Com []*ring.Poly, PiCom) error` calling `PIOP.VerifyNIZK` on the new statement.

3.2 Testing
- Deterministic PRNG → build holder state, run `ProveCom/VerifyCom`.
- Negative: tamper `Com`, expect failure; exceed bounds, expect failure.

---

## 4. Issuer challenge (Message 2)
4.1 Sampling `rI0, rI1`
- Use `FillPolyBoundedFromPRNG` + clamp to `[-B,B]` (or direct uniform in `[0,q)` then center/wrap to `[-B,B]`).
- Ensure lengths match `LenRU0`, `LenRU1`.
- Package as `IssuerChallenge`.
- **MORE CONTEXT NEEDED - Uniform distribution**: exact distribution for issuer randomness (uniform over `[-B,B]`? domain size).

---

## 5. Target computation & circuit (Message 3)
5.1 Combine randomness
- `R0 = CombineRandomness(RU0, RI0, BoundB)`, `R1 = CombineRandomness(RU1, RI1, BoundB)` (`credential/helpers.go`).

5.2 Hash to target
- `T = HashMessage(ringQ, B, M1, M2, R0, R1)` → centered `[]int64` (as in `HashMessage` / `PIOP/build_witness.go`).

5.3 Target circuit (new PIOP statement, e.g., `PIOP/target_statement.go`)
- Publics: `Com`, `RI0`, `RI1`, `B`, `Ac`, `T`.
- Witness: `(M1, M2, RU0, RU1, R)`.
- Constraints:
  - `Ac·vec = Com` (reuse commit gadget).
  - `R0 = center(RU0 + RI0)`, `R1 = center(RU1 + RI1)`; encode wrap: `(x+B) mod (2B+1) - B` with modular equality constraints.
  - `T = HashMessage(B, M1, M2, R0, R1)`; reuse the exact arithmetic from `PIOP/build_witness.go`/`vsishash.ComputeBBSHash`. Implement as deterministic gadget in-circuit (NTT lifts + hash) and constrain equality.
  - Bounds on all secret vectors.
- APIs:
  - `ProveT(params, Com, challenge, holderState) (T []int64, PiT, error)`
  - `VerifyT(params, Com, challenge, T, PiT) error`.

5.4 Testing
- Happy path with deterministic inputs.
- Negative: tamper `Com` or `T`, wrong `RI*`, bound violations.

---

## 6. Signature issuance (Message 4)
6.1 Sign and verify
- After `VerifyT`, Issuer: `signverify.SignTarget(T, maxTrials, defaultOpts)` (explicit target).
- Holder: lightweight check `A·U = T (mod q)` + norm using `ntru.CheckNormC` or `signverify.Verify` (skip seed checks if seeds empty).
- Store credential: `(U, M1, M2, R0, R1, Com, T)` for showing.
- **MORE CONTEXT NEEDED - reuse sampler defaults and document it**: Norm bound to enforce on `U` (reuse sampler defaults? explicit β∞?).

6.2 Testing
- Happy path signer with deterministic `T`.
- Negative: tamper `U`, expect verification fail.

---

## 7. Showing (identity PRF constraints, upgradeable)
7.1 PRF model
- For now: `Tag = M2` or `Tag = concat(M2, Nonce)` identity; encode as equality constraint (no placeholder struct).
- Add `DeriveTag` helper returning the chosen identity mapping; keep interface ready for Poseidon later.
- **MORE CONTEXT NEEDED**: Desired nonce domain / range proof requirement.

7.2 Showing circuit (new PIOP statement, e.g., `PIOP/show_statement.go`)
- Publics: `Tag`, `Nonce` (optional), `A`, `B`.
- Witness: `(U, M1, M2, R0, R1)`.
- Constraints:
  - `A·U = HashMessage(B, M1, M2, R0, R1)` (reuse hash gadget).
  - `Tag = PRF(M2, Nonce)` (identity now).
  - Bounds on `(M1, M2, R0, R1)`.
  - Optional: range proof on `Nonce` if hiding the value (reuse/extend existing range gadgets if available; otherwise mark **MORE CONTEXT NEEDED**).
- APIs: `ProveShow(cred, nonce) -> tag, π_show`; `VerifyShow(tag, nonce, π_show)`.

7.3 Replay protection
- Verifier keeps map of seen `tag` (and `nonce` if public) to reject reuse.

7.4 Testing
- Happy path: show verifies, tag marked used.
- Negative: reused tag rejected; tampered `tag`/`U` fails verification.

---

## 8. PIOP integration details
- Follow `PIOP/run.go` and `PIOP/PACS_Statement.go` patterns:
  - Build witnesses, interpolate rows (`BuildRowPolynomial`), sample masks, Merkle-pack (`docs/Merged_Merkle.md`).
  - Use grinding knobs (`SimOpts.Kappa`), rows/degree logic from existing PACS builder.
- For new statements, keep separate statement builders to avoid entangling with existing PACS constraints but reuse shared gadgets (norm checks, packing, FS).
- Hash gadget: replicate the path in `PIOP/build_witness.go` where `vsishash.ComputeBBSHash` is called (NTT lifts of m/x0/x1, Hadamard products, inv NTT).
- Commitment gadget: polynomial linear form; use `ring.MulCoeffs` + accumulation, same as `BuildWitness` uses for `A·s` in NTT domain.

---

## 9. CLI and persistence
- Optional CLI `cmd/credentialcli`:
  - `issue`: runs commit proof, issuer challenge, target proof, signing; emits JSON (com, π_com, π_t, u, params).
  - `show`: loads credential, derives tag, runs show proof, prints tag/nonce.
- Persistence: JSON encoding for params, transcript, credential; mirror style in `ntru/keys` and `measureutil/snapshot.go`.
- **MORE CONTEXT NEEDED - Make the most logical file artifact so that we can replay authentications**: Desired file layout for new JSON artifacts.

---

## 10. Testing matrix
- Unit: bounds helpers, CombineRandomness, HashMessage consistency (vs `ComputeTargetFromSeeds` when m2=0, as in `credential/helpers_test.go`), commitment/target/show proofs happy-path & tamper cases.
- Integration: end-to-end issuance (H→I→H) with deterministic seeds; showing with identity PRF; replay rejection.
- Performance sanity: optional `-short` to skip heavy signing (`RUN_SLOW_SIGN=1` already gates SignTarget test).

---

## 11. Constants & domains
- Ring: `N=1024`, `q=1038337` (from `Parameters/Parameters.json`); adjust if params change.
- B-matrix: `Parameters/Bmatrix.json`.
- Bounds: existing sampler bound/β∞ documented in `docs/NTRU.md` (β∞ ≈ 6000 for signatures). New `BoundB` for m1/m2/r* must be set (**MORE CONTEXT NEEDED - This bound needs to be the same as the gadget in the PIOP (likely 7-8)**).
- Grinding: reuse defaults in `PIOP` (`κ_i` = 16 unless overridden).
- Hash domain: same as current BBS hash over ring q.

---

## 12. Open questions (**MORE CONTEXT NEEDED**)
- Exact Ac storage format and path; whether Ac is NTT or coeff domain in JSON.
- Concrete `BoundB` for m1/m2/r* and issuer randomness domain.
- Desired nonce domain/range proof for showing; whether nonce is public or hidden.
- File layout for new credential/transcript JSON artifacts.
- Norm bound to enforce on signer output `U` (use sampler defaults or explicit threshold?).

---

## 13. Progressive workflow
1) Implement params/types/bounds helpers.  
2) Build commitment statement + tests.  
3) Implement challenge sampling.  
4) Build target statement (reuse hash gadget) + tests.  
5) Wire signing/credential bundling.  
6) Build showing statement with identity PRF + replay check.  
7) Add CLI/persistence if desired.  
8) Run full test matrix; address **MORE CONTEXT NEEDED** items before merging.
