# Credential Protocol (Issuance + Showing)

This document is the primary reference for the credential protocol (Spruce-And-AC B.6) as implemented in this repo. It provides:
- A protocol-level description (math/spec) of issuance and showing.
- A code-level map of the core functions and where to find them.
- The current row layout and constraint set used by the PIOP/PACS stack.

The current implementation is aligned with the working pre-sign (issuance) proof and the post-sign (showing) proof as exercised by `cmd/issuance` and `cmd/showing`.

## 1) Protocol-level description

### 1.1 Setup
Public parameters:
- Ring: `N=1024`, `q=1038337` (from `Parameters/Parameters.json`).
- Signature matrix `A` (issuer holds trapdoor; used for `A·u = t`).
- Hash key matrix `B` for the vSIS/BBS rational hash `h_{m,(r0,r1)}(B)`.
- Commitment matrix `Ac` (random; used in Ajtai-style linear commitment).
- Bound `B` (the coefficient bound used in all shortness checks).
- Center function `center(x)` maps `[-2B,2B] -> [-B,B]` by wrapping around the interval.

Roles:
- Holder (H): chooses message split `m = m1 || m2` and user randomness.
- Issuer (I): provides challenge randomness and signs `t` with a trapdoor sampler.
- Verifier (V): checks showing proof and enforces non-reuse via tag (PRF).

### 1.2 Issuance (pre-sign)
Let `m1, m2, rU0, rU1, r` be Holder values (all in `[-B,B]` coefficient-wise). The Holder commits to them and later proves correctness of the target `t`.

1) Holder samples:
- `m1` (public credential material) and `m2` (secret PRF key material).
- `rU0, rU1` (user randomness for hash), and `r` (commitment randomness).

2) Holder computes commitment:
- `com = Ac · [m1 || m2 || rU0 || rU1 || r]`.

3) Issuer samples challenge randomness:
- `rI0, rI1` (public to the Holder).

4) Holder derives centered randomness and target:
- `r0 = center(rU0 + rI0)`
- `r1 = center(rU1 + rI1)`
- `t = h_{m1||m2,(r0,r1)}(B)`

5) Holder sends `t` with a NIZK proof (pre-sign) of knowledge of
`(m1,m2,rU0,rU1,r)` such that:
- (a) `com = Ac · [m1||m2||rU0||rU1||r]`
- (b) `t = h_{m1||m2,center(rU0+rI0),center(rU1+rI1)}(B)`
- (c) all values are in `[-B,B]`

6) Issuer verifies the proof, then signs `t`:
- Find short `u` with `A·u = t (mod q)`.

7) Holder checks `A·u = t` and shortness of `u`, then stores the credential.

### 1.3 Showing (post-sign)
Let `(m1,m2,r0,r1,u)` be the Holder's stored credential values, and `nonce` a fresh public nonce.

1) Holder chooses `nonce` (public).
2) Holder computes `tag = PRF(m2, nonce)`.
3) Holder produces a NIZK proof of knowledge of `(u,m1,m2,r0,r1)` such that:
- (a) `A·u = t` and `t = h_{m1||m2,(r0,r1)}(B)` (t is internal witness)
- (b) `tag = PRF(m2, nonce)`
- (c) all witness values are in `[-B,B]` (packing + bounds)

4) Holder sends `(tag, nonce, proof)` to verifier; verifier checks proof and tag reuse.

Notes:
- The cleared-denominator form of the hash is used in constraints:
  `(B3 - R1) ⊙ T - (B0 + B1·(M1+M2) + B2·R0) = 0`.
- Denominator nonzero is treated as a negligible abort (no explicit guard).

## 2) Row layout and constraint sets

### 2.1 Issuance (pre-sign) row layout
Witness rows (single poly each, fixed order):
1. `M1`
2. `M2`
3. `RU0`
4. `RU1`
5. `R`
6. `R0`
7. `R1`
8. `K0` (carry for center)
9. `K1` (carry for center)

Public inputs:
- `Com, RI0, RI1, Ac, B, T, BoundB`.
- `T` is public in issuance.

Constraints (all F-par, F-agg empty):
- Commit: `Ac·[M1||M2||RU0||RU1||R] = Com`.
- Center: `RU* + RI* = R* + (2B+1)·K*`.
- Hash: cleared-denominator hash with public `T`.
- Packing: `M1` zero on upper half of ring, `M2` zero on lower half.
- Bounds: `P_B(row)=0` for witness rows; `P_1(K*)=0` for carries.

### 2.2 Showing (post-sign) row layout
Showing reuses base rows and appends internal `T`, signature rows, and PRF trace rows:
- Base rows: `M1,M2,RU0,RU1,R,R0,R1,K0,K1` (as above).
- Internal `T` row (hash output).
- Signature rows `U` (1 or 2 polys depending on key format).
- PRF trace rows: `x^(r)_j` for `r=0..RF+RP` and lane `j=0..t-1` in row-major order.
  `startIdx` marks the first PRF trace row.

Public inputs (showing):
- `A, B, Tag, Nonce, BoundB` (and `Com/Ac` if re-binding to issuance).
- `Tag` and `Nonce` are public.

Constraints (F-par):
- Signature: `A·U = T`.
- Hash: `T = h_{m1||m2,(R0,R1)}(B)` (cleared denominator; now bilinear because `T` is a witness).
- Packing/bounds on `M1,M2,R0,R1,T,U` (and others if present).
- PRF: per-round Poseidon2-like constraints + feed-forward/tag binding.

## 3) Code-level mapping

### 3.1 Issuance code
- `issuance/flow.go`:
  - `PrepareCommit`: computes `com` from `(m1,m2,rU0,rU1,r)`.
  - `ApplyChallenge`: computes `R0/R1/K0/K1`, loads `B`, hashes to `T`.
  - `ProvePreSign` / `VerifyPreSign`: build/verify the pre-sign proof.
  - `SignTargetAndSave`: signs `T` with the trapdoor sampler.
- `cmd/issuance/main.go`: orchestrates end-to-end issuance and persists state.

### 3.2 Showing code
- `cmd/showing/main.go`:
  - Loads credential state and PRF params.
  - Builds `tag/nonce`, PRF trace, witness rows, and publics.
  - Calls `PIOP.BuildShowingCombined` then `PIOP.VerifyWithConstraints`.
- `PIOP/showing_builder.go`:
  - `BuildShowingCombined`: builds post-sign + PRF constraints and uses `BuildWithConstraints`.
- `PIOP/credential_rows_showing.go`:
  - `BuildCredentialRowsShowing`: builds row layout, appends PRF trace rows, returns `startIdx`.

### 3.3 Constraint builders
- `PIOP/credential_constraints.go`:
  - `BuildCredentialConstraintSetPre`: commit/center/hash/packing/bounds.
  - `buildCredentialConstraintSetPostFromRows`: signature/hash/packing/bounds.
- `PIOP/prf_constraints.go`:
  - `BuildPRFConstraintSet`: degree-5 Poseidon2-like round constraints + tag binding.
- `PIOP/constraint_eval.go`:
  - Evaluator used to recompute constraint residuals at opened points for verifier replay.

### 3.4 Helpers and persistence
- `credential/commit.go`: Ajtai commit helper.
- `credential/helpers.go`: `CenterBounded`, `CombineRandomness`, `HashMessage`.
- `credential/state.go`: persistence helpers for `credential/keys/credential_state.json`.
- `ntru/signverify/SignTarget`: signs `T` from coefficients (no seed).

## 4) CLI entry points
- Issuance demo:
  - `go run ./cmd/issuance`
- Showing demo:
  - `go run ./cmd/showing`

## 5) Notes and limitations
- Nonzero-denominator guard for the hash is not enforced; negligible abort assumed.
- PRF is Poseidon2-like with parameters loaded from `prf/` (see `prf/README.md`).
- Tag/nonce are public in showing; a nonce range proof can be added later.
- Optional re-binding to `Com/Ac` is supported by adding commit constraints in showing.
