# Credential Module Progress (Updated)

This document captures the current state of the credential/issuance flow and the supporting PACS/PIOP wiring. It reflects the recent fixes (ΣΩ/masking) and the end-to-end issuance helpers.

## Files and APIs

### Params (`credential/params.go`)
- JSON schema:
  ```json
  {
    "AcPath": "path/to/Ac.json",
    "BPath": "Parameters/Bmatrix.json",
    "BoundB": 6000,
    "LenM1": 1,
    "LenM2": 1,
    "LenRU0": 1,
    "LenRU1": 1,
    "LenR": 1
  }
  ```
- `Ac` file format: `{"Ac": [ [ [coeffs...], [coeffs...] ], ... ]}` (rows × cols × coeffs, coeff domain). Loader lifts to NTT. Validates dimensions vs. `Len*`.
- Ring source: `Parameters/Parameters.json` defaults (`n=1024`, `q=1038337`).

### Types (`credential/types.go`)
- `HolderState { M1, M2, RU0, RU1, R []*ring.Poly }`
- `IssuerChallenge { RI0, RI1 []*ring.Poly }`
- `Transcript { Com []*ring.Poly; PiCom interface{}; T []int64; PiT interface{}; U []int64 }`
- `Credential { U []int64; M1, M2, R0, R1 []*ring.Poly; Com []*ring.Poly; BPath, AcPath string }`

### Bounds (`credential/bounds.go`)
- `CheckBound(vec []*ring.Poly, bound int64, name string, ringQ *ring.Ring) error` – centers coeffs into `[-q/2,q/2]`, asserts ∈ [-bound, bound].
- `CheckLengths(vec []*ring.Poly, want int, name string) error`.

### Commitment builder (`credential/commit.go`)
- `BuildCommit(p *Params, h HolderState) (commitment.Vector, error)`:
  - Validates lengths/bounds vs. `Len*`.
  - Flattens `[m1||m2||rU0||rU1||r]`, lifts to NTT, calls `commitment.Commit`.

### Helpers (`credential/helpers.go`)
- `CenterBounded/CombineRandomness`: center wrap into `[-B,B]` via modulus `2B+1`.
- `HashMessage(ringQ, B, m1, m2, r0, r1) ([]int64, error)`: explicit `h_{m,(r0,r1)}(B)` (BBS) using coeff-domain inputs and B in NTT; returns centered coeffs for signing.
- `LoadDefaultRing() (*ring.Ring, error)`: loads `Parameters/Parameters.json`.

### Issuer challenge (`credential/challenge.go`)
- `NewIssuerChallenge(p *Params) (IssuerChallenge, error)`: samples RI0/RI1 in `[-BoundB, BoundB]`, lifts to NTT; sizes from `LenRU0/LenRU1`.

### Target preparation (`credential/target.go`)
- `ComputeCombinedTarget`: coeff-side `R0/R1 = center(RU*+RI*)`, loads B, hashes to T; single-poly restriction for m1/m2/r0/r1.

### Issuance orchestration (`issuance/flow.go`)
- Helpers to stitch Holder→Issuer (Spruce-And-AC §B.6):
  - `PrepareCommit` → `Com = Ac·[m1||m2||RU0||RU1||R]` (NTT).
  - `ApplyChallenge` → coeff-side `R0/R1`, carries `K0/K1`, loads B, computes `T = HashMessage`.
  - `ProvePreSign` / `VerifyPreSign` → build/verify the pre-sign credential proof with publics `{Com, RI0, RI1, Ac, B, T, BoundB}` and witnesses `{M1, M2, RU0, RU1, R, R0, R1, K0, K1}`.
  - `SignTargetAndSave` → signs `T` with stored NTRU trapdoor (`./ntru_keys`) via `signverify.SignTarget`, saves `signature.json`.
- Recommended opts (match tests): `Theta=2, EllPrime=1, Rho=1, NCols=8, Ell=1, Credential=true`.

## Credential PIOP (Pre-sign)

- Witness rows (fixed order, single poly): `M1, M2, RU0, RU1, R, R0, R1, K0, K1`.
  - `K0/K1` carry rows for center wrap (`RU+RI = R + (2B+1)·K`, K ∈ {-1,0,1}, bounded in-circuit).
  - `T` is **public** (issuance target t).
- Publics: `Com, RI0, RI1, Ac, B, T` (bound into FS via `BuildPublicLabels` + `LabelsDigest`).
- Constraints (all F-par; F-agg may be empty):
  - **Commit**: `Ac·[M1‖M2‖RU0‖RU1‖R] − Com = 0`
  - **Center wrap**: `RU* + RI* − R* − (2B+1)·K* = 0` for *∈{0,1}
  - **Hash (cleared denominator)**: `(B3 − R1) ⊙ T − (B0 + B1·(M1+M2) + B2·R0) = 0` (T public; no explicit denom-nonzero guard—abort-on-invertible assumed negligible)
  - **Packing**: M1 zero on upper half, M2 zero on lower half (concatenation convention)
  - **Bounds**: `P_B(row)=0` for all witness rows; `P_1(K*)=0` for carries; Go-side scan remains as precheck.
- Verifier (θ>1): `VerifyNIZK` tolerates empty F-agg, replays FS with `LabelsDigest/OmegaTrunc/NColsUsed`, checks ΣΩ via `VerifyQK_QK`.

### Masking / ΣΩ behavior
- Credential mode uses **compensated masks (PACS style)** so ΣΩ sums to zero on valid inputs (matches SmallWood PACS). Tampering is caught via non-zero residual constraints (commit/center/hash/packing/bounds).
- DEBUG: set `DEBUG_QK=1` to log non-zero QK evaluations when ΣΩ fails.

## Constants and defaults
- Ring: `N=1024`, `q=1038337` (`Parameters/Parameters.json`).
- B-matrix: `Parameters/Bmatrix.json`.
- `BoundB`: from params JSON; should match PIOP bound for message vectors.

## NTRU Signing CLIs (for signing T)
- `cmd/ntru_sign`: sign explicit `t` (`-target` or derive from `-msg`), writes `./NTRU_Signature/signature.json`.
- `cmd/ntrucli`: `gen/sign/verify` using stored keys in `./ntru_keys`.
- Library: `signverify.SignTarget(tCoeffs, maxTrials, opts)` signs T with stored trapdoor.

## Next steps
- Post-sign (Holder→Verifier): add row `U`, constraint `A·U = T`, decide on binding to `Com/Ac`, PRF/tag gadget (PRF currently identity).
- Optional: explicit nonzero-denominator guard for the hash if desired.
- Ensure C compatibility test skips when BFile is invalid; otherwise all tests should be green.
