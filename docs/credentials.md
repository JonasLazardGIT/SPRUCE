# Credential Module Progress (Steps 1–3)

This doc tracks the implemented pieces for the augmented issuance flow, aligned with **docs/Spruce-And-AC.pdf** §B.6 and the existing DECS/LVCS/PCS/PACS stack.

## Current scope
- Parameter loading for credential issuance (Ac, bounds, block lengths).
- Core data structs for holder/challenge/transcript/credential.
- Bound checking helpers.
- Commitment builder using the public Ac matrix.

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
  - `Ac` file format: `{"Ac": [ [ [coeffs...], [coeffs...] ], ... ]}` i.e. Ac[row][col][coeff], coeffs in coeff domain. Loader lifts to NTT.
- `LoadParamsFromFile(path)` → `*credential.Params` with:
  - `Ac commitment.Matrix` (NTT), `BPath`, `AcPath`, `BoundB`, block lengths, `RingQ`.
  - Fallback search for files in `.`/`..`/`../..`.
- Ring source: `Parameters/Parameters.json` defaults (`n=1024`, `q=1038337`).

### Types (`credential/types.go`)
- `HolderState { M1, M2, RU0, RU1, R []*ring.Poly }`
- `IssuerChallenge { RI0, RI1 []*ring.Poly }`
- `Transcript { Com []*ring.Poly; PiCom interface{}; T []int64; PiT interface{}; U []int64 }`
- `Credential { U []int64; M1, M2, R0, R1 []*ring.Poly; Com []*ring.Poly; BPath, AcPath string }`

### Bounds (`credential/bounds.go`)
- `CheckBound(vec []*ring.Poly, bound int64, name string, ringQ *ring.Ring) error` – asserts all coeffs ∈ [-bound, bound] after centering.
- `CheckLengths(vec []*ring.Poly, want int, name string) error`.

### Commitment builder (`credential/commit.go`)
- `BuildCommit(p *Params, h HolderState) (commitment.Vector, error)`:
  - Validates lengths vs. `Len*`.
  - Bound-checks all blocks with `BoundB`.
  - Flattens `[m1||m2||rU0||rU1||r]` and calls `commitment.Commit`.
  - Returns `com` (slice of polys).

### Helpers (`credential/helpers.go`)
- `CenterBounded`, `CombineRandomness`, `HashMessage` retained for later steps; `HashMessage` mirrors `PIOP/build_witness.go` → `vsishash.ComputeBBSHash` and returns centered `t`.

### Issuer challenge (`credential/challenge.go`)
- `NewIssuerChallenge(p *Params) (IssuerChallenge, error)`:
  - Samples `RI0, RI1` with coeffs in `[-BoundB, BoundB]`, lifts to NTT.
  - Uses `LenRU0/LenRU1` to size each slice.

### Target preparation (`credential/target.go`)
- `ComputeCombinedTarget(p, holderState, challenge) (*CombinedTarget, error)`:
  - Converts inputs from NTT to coeff domain.
  - Computes `R0/R1 = center(RU* + RI*)` coeff-wise (bounded by `BoundB`).
  - Loads `B` (NTT) from `BPath`, hashes to `T` via `HashMessage`.
  - Restriction: only single-poly `m1`, `m2`, `r0`, `r1` are supported; length must be 1 for each (avoids multi-poly hashing for now).

### Pre-sign proof scaffold (`PIOP/pre_sign.go`)
- `ProvePreSign(p, holderState, challenge) -> PreSignProof`:
  - Runs `BuildCommit` and `ComputeCombinedTarget`, returns `Com`, `R0`, `R1`, `T`.
- `VerifyPreSign(p, holderState, challenge, proof) error`:
  - Deterministically recomputes the same constraints (no ZK yet).
- PIOP-side scaffold: `PIOP/pre_sign_augmented.go` exposes deterministic `ProvePreSignAugmented` / `VerifyPreSignAugmented` (Com + center combine; no hash constraint). The full PACS-style circuit is still TODO.

## Constants and defaults
- Ring: `N=1024`, `q=1038337` (`Parameters/Parameters.json`).
- B-matrix: `Parameters/Bmatrix.json`.
- `BoundB`: currently read from params JSON; should match PIOP bound for message vectors (same bound used when checking message coordinates in PIOP). If unsure, set to the PIOP message bound (**MORE CONTEXT NEEDED** if different).

## Notes / TODO for next steps
- Define and publish canonical `Ac` JSON (coeff domain vs. NTT) and sample params file.
- Target circuit and show circuit still to be implemented.
- Norm bound for signer output `U` (currently signer uses β≈7054 from Parameters) and nonce domain for PRF tagging remain to be fixed (**MORE CONTEXT NEEDED**).
