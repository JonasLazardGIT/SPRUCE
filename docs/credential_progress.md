# Credential Integration Progress

This doc tracks implementation status for the credential protocol (Spruce-And-AC B.6) in this repo, including both issuance (pre-sign) and showing (post-sign).

## Implemented
- **Credential helpers**: params loader, bounds/length checks, commitment builder, challenge sampler, `HashMessage`, target derivation (`R0/R1/K0/K1/T`).
- **Constraint helpers**: commit, center wrap, signature (linear), bounds, hash (cleared denominator), packing (M1 lower half, M2 upper half).
- **PIOP refactor**:
  - `BuildWithConstraints` supports credential mode; publics bound via `BuildPublicLabels` + `LabelsDigest` (personalization `PACS-Credential`).
  - `runMaskFS` is fully extracted; theta>1 uses compensated masks and K-point replay.
  - Verifier replays FS with label digest + omega/ncols overrides; Eq.(4) replay uses opened evaluations in credential mode.
- **Pre-sign issuance (working)**:
  - Witness rows: `M1, M2, RU0, RU1, R, R0, R1, K0, K1`.
  - Publics: `Com, RI0, RI1, Ac, B, T, BoundB`.
  - Constraints: commit, center, hash (cleared denominator), packing, bounds (all F-par).
  - Demo: `go run ./cmd/issuance`.
- **Post-sign showing (working)**:
  - Rows: pre-sign base + internal `T`, signature `U`, PRF trace rows `x^(r)_j`.
  - Publics: `A, B, Tag, Nonce, BoundB`.
  - Constraints: signature `A·U=T`, hash, packing, bounds, PRF (degree-5).
  - Demo: `go run ./cmd/showing`.

## Current behavior notes
- Packing uses full ring split (`N=1024`, half=512): `M1` zero on upper half, `M2` zero on lower half.
- Hash uses cleared-denominator identity; nonzero-denominator guard is not enforced (negligible abort assumed).
- PRF tag/nonce are public in showing. PRF trace rows are committed in the witness matrix.

## Remaining work / optional extensions
1) **Re-bind showing to issuance commitment** (optional)
   - Add `Com/Ac` to showing publics and include the commit constraint in post-sign.
2) **Nonce domain proof** (optional)
   - Add a range or set-membership gadget for `nonce` (instead of revealing it), if desired.
3) **PRF parameter hardening**
   - Finalize parameter generation and KAT vectors for Poseidon2 params, and lock the JSON into the build.
4) **Protocol cleanup**
   - Prune remaining demos and deprecated flags after the protocol stabilizes.

## Key code entry points
- Issuance orchestration: `issuance/flow.go`, CLI `cmd/issuance`.
- Showing orchestration: `cmd/showing`, builder `PIOP/showing_builder.go`.
- Protocol docs: `docs/credentials.md`, PRF details in `docs/proving_prf.md`.
