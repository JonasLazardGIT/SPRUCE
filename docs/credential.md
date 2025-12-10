# credential Helpers

The `credential/` package groups small helpers used by the new issuance layer.

## API

- `CenterBounded(v, bound int64) int64` – wraps `v` into `[-bound, bound]` using modulus `2·bound+1`, matching the randomness-combining “center” step.
- `CombineRandomness(rUser, rIssuer []int64, bound int64) ([]int64, error)` – computes `center(rUser + rIssuer)` component-wise using `CenterBounded`. Enforces equal lengths and a positive bound.
- `HashMessage(ringQ *ring.Ring, B []*ring.Poly, m1, m2, r0, r1 *ring.Poly) ([]int64, error)` – computes `t = h_{m,(r0,r1)}(B)` using explicit polynomials (mirrors `BuildWitnessFromDisk`). Inputs are coefficient-domain polynomials; `B` must be four NTT-domain polys. Returns centered coefficients for feeding the signer.
- `LoadDefaultRing() (*ring.Ring, error)` – loads `Parameters/Parameters.json` (with a parent-directory fallback) and constructs the main ring.

These helpers are pure Go utilities; they do not persist artifacts or touch disk beyond reading parameters.
