# commitment Package Notes

The `commitment/` package provides a simple linear commitment helper over ring polynomials. It is designed to bind `(m₁, m₂, rU0, rU1, r)` into a vector commitment `com = A_c · vec`, where `A_c` is public and all operands live in the same ring/domain (NTT or coefficient).

## API

- `Commit(ringQ *ring.Ring, Ac Matrix, vec Vector) (Vector, error)` – computes `com = A_c · vec` with dimension checks. `Matrix` is a row-major `[][]*ring.Poly` and `Vector` is a `[]*ring.Poly`. Returns the committed rows as a slice of polynomials.
- `Verify(ringQ *ring.Ring, Ac Matrix, vec, com Vector) error` – recomputes the commitment and compares against `com`, returning an error on mismatch.
- `Open(ringQ *ring.Ring, Ac Matrix, vec Vector) (Vector, error)` – convenience wrapper that recomputes the commitment from the opening.

All methods expect non-nil polynomials and consistent dimensions; failures are reported via errors instead of panics.
