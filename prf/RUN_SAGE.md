# Running `generate_params_poseidon.sage` for the PRF (Spruce-And-AC §B.6)

This note explains how to produce the Poseidon2-like parameters (MDS matrices and round constants) required by the PRF `F(k, n)` from §B.6 and export them into a JSON blob that the Go PRF package can consume.

## What we need from the paper
- Field modulus `q`: use the protocol field (same as PCS), `q = 1_038_337 = 0xFD801`.
- S-box exponent `d`: smallest `d ≥ 3` with `gcd(d, q−1) = 1`. For `q = 1_038_337`, `q−1 = 1_038_336`, so `d = 5` is the first valid choice (3 and 4 share factors with `q−1`).
- Width `t = lenkey + lennonce`:
  - `lenkey` = number of `m2` slots in showing (e.g., 256 if you use half of a 512-slot packing).
  - `lennonce`: protocol choice (pick per spec; ensure `lentag` security: `lentag ≥ ceil(λ / log2 q)` ⇒ with q≈2^20, `lentag ≥ 7` for 128-bit).
- Rounds `RF/RP`: choose per Poseidon2 guidance; the Sage script can compute minimal secure values for given `(q, t, alpha=d, security_level)`.

## Sage script CLI
The script expects:
```
sage prf/generate_params_poseidon.sage <field> <s_box> <field_bits> <num_cells> <alpha> <security_level> <modulus_hex>
```
- `field=1` for GF(p) (our case), `s_box=0` for x^alpha.
- `field_bits` = bitlength of q (for q=1_038_337, use 20).
- `num_cells` = t (lenkey + lennonce).
- `alpha` = d (use 5 for q above).
- `security_level` = e.g., 128.
- `modulus_hex` = modulus in hex (0xFD801).

### Example command (paper “for now” parameters)
The paper provides example lengths `lenkey=90`, `lennonce=8`, `lentag=2` (so `t=98`) and round counts `RF=8`, `RP=10`. To generate params for that instantiation on the paper’s field:
```
sage prf/generate_params_poseidon.sage 1 0 20 98 5 128 0xFD801
```
The script embeds these example lengths (`LENKEY=90`, `LENNONCE=8`, `LENTAG=2`) and will write `prf_params.json` alongside the `.txt`.

## Exporting JSON for Go
The script now dumps a machine-readable `prf_params.json` (ME=MI by default) after running. Steps:
1. Run the Sage command above from repo root.
2. Copy `prf/prf_params.json` into `prf/testdata/` (or embed in Go).
3. Load it in Go via a `LoadParamsFromJSON` helper and validate.

## Loading in Go
Add a loader to `prf/params.go`:
```go
type ParamsJSON struct {
    Q uint64 `json:"q"`
    D uint64 `json:"d"`
    LenKey, LenNonce, LenTag int `json:"lenkey","lennonce","lentag"`
    RF, RP int `json:"RF","RP"`
    ME, MI [][]uint64 `json:"ME","MI"`
    CExt [][]uint64 `json:"cExt"`
    CInt []uint64   `json:"cInt"`
}
```
Convert to `Params` and call `Validate()`.

## Sanity/KATs
- After exporting params, generate a KAT in Sage:
  - pick `k, n`, compute `tag = F(k,n)` using the same permutation and feed-forward.
  - dump to `prf/testdata/kat.json` (`key`, `nonce`, `tag` as hex/ints).
- Add a Go test that loads params and KAT and checks `Tag(key, nonce)` matches.

## Notes
- The paper fixes `q` and the rule for `d`; the numeric `d=5` follows from that rule.
- Lengths (`lenkey=90`, `lennonce=8`, `lentag=2`, `t=98`) and `RF=8`, `RP=10` are paper example (“for now”) parameters; you may choose different values to match your packing/security, but then adjust the Sage CLI accordingly.
- The script sets `LENKEY/LENNONCE/LENTAG`; if you change `num_cells`, ensure `LENKEY+LENNONCE = t`.
