# PRF package (Spruce-And-AC §B.6)

This package implements the PRF `F` defined in §B.6 using a Poseidon2‑like permutation over the protocol field. It is structured for native evaluation (holder/verifier) and ready to be wired into the ZK circuit (trace mode can be added as needed).

## 1. Definition (paper-faithful)
Parameters:
- Field `Fq` with modulus `q` (same as PCS); `d` is the smallest `d>=3` with `gcd(d,q−1)=1`.
- Width `t = lenkey + lennonce`.
- Rounds: `RF` external (“full”) rounds (even), `RP` internal (“partial”) rounds.
- MDS matrices `ME`, `MI` (t×t, Cauchy-style).
- Round constants `cExt[RF][t]`, `cInt[RP]` (scalar for lane 0).

Permutation `P = E_RF ∘ … ∘ E_RF/2+1 ∘ I_RP ∘ … ∘ I_1 ∘ E_RF/2 ∘ … ∘ E_1`
- External round `E_i`: `state = ME * S(state + cExt[i])`, S-box on all lanes.
- Internal round `I_i`: add `cInt[i]` to lane 0, S-box lane 0 only, linear on others, then `state = MI * state`.
- S-box: `x ↦ x^d (mod q)`.

PRF `F(k, n)`:
1. `x = k || n` (len = t).
2. `y = P(x)`.
3. `z = y + x` (feed-forward).
4. `tag = z[:lentag]`.

## 2. Package layout
```
prf/
  field.go            // field ops mod q
  params.go           // Params struct + validation + JSON loaders
  permute.go          // Poseidon2-like permutation (external/internal rounds)
  prf.go              // Tag(key, nonce, params) wrapper (feed-forward + truncation)
  prf_vectors_test.go // loads prf_params.json, deterministic vector
  prf_params.json     // generated parameters (paper defaults)
  generate_params_poseidon.sage // parameter generator (checks flag)
  README.md           // this document
  RUN_SAGE.md         // how to regenerate params with Sage
```
Trace generation is not yet implemented; add it if you need witness traces for ZK.

## 3. Params representation and generation
Stored in `prf_params.json`: `q, d, lenkey, lennonce, lentag, RF, RP, ME, MI, cExt, cInt`.
Validation enforces dimensions, RF even, lentag ≤ t.

Generate params with Sage (defaults are the paper example: `q=1038337`, `d=5`, `t=98`, `lenkey=90`, `lennonce=8`, `lentag=2`, `RF=8`, `RP=10`):
```
cd prf
sage generate_params_poseidon.sage
```
This writes `prf_params.json`. Heavy MDS trail checks are behind a flag in the script; enabled by default, but very slow for large t. Set `enable_checks=False` inside the script for a fast Cauchy-only path.

Load in Go:
```go
p, err := prf.LoadParamsFromFile("prf/prf_params.json")
```

## 4. API
### Tag
```go
tag, err := prf.Tag(key []Elem, nonce []Elem, params *Params)
```
- `len(key) = lenkey`, `len(nonce) = lennonce`.
- Builds state `k||n`, permutes, feed-forward, truncates to `lentag`.

### Permutation
```go
prf.PermuteInPlace(state []Elem, params *Params)
```
- Requires `len(state) = t`.
- Full/partial rounds as above; uses row-major ME/MI.

### Params loading
```go
p, err := prf.LoadParamsFromFile(path)
// or
p, err := prf.LoadParams(io.Reader)
```

## 5. Testing
- Run `go test ./prf -run TestVectorsFromParams -v` to load `prf_params.json`, derive a deterministic key/nonce (seeded RNG), and print the tag. Example output:
```
params: q=1038337 d=5 t=98 RF=8 RP=10
key[0:4]=[...] nonce[0:4]=[...]
tag=[63973 244141]
```
- Add KATs by fixing `(k, n)` and comparing against Sage if needed.

## 6. Integration notes (B.6 showing)
- `m2` (credential secret) maps to `key`.
- `nonce` is chosen per showing, already encoded into `Fq^{lennonce}`.
- `tag` is public to the verifier; server tracks tags to prevent double use.
- In-circuit: mirror the permutation rounds, enforce `z = P(x)+x` and `tag = z[:lentag]`. Add nonce/domain proofs per your presentation policy.

## 7. Performance hints
- t can be large (e.g., 98): avoid allocations in matrix multiplies, reuse buffers.
- `d` is small: square-and-multiply is fine; Montgomery/Barrett mul optional.
- Embedding params in Go source avoids runtime JSON parsing if needed.
