# NTRU Package Documentation

## Overview

The `ntru/` package implements the lattice trapdoor, sampling, and signing primitives that feed both the on-disk fixture generation and the higher-level PIOP construction. It mirrors the C reference implementation while exposing Go-friendly APIs for:

- Generating NTRU trapdoors `(f,g,F,G)` and the public key polynomial `h`.
- Reconstructing the hash-bridge target `t` from recorded seeds.
- Producing Hybrid‑B signatures `(s₀,s₁)` together with diagnostic residuals.
- Verifying signatures via congruence checks and norm predicates.

Subpackages such as `ntru/io` and `ntru/signverify` provide I/O wrappers and CLI entry points; the core logic lives in the root `ntru` directory.

---

## Parameters and Ring Representation

- **Ring**: All operations occur in the cyclotomic ring `R_q = ℤ_q[X]/(Xⁿ + 1)` with `n` a power of two (default `N=1024`) and a prime modulus `q` (`1038337` for the fixtures). Constructors in `params.go` expose the `Params` type holding `(N, Q, log₂ N, …)`.
- **Presets**: `presets.go` and `keys/` record canonical parameters used during signing; CLI helpers (`signverify.GenerateKeypairAnnulus`) load them from JSON files.
- **Polynomials**:
  - `poly.go`, `ring.go`, and `ntt.go` define coefficient-domain and NTT-domain representations.
  - Helper functions (`Int64ToModQPoly`, `CenterModQToInt64`) convert between signed integers and modulo-`q` residue classes.

This representation underpins every other module; all keygen and signing routines expect consistent `Params`.

---

## Hash Bridge (`hash_bridge.go`)

The hash bridge converts message seeds into a target polynomial `t` using the BBS hash described in SmallWood (§3.3):

1. **Inputs**: system parameters (`Parameters/Parameters.json`), the B-matrix (`Parameters/Bmatrix.json`), and three 32-byte seeds (`mSeed`, `x0Seed`, `x1Seed`).
2. **Sampling**: `FillPolyBoundedFromPRNG` reconstructs `m`, `x₀`, `x₁` from the seeds using Antrag’s bounded sampler (seeded PRNG from `github.com/tuneinsight/lattigo/v4/utils`).
3. **Hash**: `vsishash.ComputeBBSHash` (from `vSIS-HASH`) hashes `(B, m, x₀, x₁)` in NTT form and returns an evaluation-domain polynomial.
4. **Output**: An inverse NTT and symmetric recentering yield `t` with coefficients in `[-Q/2, Q/2]`.

`ComputeTargetFromSeeds` exposes this pipeline; both the signer and the verifier call it verbatim to guarantee that targets match the recorded seeds.

---

## Key Generation

Two interfaces exist for generating trapdoors:

1. **Antrag Annulus Sampler** (`Keygen` / `KeygenRadialFG` in `keygen.go`, `keygen_fft.go`):
   - Samples `(f, g)` inside an annulus or fixed-radius shell.
   - Calls `NTRUSolve` (`ntrusolve.go`) to obtain `(F, G)` such that `fG - gF = q`.
   - Guards the α-window / radius relationship (see `docs.md` §Keygen).
2. **Trivial Generator** (`GenerateKeypair` in `signverify/signverify.go`):
   - Produces a degenerate trapdoor `(f=1, g=X)` for tests.

Both routes ultimately compute the public key `h = g / f mod q` via `PublicKeyH`, reduce all polynomials to `[-Q/2, Q/2]`, and persist JSON bundles under `./ntru_keys/` using `keys.SavePublic` / `keys.SavePrivate`.

Keygen options (`KeygenOpts`):

- Precision (`Prec`): arbitrary precision used by embeddings and Babai steps (≥256 bits recommended).
- `Alpha`, `UseCRadius`, `Radius`: control the annulus or fixed-radius sampler.
- `MaxTrials`, `Verbose`: limit iterations and emit diagnostics (also gated by `NTRU_DEBUG`).

---

## Sampler Architecture

The Hybrid‑B sampler resides in `ffsampler.go`, `preimage_sign.go`, and supporting files (`ffsampler.go`, `sampling_bounded.go`):

- **Construction**: `NewSampler(f, g, F, G, par, prec)` copies the trapdoor, enforces `prec ≥ 256`, and precomputes evaluation-domain views (`ToEvalCFFT`) for all polynomials.
- **Trapdoor reduction**: `ReduceTrapdoor(maxIters)` applies repeated Babai steps (`ReduceOnce` from `reduce.go`) to shrink `(F, G)` before sampling.
- **Gram matrix**: `BuildGram` constructs per-slot Gram entries in the evaluation domain for the basis vectors `(g, -f)` and `(G, -F)`.
- **Sigma computation**: `ComputeSigmasC` derives per-slot standard deviations matching the C reference implementation; these feed the two-plane sampler.
- **Option B sampling**: `SamplePreimageTargetOptionB` (in `preimage_sign.go`) implements the Hybrid-B loop:
  1. Centers the target via `CentersFromSyndrome`.
  2. Samples via `samplePairCExact` (Box–Muller complex Gaussian).
  3. Reconstructs `v₁`, `v₂`, rounds with `RoundAwayFromZero`, and sets `s₁ = -round(v₁)`.
  4. Forms `s₂ = center_Q(c₁ - v₂)` and enforces the C-style bound `CheckNormC(s₁, s₂)`.
  5. If accepted, computes `s₀ = center_Q(t - h ⊛ s₁)` and returns `(s₀, s₁)` plus the number of trials.
- **Residual tracing**: `Sampler.LastS2()` exposes the last accepted residual for later bundling.

Sampler options (`SamplerOpts`) include `RSquare`, `Alpha`, `Slack`, `ReduceIters`, measurement hooks (`UseCNormalDist`, `UseExactResidual`), and acceptance thresholds (`ResidualLInf`). Defaults derive from Antrag’s Hybrid‑B parameters.

---

## Signing Pipeline (`signverify.SignWithOpts`)

`signverify/signverify.go` orchestrates the entire signing flow:

1. **Load fixtures**: Reads `public.json`, `private.json`, derives `par := ntru.NewParams`.
2. **Targets**: Calls `loadParams` to fetch system parameters, derives seeds (`mSeed = SHA256(message)`, plus random `x0Seed`, `x1Seed`), and computes `t := ComputeTargetFromSeeds`.
3. **Sampler setup**: Instantiates `Sampler` with `NewSampler`, applies defaults (`SamplerOpts.ApplyDefaults`), and configures Option B (C-style Gaussian, exact residual).
4. **Sampling loop**: Invokes `SamplePreimageTargetOptionB(t, maxTrials)` to obtain `(s₀, s₁)` and the residual `s₂`.
5. **Post-check / diagnostics**:
   - Recomputes `s₂` via `ConvolveRNS(h, s₁) + c₁` to confirm it matches the cached residual.
   - Calls `CheckNormC(s₁, s₂Vec)` to ensure the sampler’s predicate succeeded.
   - Records ℓ₂ estimates and residual norms.
6. **Bundle**: Persists `keys.Signature` containing:
   - Parameters `(N, Q)`, seeds, target coefficients `t`.
   - Public key coefficients `h`.
   - Signature rows `s₀`, `s₁`, residual `s₂`.
   - Acceptance telemetry (`TrialsUsed`, `Rejected`, `Norm` details).
   - Measurement hooks (`recordSignatureMeasurements`) update `measure.Global`.

CLI commands (`cmd/ntru_sign`) wrap `SignWithOpts` for manual testing.

---

## Verification Pipeline (`signverify.Verify`)

Verification mirrors signing but treats the signature as input:

1. **Parameter reconstruction**: Parses `(N, Q)` from the signature, rebuilds `Params`.
2. **Target check**: Recomputes `t = ComputeTargetFromSeeds` using the stored seeds and compares coefficient-wise against `sig.Hash.TCoeffs`.
3. **Congruence**: Converts `s₀`, `s₁`, `h` to `ModQPoly`, evaluates `h ⊛ s₁ + s₀ mod q`, and ensures it equals `t`.
4. **Residual**: Computes `s₂ = center_Q(h ⊛ s₁ + c₁)` and confirms it matches the stored residual.
5. **Norm predicate**: Reapplies `CheckNormC(s₁, s₂)` using default sampler options (including `UseLog3Cross` in log³ mode).

Any mismatch yields an explicit error indicating the failing step (target mismatch, congruence failure, or norm check failure).

---

## I/O, Keys, and Fixtures (`ntru/io`, `ntru/keys`)

- **System parameters**: `io/system_params.go` parses JSON files describing `(N, Q, sigma, …)` for reproducible configurations.
- **Key storage**: `keys` package stores public/private keys and signatures under `./ntru_keys/` with versioned schemas.
- **CLI support**: `signverify.GenerateKeypairAnnulus` / `GenerateKeypair` persist keys, while `LoadParamsForCLI` exposes parameter loading to external tools.

These utilities ensure signing and verification routines share consistent inputs.

---

## Interactions with PIOP

When `PIOP` rebuilds witnesses (`BuildWitnessFromDisk`):

- It calls `ntru/io.LoadParams`, `keys.LoadPublic`, and `keys.Load` to recover `A = [1, -h]`, B-matrix columns, and the signature bundle.
- It regenerates message/mask polynomials via `FillPolyBoundedFromPRNG`, computes `s₂`, and verifies the proof-friendly equation described in `build_witness.go`.
- The hash bridge (`ComputeTargetFromSeeds`) ensures the PIOP layer sees the exact same target used during signing.

Thus, the PIOP documentation relies on the correctness guarantees provided by this package.

---

## CLI Reference

The CLI under `cmd/ntrucli` wraps the key workflows.

### `ntru gen`

Generates a keypair under `./ntru_keys/`.

| Flag | Default | Description |
|------|---------|-------------|
| `-mode` | `cstyle` | Keygen mode: `trivial` or `cstyle`. |
| `-fplus`, `-fminus` | `10` | Number of ±1 coefficients in `f` (cstyle). |
| `-gplus`, `-gminus` | `10` | Number of ±1 coefficients in `g` (cstyle). |
| `-kgtr` | `128` | Max keygen trials in cstyle mode. |
| `-prec` | `256` | Big-float / FFT precision (bits). |

Annulus/FFT-specific flags:

| Flag | Default | Description |
|------|---------|-------------|
| `-keygen` | `auto` | Keygen branch (`auto`, `annulus`, `cstyle`). |
| `-alpha` | `1.20` | α-window parameter; ≥1 unless using fixed radius. |
| `-kgtrials` | `10000` | Max GoodPair trials for annulus/FFT keygen. |
| `-use-c-radius` | `false` | Force fixed C-style radius. |
| `-radius` | `0.0` | Radius scaling when fixed-radius mode is enabled (`rad = √q·radius`). |
| `-kgverbose` | `false` | Verbose annulus keygen logging. |

### `ntru sign`

Signs a message and writes `./ntru_keys/signature.json`.

| Flag | Default | Description |
|------|---------|-------------|
| `-m` | — | Message string (required). |
| `-max` | `2048` | Maximum Hybrid-B rejection trials. |
| `-v` | `false` | Verbose telemetry (ℓ₂ estimates, residual norms). |

### `ntru verify`

Validates the signature bundle in `./ntru_keys/signature.json`, recomputes the hash bridge target from seeds, checks congruence `h⊛s₁ + s₀ ≡ t (mod q)`, and re-applies the norm predicate.

---

## Command Call Paths

Developers can trace the CLI commands back to the core APIs as follows:

- **`ntru gen`** (`cmd/ntrucli/main.go`):
  - Loads system parameters via `signverify.LoadParamsForCLI`.
  - Dispatches to `signverify.GenerateKeypair` (trivial trapdoor) or `signverify.GenerateKeypairAnnulus`, which invokes `ntru.Keygen`/`NTRUSolve` and persists keys with `keys.SavePublic` / `keys.SavePrivate`.

- **`ntru sign`**:
  - `signverify.SignWithOpts` loads keys, derives seeds, calls `ComputeTargetFromSeeds`, constructs a sampler with `NewSampler`, and runs `SamplePreimageTargetOptionB`. The signature is serialized with `keys.NewSignature` and `keys.Save`.

- **`ntru verify`**:
  - `signverify.Verify` reloads the bundle, recomputes `t`, checks congruence using `ConvolveRNS`, and enforces `CheckNormC` on `(s₁, s₂)`.

These call paths are useful when instrumenting or extending the CLI.

---

## Tests and Instrumentation

Key test files include:

- `docs.md`: living design document summarising sampler, reducer, and signing architecture (basis for this write-up).
- `signverify/c_compat_test.go`: compares Go signatures against the C reference outputs.
- `samplez_test.go`, `cembed_roundtrip_test.go`: guard the correctness of embeddings and sampling primitives.
- `egcd_test.go`, `fieldops_test.go`: validate arithmetic helpers.

Instrumentation:

- `measure` integration records byte sizes and coefficients during signing (`recordSignatureMeasurements`).
- `NTRU_DEBUG` enables verbose sampling traces, Babai reductions, and acceptance ratios.

---

## High-Level Flow Diagram

```
Message → seeds ─┐
                 │     (Parameters, B-matrix)
                 ├─ ComputeTargetFromSeeds ─→ target t
                 │
Trapdoor (f,g,F,G) ── NewSampler ── Option B loop ──► (s0,s1,s2)
                                       │
                                       └─ CheckNormC(s1,s2)

Persist:
  - public key h
  - target t, seeds
  - signature rows s0, s1, residual s2

Verify:
  recompute t → congruence check → norm predicate
```

This pipeline is the “lower-level” primitive consumed by the PACS/PIOP layers. Any change to the sampler or hash bridge must maintain bit-for-bit compatibility with the stored fixtures so that witness reconstruction and verification continue to succeed.
