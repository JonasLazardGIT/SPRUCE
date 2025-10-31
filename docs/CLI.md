# Command Packages Documentation

This document describes the executables under `cmd/`, the flags they accept, and how each command interacts with the core libraries (`ntru`, `PIOP`, `LVCS`, `DECS`). Use this as a complement to:

- `docs/NTRU.md` – trapdoor, hash-bridge, and signing internals.
- `docs/piop.md` – witness construction, constraint gadgets, and PACS orchestration.
- `docs/lvcs.md`, `docs/decs.md` – LVCS/DECS commitment layers consumed by the PACS runner.

All commands are invoked from the repository root unless otherwise noted.

---

## Summary of Executables

| Command | Purpose | Key Dependencies |
|---------|---------|------------------|
| `cmd/ntrucli` | Main entry point for keygen, signing, verification, and single-run PACS simulations. | `ntru`, `PIOP`, `measure`, `prof` |
| `cmd/ntru_sign` | Standalone signer that accepts custom messages or explicit targets. | `ntru`, `ntru/io` |
| `cmd/keycheck` | Diagnostic tool that recomputes the residual `s₂` for an existing signature. | `ntru`, `ntru/keys` |
| `cmd/pacs_sweep` | Parameter sweep runner for PACS simulations; writes CSV + JSONL reports. | `PIOP`, `measure`, `prof` |
| `cmd/analysis` | Coefficient-distribution analysis (requires `-tags analysis`). | `ntru`, `ntru/signverify`, `Measure_Reports` utilities |

The sections below detail the flags, control flow, and documentation cross-references for each tool.

---

## `cmd/ntrucli`

`ntrucli` multiplexes subcommands:

```
go run ./cmd/ntrucli <gen|sign|verify|pacs|pacs-small> [flags]
```

### `gen`: Key Generation

- **Flags** (subset of the canonical list in `Commands.md`):
  - `-mode` (`annulus` or `trivial`) chooses between the Antrag annulus sampler and the degenerate trapdoor.
  - Annulus-specific options: `-alpha`, `-kgtrials`, `-use-c-radius`, `-radius`, `-kgverbose`, `-prec`.
- **Call graph**:
  1. `runGen` → `signverify.LoadParamsForCLI()` loads `Parameters/Parameters.json`.
  2. `ntru.NewParams` validates `(N,Q)`.
  3. Depending on `-mode`:
     - `signverify.GenerateKeypairAnnulus` → `ntru.Keygen` → `ntru.NTRUSolve` (Antrag annulus flow; see “Key Generation” in `docs/NTRU.md`).
     - `signverify.GenerateKeypair` (trivial `(f,g)` plus `NTRUSolve`).
  4. Results are serialized via `keys.SavePublic` / `keys.SavePrivate`.
- **Related documentation**: `docs/NTRU.md` (“Key Generation”), `Commands.md` (§1).

### `sign`: Hybrid‑B Signature

- **Flags**: `-m`, `-max`, `-sigma-scale`, `-reduce-iters`, `-prec`, `-v`. These mirror the sampler options documented in `docs/NTRU.md`.
- **Call graph**:
  1. Load fixtures (`keys.LoadPublic`, `keys.LoadPrivate`, `ntru.NewParams`).
  2. Rebuild the hash-bridge target via `ComputeTargetFromSeeds` (see “Hash Bridge” in `docs/NTRU.md`).
  3. `ntru.NewSampler` + `SamplerOpts` configure Option B sampling.
  4. `Sampler.SamplePreimageTargetOptionB` returns `(s₀,s₁)` and caches the residual `s₂`.
  5. `keys.NewSignature` bundles `s₀`, `s₁`, `s₂`, seeds, and telemetry; `keys.Save` persists the JSON.
- **Output**: Stdout reports `trials_used`, whether any rejection occurred, and (if `-v`) ℓ₂ estimates. See “Signing Pipeline” in `docs/NTRU.md`.

### `verify`: Signature Verification

- No flags; operates on `./ntru_keys/signature.json`.
- **Flow**: `signverify.Verify` (see “Verification Pipeline” in `docs/NTRU.md`) recomputes the target, checks congruence `h⊛s₁ + s₀ ≡ t (mod q)`, and reruns `CheckNormC(s₁, s₂)`.

### `pacs`: Large-Field PACS Simulation

- **Flags**: map directly to `PIOP.SimOpts` (e.g., `-ncols`, `-ell`, `-rho`, `-eta`, `-theta`, `-dq`, `-kappa1..4`, `-lambda`, `-W`, `-L`). See `README.md` “Security knobs” and Phase 3 of `docs/piop.md`.
- **Call graph**:
  1. `runPACS` builds `SimOpts`.
  2. `PIOP.RunOnce` executes the pipeline documented in `docs/piop.md`.
  3. Prints verdicts, proof-size estimates, soundness budget, and (optionally) runs `VerifyNIZK` for consistency.
- **References**: `docs/piop.md` (Phases 1–3), `docs/lvcs.md`, `docs/decs.md` for the underlying commitment layers.

### `pacs-small`: Small-Field Variant

- Same structure as `pacs` but with θ>1 defaults (`-theta`, `-ell`, `-rho`, etc.) exposed for the small-field PCS described in `docs/piop.md` (extension-field support).

---

## `cmd/ntru_sign`

Purpose-built signer for experiments with custom messages or manually supplied targets:

```
go run ./cmd/ntru_sign -msg message.txt -outdir ./NTRU_Signature
```

- **Key features**:
  - Accepts `-msg` (file path or hex string) or `-target` (colon-separated polynomial coefficients).
  - Allows overriding sampler parameters (`-alpha`, `-rsq`, `-slack`, `-trials`, `-N`, `-Q`).
  - Reuses the same hash-bridge logic (`ComputeTargetFromSeeds`) when only a message is provided.
- **Flow**:
  1. Builds fresh trapdoors with `ntru.Keygen`.
  2. Instantiates a sampler (`ntru.NewSampler`), sets `SamplerOpts`, and calls `SamplePreimageTargetOptionB`.
  3. Persists the target and signature via `Sampler.WriteTargetSignature`.
- **Use cases**: deterministic experiments, regression tests, or generating standalone signature fixtures.
- **References**: `docs/NTRU.md` (“Sampler Architecture”, “Signing Pipeline”).

---

## `cmd/keycheck`

Minimal diagnostic that recomputes the centered residual for an existing signature:

```
go run ./cmd/keycheck
```

- **Flow**:
  1. Load signature (`keys.Load`) and private key (`keys.LoadPrivate`).
  2. Reconstruct the public key `h = g/f mod q`.
  3. Compute `center(h⊛s₁ + t)` and report its ℓ∞ norm and the first coefficients.
- **Purpose**: sanity-check the acceptance predicate outside the full verification stack (useful when tuning sampler parameters).
- **Reference**: `docs/NTRU.md` (“Signing Pipeline” – residual checks).

---

## `cmd/pacs_sweep`

Batch runner for PACS parameter grids (documented in `cmd/pacs_sweep/README.md`):

```
go build -o bin/pacs_sweep ./cmd/pacs_sweep
./bin/pacs_sweep -ncols=8,12 -ell=16,32 -rho=2,4 -csv out/sweep.csv -jsonl out/sweep.jsonl
```

- **Flags**:
  - Output paths: `-csv`, `-jsonl`.
  - Parameter grids: `-ncols`, `-ell`, `-ellp`, `-rho`, `-eta`, `-theta`, `-nleaves`, `-kappa1..4`, `-lambda`, `-W`, `-L`, `-dq`.
  - Queue heuristics: `-min_bits_per`, `-min_bits_total`, `-max_bits_spread`, `-est_seconds`.
  - Manual overrides: repeated `-grid key=values`.
- **Call graph**:
  1. `main` parses grids into `sweepConfig`.
  2. For each grid point, build `PIOP.SimOpts` and call `PIOP.RunOnce`.
  3. Collect `SimReport` (verdicts, timings, proof sizes) and emit CSV + JSONL rows.
  4. Uses `measure` and `prof` instrumentation via the underlying PACS run (see Phase 3 in `docs/piop.md`).
- **Outputs**: documented in `cmd/pacs_sweep/README.md` (CSV columns, JSON schema).

---

## `cmd/analysis` (Build Tag `analysis`)

Coefficient-distribution tool for batching experiments. Requires building with the `analysis` tag:

```
go build -tags analysis -o bin/analysis ./cmd/analysis
./bin/analysis -runs 50 -sign=true -out Measure_Reports
```

- **Flags** (abridged):
  - `-runs`: number of keygen iterations.
  - `-sign`: optionally produce one signature per run (records `s₀`, `s₁`, `s₂`).
  - `-keygen`: `annulus` or `cstyle`.
  - `-fixed`, `-bfile`, `-m`, `-mseedhex`, `-x0hex`, `-x1hex`: control the target generation.
  - `-out`: output directory.
- **Flow**:
  1. For each run, generate keys (`signverify`), optionally produce a signature.
  2. Aggregate coefficient vectors and residuals into summary statistics (`summaryStats`) and histograms.
  3. Render HTML dashboards (via `go-echarts`) and JSON summaries under `Measure_Reports/`.
- **Reference**: `Commands.md` (§4) provides usage patterns; algorithmic details map to `docs/NTRU.md` (sampler statistics).

---

## See Also

- `docs/NTRU.md` – NTRU trapdoors, hash bridge, sampler internals.
- `docs/piop.md` – Witness preparation, constraint gadgets, PACS orchestration.
- `docs/lvcs.md` & `docs/decs.md` – LVCS/DECS protocols referenced by PACS commands.
- `cmd/pacs_sweep/README.md` – Extended description of the sweep runner outputs.
- `Commands.md` – Quick-reference flag listings and example invocations.

Use these resources together to navigate the CLI surface and trace each command through the underlying protocol implementations.
