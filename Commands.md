### Commands and Options Guide

This guide explains how to run key generation, signing, verification, PACS simulation, and coefficient‑distribution analysis. All commands use Go modules from the repo root.

Prerequisites

* Go 1.20+ with module mode.
* Dependencies fetched automatically by `go run`/`go build`.
* `Parameters/Parameters.json` controls ring size and modulus (e.g., `n=1024`, `q=1038337`).
* Artifacts under `./ntru_keys/`:
  `public.json`, `private.json`, `signature.json`.

---

1) Key Generation

Recommended (Annulus/FFT):

```
go run ./cmd/ntrucli gen -keygen=annulus -alpha=1.20 -prec=256 -kgverbose
```

Alternative (Balanced‑ternary C‑style):

```
go run ./cmd/ntrucli gen -keygen=cstyle -fplus=11 -fminus=10 -gplus=11 -gminus=10 -kgtr=128 -prec=256
```

Flags (`gen`):

* `-mode <trivial|cstyle>` (default `cstyle`)
* `-keygen <auto|annulus|cstyle>`
* `-alpha <float>` (annulus)
* `-use-c-radius`, `-radius <float>` (fixed C radius)
* `-kgtrials <int>` (annulus)
* `-kgverbose` (annulus)
* `-fplus/-fminus/-gplus/-gminus <int>` (balanced ternary)
* `-kgtr <int>` (balanced ternary)
* `-prec <bits>`

Outputs: writes `ntru_keys/public.json`, `ntru_keys/private.json`.

Notes: `NTRU_ANNULUS_DEFAULT=1` or `NTRU_KEYGEN=annulus` can flip the default in auto mode.

---

2) Signing (Hybrid‑B, C‑style residual acceptance)

The signer mirrors Antrag’s two-plane sampler and acceptance rule: draw using Box–Muller complex Gaussians, round ties away from zero, form `s2 := center(h⊛s1 + c1)` with the Hash-bridge target `c1`, and accept iff `CheckNormC(s1, s2)` passes. Trapdoor Babai reduction (`ReduceTrapdoor(64)`) runs before every signature attempt.

```
go run ./cmd/ntrucli sign -m "hello" -max 2048 -sigma-scale 1.0 -reduce-iters 64 -prec 256 -v
```

Flags (`sign`):

* `-m <string>` – message to sign (required).
* `-max <int>` – maximum rejection trials (default 2048).
* `-sigma-scale <float>` – multiplier applied to the per-slot sigmas from `ComputeSigmasC` (must be ≥ 1.0; default 1.0).
* `-reduce-iters <int>` – Babai reductions on `(F,G)` before sampling (default 64).
* `-prec <bits>` – big-float/FFT precision used by the sampler (default 256 bits).
* `-v` – verbose telemetry (`l2_est` plus residual diagnostics in debug builds).

Notes:

* The residual bound is always `CheckNormC(s1, center(h⊛s1 + c1))` with Antrag’s `(R², α, Slack)` parameters (LOG3 cross-terms enabled automatically when the parameter set requires them).
* Targets come exclusively from the Hash Bridge (`ComputeTargetFromSeeds` + `Parameters/Bmatrix.json`).
* Output: writes `./ntru_keys/signature.json`; stdout reports `trials_used`, whether any rejections occurred, and `max_trials`.

Signature encoding details:

* The JSON bundle now persists `signature.s2`, the centered residual `s₂ := center_Q(h⊛s₁ + c₁)` generated during signing. This vector is the object tested by the acceptance predicate and sits in the few-thousand range even when the mod-`Q` lift of `t − h⊛s₁` lives near ±`Q/2`.
* Both `s₁` and `s₂` satisfy the norm constraint, giving the linear relation 

  ```
  [ I | h ] · [ s₂ ; s₁ ] ≡ c₁ (mod Q).
  ```

* `s0` remains in the record for completeness, but downstream tooling (e.g. `cmd/analysis`) should prefer `s₂` when inspecting "small" signature components.

Verification enforces the same predicate: it recomputes `center_Q(h⊛s₁ + c₁)`, checks that it matches the stored `s₂`, and re-runs `CheckNormC(s₁, s₂)` before asserting congruence.

---

3) Verification

```
go run ./cmd/ntrucli verify
```

On success, prints `signature verified`.

---

(Optional sections: PACS & coefficient analysis remain as‑is.)

---

4) Distribution Analysis (Measure_Reports)

Build the analysis tool (tagged `analysis`) and run it to aggregate coefficient distributions into HTML + JSON under `./Measure_Reports`.

Build:

```
go build -tags analysis ./cmd/analysis
```

Examples:

- Annulus keygen (default), sign each run, auto targets per run:

```
./analysis -runs 50 -sign=true -out Measure_Reports
```

- Balanced‑ternary keygen, sign each run, fixed target across runs (fixed B, m, x0, x1):

```
./analysis \
  -runs 50 -sign=true -keygen cstyle -out Measure_Reports \
  -fixed -bfile Parameters/Bmatrix.json \
  -m "analysis-fixed" \
  -x0hex 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f \
  -x1hex f0e0d0c0b0a0908070605040302010ff0e0d0c0b0a0908070605040302010f
```

Outputs:

- HTML: `Measure_Reports/coeff_histograms_YYYYMMDD_HHMMSS.html`
- JSON: `Measure_Reports/coeff_stats_YYYYMMDD_HHMMSS.json`

Flags (`analysis`):

- `-runs <int>`: keygen runs (default 20)
- `-sign <bool>`: include one signature per run (captures `s0`, `s1`, **and** `s2`)
- `-keygen <annulus|cstyle>`: keygen engine (default `annulus`); failures in annulus mode are retried automatically
- `-out <dir>`: output directory (default `Measure_Reports`)
- `-fixed`: use a fixed target across runs
- `-bfile <path>`: B-matrix JSON path (fixed target)
- `-m <string>`: message string (SHA256 hashed to `mseed`) when `-mseedhex` is not set
- `-mseedhex <hex>`: 32-byte hex message seed to override `-m`
- `-x0hex/-x1hex <hex>`: 32-byte hex seeds for `x0`/`x1`

The generated stats/plots now include an `s2` histogram that reflects the centered residual distribution bound during Antrag signing. Key generation defaults to the annulus sampler (`go run ./cmd/ntrucli main.go gen -keygen annulus`), and the signing stage mirrors the `NTRU_DEBUG=1 go run ./cmd/ntrucli/main.go sign -m "Hello World"` workflow used for end-to-end Antrag runs.


# Commands, Tags, and Options

This document complements `Commands.md` with flags and build tags. Prefer `Commands.md` for canonical CLI usage and examples.

Prerequisites

- Go 1.20+ with modules
- `Parameters/Parameters.json` and `Parameters/Bmatrix.json`

Core Commands

- Keygen (annulus/FFT): `go run ./cmd/ntrucli gen -keygen=annulus -alpha=1.20 -prec=256 -kgverbose`
- Sign: `go run ./cmd/ntrucli sign -m "hello" -max 2048 -v`
- Verify: `go run ./cmd/ntrucli verify`
- PACS: `go run ./cmd/ntrucli pacs -ell 1 -ncols 8 -rho 1 -measure=true`

Build Tags

- `analysis`: enables the distribution analysis tool under `cmd/analysis`.

Distribution Analysis

Build:

```
go build -tags analysis ./cmd/analysis
```

Examples:

- Auto target per run:
  `./analysis -runs 50 -sign=true -keygen annulus -out Measure_Reports`

- Fixed target (fixed B, m, x0, x1):

```
./analysis \
  -runs 50 -sign=true -keygen cstyle -out Measure_Reports \
  -fixed -bfile Parameters/Bmatrix.json \
  -m "analysis-fixed" \
  -x0hex 000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f \
  -x1hex f0e0d0c0b0a0908070605040302010ff0e0d0c0b0a0908070605040302010f
```

Outputs: `Measure_Reports/coeff_histograms_*.html`, `Measure_Reports/coeff_stats_*.json`

Environment

- `NTRU_ANNULUS_DEFAULT=1` flips `gen -keygen=auto` to annulus/FFT
- Signing (Hybrid‑B) defaults: `RSquare≈7.84` (from `CReferenceRSquare()`), `Alpha=1.25`, `Slack≈1.042`, `MaxSignTrials=2048`. Use `-exact-residual` and `-bound-shape` for tight mode, keeping in mind the upgraded big-float norm check in `CheckNormC`.

See `Commands.md` for detailed flags and additional examples.
