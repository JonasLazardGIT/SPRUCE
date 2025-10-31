# pacs_sweep Runner Documentation

`pacs_sweep` executes the PACS workflow serially across a grid of SmallWood parameters and records metrics for each configuration. It produces both CSV (for quick inspection) and JSON Lines (for full structured data) while keeping every verifier check strict.

## Synopsis

```bash
# build the tool
go build -o bin/pacs_sweep ./cmd/pacs_sweep

# run a small sweep (comma-separated grids)
./bin/pacs_sweep \
  -ncols=8,12 \
  -ell=16,32 \
  -ellp=4,8 \
  -rho=2,4 \
  -eta=2,3 \
  -theta=1 \
  -kappa1=8,16 \
  -csv=out/sweep.csv \
  -jsonl=out/sweep.jsonl
```

Each configuration is run sequentially (`GOMAXPROCS=1` by default) to stabilise timings. Every run captures verdicts (`OkLin`, `OkEq4`, `OkSum`), per-phase timings from `prof`, size counters from `measure`, the inferred polynomial degree, and the observed heap delta.

## Flag Reference

| Flag | Type | Default | Description |
| ---- | ---- | ------- | ----------- |
| `-csv` | path | `sweep.csv` | Output path for the compact CSV summary. |
| `-jsonl` | path | `sweep.jsonl` | Output path for newline-delimited JSON (`SimReport` per line). |
| `-trials` | int | `1` | Number of repetitions per parameter tuple. Each trial appends another row/JSON entry. |
| `-ncols` | CSV ints | `4,6,8,10,12,14,16` | Grid of $|\Omega|$ values (number of evaluation columns). |
| `-ell` | CSV ints | `16,18,20,22,24,26,28,30` | Grid of masked tail lengths $\ell$. |
| `-ellp` | CSV ints | `2,3,4,6,8` | Grid of LVCS/PIOP evaluation queries $\ell'$. |
| `-rho` | CSV ints | `1,2,3,4` | Grid for the batching factor $\rho$. |
| `-eta` | CSV ints | `7,9,11,13,15,17` | Grid for DECS repetitions $\eta$. |
| `-nleaves` | CSV ints | `0` | Grid for the Merkle leaf count $N$ (0 = ring dimension). |
| `-theta` | CSV ints | `1,2,3,4,6,8` | Grid for the extension degree $\theta$. |
| `-dq` | CSV ints | `0` | Grid for overriding $d_Q$ (0 = auto-compute). |
| `-max_bits_spread` | float | `64` | Reject candidates whose $\varepsilon$ components differ by more than this bit gap (≤0 disables). |
| `-kappa1..4` | CSV ints | `0` | Grinding slack for the four Fiat–Shamir rounds; 0 selects the default (16). |
| `-lambda` | int | `128` | Fiat–Shamir security target $\lambda$. |

Lists are comma-separated with optional whitespace (e.g. `-rho="2, 4"`). Empty tokens are ignored, so `-ell=16,,32` becomes `[16,32]`. Singletons do not require commas (`-theta=1`). Invalid integers cause an immediate error.

## Outputs

### CSV (`-csv`)

A compact per-run summary with stable columns:

```
"ncols","ell","ellp","rho","eta","theta",
"degree","ok_lin","ok_eq4","ok_sum","heapB",
"t_total_us","t_buildSimWith_us","sz_Fpar_linf_chain"
```

Timings are microseconds. Verdict columns use `1` / `0`. Size buckets are byte counts.

### JSONL (`-jsonl`)

Each line is a JSON-encoded `SimReport`:

```json
{
  "Opts": {"NCols": 8, "Ell": 26, "EllPrime": 10, "Rho": 7, "Eta": 7, "Theta": 1},
  "Verdict": {"OkLin": true, "OkEq4": true, "OkSum": true},
  "Degree": 34,
  "Ncols": 8,
  "Ell": 26,
  "Rho": 7,
  "QMod": 1038337,
  "TimingsUS": {"buildSimWith": 28450, "__total__": 31614},
  "SizesB": {"piop/Fpar/linf_chain": 16384, "piop/witness/linf_chain/M": 8192},
  "PeakHeapB": 4304448
}
```

Analyse the JSON with `jq` or similar tooling:

```bash
jq '.Verdict + {ncols: .Ncols, ell: .Ell, total_us: .TimingsUS.__total__}' sweep.jsonl
```

## Failure Handling

- The runner never relaxes security checks. If the prover or verifier fails, the JSON entry records the failed verdict (e.g. `"OkEq4": false`).
- Diagnostics are written to `stderr`:

```
[pacs_sweep] failure=OkEq4 seed=12345 reason=verifier rejection opts={...}
[pacs_sweep] timings_us=map[buildSimWith:187042 __total__:187211]
```

`failure` lists all failing verdict keys (comma-separated). `reason=init` denotes an early error (e.g. missing fixtures).

## Filtering Diagnostics

Sweeps often explore very large grids while enforcing minimum soundness (`-min_bits_per`, `-min_bits_total`) and bit-spread limits (`-max_bits_spread`). To make it clear why most tuples are being dropped, the runner now prints a breakdown of prediction-stage and post-run rejections. Use `-log_rejections=N` to dump the first `N` rejected tuples together with their predicted bits, total soundness, and `dQ`. This makes it easy to see whether, for example, the per-component threshold or the spread limit is the tightest constraint and to adjust the CLI knobs accordingly.

## Automatic Grinding Boosts

Whenever a parameter tuple survives the predictor but exhibits an ε component more than 2 bits below the strongest component, `pacs_sweep` automatically assigns up to 2 grinding bits (`κᵢ≤2`) to the affected Fiat–Shamir round. Each such tuple is executed three times – once with no extra grinding, once with a +1 slack, and once with +2 (only when the heuristic says +2 may be required) – so you can see the exact impact of the extra rounds. The CLI summary prints how many tuples required boosts and the cumulative bits per round so you can gauge the resulting Fiat–Shamir cost.

## Suggested Workflows

1. **Baseline sweep**: run with defaults to capture the current proof shape and size.
2. **Soundness sweep**: vary `-ncols`, `-ell`, and `-ellp` together to inspect Eq. (8)/(10) under different interpolation grids.
3. **Batching stress test**: expand `-rho` and `-eta` to quantify batching pressure on the LVCS/DECS layers.

For large grids, redirect `stderr` to a log and use `csvtool`, `pandas`, or `duckdb` to slice CSV metrics.

## Notes

- `RunOnce` forces `measure` and `prof` instrumentation on each run, resetting counters between iterations.
- Peak heap usage is computed as the delta of Go runtime allocation stats (`TotalAlloc`). For strict maxima, consider external profilers.
- The sweep is intentionally serialised; parallelising the grid would distort timing comparisons and memory measurements.

Happy sweeping!
