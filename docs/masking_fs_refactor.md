# Masking/FS Refactor Tasks (Staged, Verifiable)

Goal: Extract the masking/Merkle/FS loop from `buildSimWith` into reusable helpers without breaking the PACS path. Each step is small and testable.

## Step 1: Define carrier structs (no behaviour change) ✅
- Add `maskFSArgs` and `maskFSOutput` structs in a new file (e.g., `PIOP/masking_fs_helper.go`).
- Fields in `maskFSArgs` (all taken from existing locals):
  - `ringQ *ring.Ring`, `omega []uint64`, `q uint64`, `rho int`, `ell int`, `ellPrime int`, `opts SimOpts`, `ncols int`.
  - Small-field params: `smallFieldK *kf.Field`, `smallFieldChi []uint64`, `smallFieldOmegaS1 kf.Elem`, `smallFieldMuInv kf.Elem`.
  - Public tables: `A [][]*ring.Poly`, `b1 []*ring.Poly`, `B0c []*ring.Poly`, `B0m [][]*ring.Poly`, `B0r [][]*ring.Poly`.
  - Witness: `w1 []*ring.Poly`, `w2 *ring.Poly`, `w3 []*ring.Poly`, `origW1Len int`, `mSig int`.
  - Range offsets: `msgRangeOffset`, `rndRangeOffset`, `x1RangeOffset int`.
  - Constraints: `FparInt`, `FparNorm`, `FaggInt`, `FaggNorm`, `FparAll`, `FaggAll []*ring.Poly`, `parallelDeg`, `aggDeg int`.
  - Mask config: `maskDegreeTarget`, `maskDegreeBound int`, `maskDegreeClipped bool`, `maskDegreeBase int`, `independentMasks []*ring.Poly`, `independentMasksK []*KPoly`.
  - Rows/layout: `rows [][]uint64`, `rowInputs []lvcs.RowInput`, `witnessRowCount`, `maskRowOffset`, `maskRowCount int`, `rowLayout RowLayout`, `oracleLayout lvcs.OracleLayout`, `decsParams decs.Params`.
  - Points/openings: `smallFieldEvals []kf.Elem` (if needed), placeholders for FS salts/ctr if desired.
- Fields in `maskFSOutput`:
  - `proof *Proof`
  - `Gamma`, `GammaPrime`, `GammaAgg [][]uint64`, `GammaPrimeK`, `GammaAggK [][]KScalar`
  - `M []*ring.Poly`, `MK []*KPoly`, `Q []*ring.Poly`, `QK []*KPoly`
  - `barSets [][]uint64`, `coeffMatrix [][]uint64`, `kPoint [][]uint64`, `evalPoints []uint64` (or packed)
  - `vTargets [][]uint64`, `openings` as needed (`openMask`, `openTail`, `combinedOpen`)
  - `maskRowOffset`, `maskRowCount`, `maskDegreeBound`, `rowLayout`
  - Any other values currently stored in `ctx` from the masking/FS block.
- This step is purely structural; no code paths use the structs yet. Run `go test ./PIOP ./tests` to confirm no change.

## Step 2: Extract masking/FS logic into `runMaskFS` (verbatim, staged) ✅
To reduce risk, split the extraction into sub-tasks, keeping logic identical at each sub-step and running tests after each move.

### 2a) FS scaffold + verifier init ✅
- Implement `runMaskFS(args maskFSArgs) (maskFSOutput, error)` with just:
  - FS init (salt/XOF/FS state).
  - Verifier init (`lvcs.NewVerifierWithParams`), using `args.decsParams`, `args.ncols`, `args.oracleLayout`, and `args.Root`.
  - CommitFinish call on `args.PK` with sampled Gamma (Round 1) and store `Rpolys`/mask openings.
  - Populate proof header fields: Root, Salt, Ctr/Digests[0], Lambda/Theta/Kappa, RowLayout, MaskRowOffset/Count/Bound, Chi/Zeta for small-field.
- Return these in `maskFSOutput` (proof + Gamma + Rpolys) so `buildSimWith` can keep going with existing logic.
- Run `go test ./PIOP ./tests`.

### 2b) FS Round 2 + GammaPrime/GammaAgg sampling ✅
- Extend `runMaskFS` to include Round 2 (GammaPrime/GammaAgg), small-field branch included.
- Populate Gamma*/Gamma*K in output; keep proof.Gamma* assignments identical.
- Keep `buildSimWith` still computing masks/Q/eval points; only delegate Gamma sampling.
- Run tests.

### 2c) Mask/Q generation ✅
- Move mask generation and Q/QK construction into `runMaskFS`, taking Fpar/Fagg, omega, mask targets, Gamma*/GammaAgg*, small-field params from args.
- Populate M/MK/Q/QK, mask degree checks, and snapshots in `maskFSOutput`.
- `buildSimWith` now skips mask/Q generation and uses returned M/MK/Q/QK when computing okLin/okEq4/okSum.
- Run tests.

### 2d) Eval points (Round 3), proof population, tail, openings ✅
- Round 3 FS call, eval point sampling (K and non-K), coeffMatrix/kPoint/barSets/vTargets, proof field population, and tail sampling/openings all live in `runMaskFS`.
- `buildSimWith` (θ>1) consumes `maskFSOutput` and no longer inlines masking/FS; round-3 digests fixed via stored tail transcript.

### 2e) Final cleanup ✅
- Dead locals removed; okLin/okEq4/okSum computed on `runMaskFS` outputs; `simCtx` population unchanged. PACS tests green.

## Step 3: Generic builder/verify (next)
- Implement `BuildWithConstraints`/`VerifyWithConstraints` on top of `runMaskFS` with explicit publics/witnesses/F-polys and personalization.
- Keep PACS as a wrapper using PACS personalization; credential builder will call the generic path.

## Notes
- Masking/FS extraction is complete; behaviour matches PACS.
- Next focus: generic builder/verify wiring and credential constraint set (commit/center/hash/bounds, PRF later).
