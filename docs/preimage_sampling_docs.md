# Preimage Sampling and BBS Hash Routines

This document summarizes the main routines found in the `Preimage_Sampler` and `vSIS-HASH` packages.  Each section lists the purpose of a function, its inputs, outputs and any noteworthy calls that are performed internally.  Line references refer to the source files under this repository.

## `Preimage_Sampler/bigcomplex.go`

This file defines arbitrary precision complex arithmetic and helpers for working with cyclotomic field elements.  Important types:

- **`BigComplex`** — complex number with `big.Float` real and imaginary parts.
- **`CyclotomicFieldElem`** — slice of `BigComplex` values representing an element of K_{2N}.  A `Domain` flag denotes whether values are in coefficient or evaluation form.

### Construction and Arithmetic

| Function | Summary |
|----------|---------|
| `NewBigComplex(real, imag float64, prec uint)` | Creates a `BigComplex` with the given real and imaginary parts at the specified precision. 【F:Preimage_Sampler/bigcomplex.go†L28-L33】 |
| `NewBigComplexFromFloat(re, im *big.Float)` | Copies `big.Float` values into a `BigComplex`. 【F:Preimage_Sampler/bigcomplex.go†L35-L41】 |
| `NewBigComplexZero(prec uint)` | Returns a zero value at `prec` bits of precision. 【F:Preimage_Sampler/bigcomplex.go†L43-L45】 |
| `(*BigComplex) Add/Sub/Mul` | Standard complex addition, subtraction and multiplication. 【F:Preimage_Sampler/bigcomplex.go†L48-L74】 |
| `(*BigComplex) Conj` | Returns the conjugate of a complex value. 【F:Preimage_Sampler/bigcomplex.go†L76-L82】 |
| `(*BigComplex) AbsSquared` | Computes |z|^2. 【F:Preimage_Sampler/bigcomplex.go†L84-L88】 |
| `(*BigComplex) Inv` | Inverse (1/z). Uses conjugate and `AbsSquared`. 【F:Preimage_Sampler/bigcomplex.go†L91-L99】 |
| `(*BigComplex) Copy` | Deep copy of a value. 【F:Preimage_Sampler/bigcomplex.go†L101-L107】 |
| `(*BigComplex) DivBy(s *big.Float)` | Divides by a scalar real. 【F:Preimage_Sampler/bigcomplex.go†L109-L114】 |

### FFT Utilities

- `FFTBig(coeffs []*BigComplex, prec uint)` – Cooley–Tukey FFT operating on `BigComplex` slices. Performs bit‑reversal ordering then iterative FFT. Returns a new slice in evaluation domain. 【F:Preimage_Sampler/bigcomplex.go†L179-L329】
- `IFFTBig(evals []*BigComplex, prec uint)` – Inverse FFT; divides each coefficient by n at the end. 【F:Preimage_Sampler/bigcomplex.go†L261-L327】

Helper `bitReverseBig` computes bit‑reversal permutations. 【F:Preimage_Sampler/bigcomplex.go†L332-L345】

### Conversions between `ring.Poly` and field elements

- `ConvertFromPolyBig(r *ring.Ring, p *ring.Poly, prec uint)` — lifts a polynomial to high‑precision complex form and applies FFT. 【F:Preimage_Sampler/bigcomplex.go†L356-L380】
- `ConvertToPolyBig(f *CyclotomicFieldElem, r *ring.Ring)` — inverse FFT back to coefficients, rounding to integers mod q. 【F:Preimage_Sampler/bigcomplex.go†L395-L433】

Other helpers convert between coefficient and evaluation (negacyclic) forms. 【F:Preimage_Sampler/bigcomplex.go†L467-L624】

### Field Operations

- `FieldAddBig`, `FieldSubBig`, `FieldMulBig` — component-wise arithmetic. 【F:Preimage_Sampler/bigcomplex.go†L627-L657】
- `FieldScalarMulBig` — multiply every coordinate by a scalar. 【F:Preimage_Sampler/bigcomplex.go†L663-L668】
- `FieldScalarDiv` — divide by norms with error checking. 【F:Preimage_Sampler/bigcomplex.go†L671-L683】
- `HermitianTransposeFieldElem` — polynomial transpose of an element. 【F:Preimage_Sampler/bigcomplex.go†L685-L731】
- `FieldInverseDiagWithNorm` — returns coordinate-wise conjugate and norms. 【F:Preimage_Sampler/bigcomplex.go†L734-L759】

### Utility Methods

- `PstrideBig` splits even and odd coefficients. 【F:Preimage_Sampler/bigcomplex.go†L761-L773】
- `(CyclotomicFieldElem) SubScalar/AddScalar` — add or subtract a scalar. 【F:Preimage_Sampler/bigcomplex.go†L775-L786】
- `(CyclotomicFieldElem) Copy` and `Conj` — deep copy and conjugation. 【F:Preimage_Sampler/bigcomplex.go†L789-L815】
- `(BigComplex) ToComplex` — convert to `complex128`. 【F:Preimage_Sampler/bigcomplex.go†L817-L821】
- `SetCoeffs`, `ExtractEven`, `ExtractOdd`, `InversePermuteFieldElem` — coefficient helpers. 【F:Preimage_Sampler/bigcomplex.go†L824-L875】
- `FloatToEvalNegacyclic` / `FloatToCoeffNegacyclic` — floating-point negacyclic FFT and inverse. 【F:Preimage_Sampler/bigcomplex.go†L877-L974】

## `Preimage_Sampler/discretegauss.go`

Implements discrete Gaussian sampling.

- `SetForceZero(b bool)` — enable deterministic zero sampling. 【F:Preimage_Sampler/discretegauss.go†L20-L26】
- `NewDiscreteGaussian(std float64)` — create a sampler; may panic if σ is too large. 【F:Preimage_Sampler/discretegauss.go†L37-L49】
- `(*DiscreteGaussian) initialize()` — build the inversion CDF. 【F:Preimage_Sampler/discretegauss.go†L51-L72】
- `(*DiscreteGaussian) Draw(mean float64)` — draw a sample using either inversion or Karney’s rejection routine. 【F:Preimage_Sampler/discretegauss.go†L74-L95】
- `karney(mean, sigma float64)` — exact sampler composed of `algoG`, `algoP` and `algoB`. 【F:Preimage_Sampler/discretegauss.go†L97-L129】
- `algoH`, `algoHDouble`, `algoG`, `algoP`, `algoB`, `algoBDouble` — auxiliary Bernoulli and rejection subroutines. 【F:Preimage_Sampler/discretegauss.go†L132-L247】

## `Preimage_Sampler/G_Sampling.go`

Trapdoor generation and discrete G-sampling routines.

- `CreateGadgetMatrix(ringQ, base, rows, k)` — returns the gadget matrix with powers of the base. 【F:Preimage_Sampler/G_Sampling.go†L30-L64】
- `TrapGen(ringQ, base, sigmaT)` — samples a random public key and its trapdoor. Calls `CreateGadgetMatrix` and draws Gaussian polynomials. 【F:Preimage_Sampler/G_Sampling.go†L66-L143】
- `Perturb(sigma, l, h, base)` — integer perturbation vector generation. Calls `NewDiscreteGaussian` per coordinate. 【F:Preimage_Sampler/G_Sampling.go†L145-L179】
- `SampleC(c, sigma, a)` — draws a lattice vector according to PALISADE’s algorithm, updating the accumulator. 【F:Preimage_Sampler/G_Sampling.go†L182-L215】
- `SampleGDiscrete(ringQ, sigma, base, uCoeff, k)` — discrete G-sampling used in `GaussSamp`. Relies on `Perturb` and `SampleC`. 【F:Preimage_Sampler/G_Sampling.go†L217-L333】

## `Preimage_Sampler/helper.go`

General helpers used throughout the sampler.

- `baseDigits(v, base, k)` — decompose an integer into base-`t` digits. 【F:Preimage_Sampler/helper.go†L12-L25】
- `AutomorphismTranspose(r, p)` — negacyclic polynomial transpose. 【F:Preimage_Sampler/helper.go†L28-L46】
- `FFT` and `IFFT` — complex FFT utilities. 【F:Preimage_Sampler/helper.go†L48-L143】
- `bitReverse` — bit reversal used by the FFTs. 【F:Preimage_Sampler/helper.go†L145-L152】
- `ModQToFloat64` — map a coefficient into a centered float64. 【F:Preimage_Sampler/helper.go†L156-L162】
- `PolyNorm2` — Euclidean norm of a polynomial. 【F:Preimage_Sampler/helper.go†L164-L175】
- `UnsignedToSigned` / `SignedToUnsigned` — convert between centered and standard representations. 【F:Preimage_Sampler/helper.go†L177-L198】
- `DotProduct(r, a, b)` — negacyclic dot product using `AutomorphismTranspose`. 【F:Preimage_Sampler/helper.go†L200-L217】

## `Preimage_Sampler/Perturbation_Sampling.go`

- `Sample2zField(a, b, d, c0, c1, n, modulus, prec)` — 2×2 lattice sampler. Uses `SampleFZBig`, field operations and diagonal inversion. 【F:Preimage_Sampler/Perturbation_Sampling.go†L14-L137】
- `SampleFZBig(f, c, modulus, prec)` — single field sampling; splits even/odd parts and calls `Sample2zField`. 【F:Preimage_Sampler/Perturbation_Sampling.go†L141-L195】
- `Permute(p *Matrix[int64])` — reorder entries, used mainly for testing. 【F:Preimage_Sampler/Perturbation_Sampling.go†L199-L215】
- `SamplePz(ringQ, s, alpha, Ttilde, expectedLength, prec)` — full perturbation generation algorithm producing polynomials `p0`, `p1` and `q̂` values. Calls `DotProduct`, `Sample2zField` and performs several conversions. 【F:Preimage_Sampler/Perturbation_Sampling.go†L217-L533】
- `makeSmallRing(N, q)` — create a one-modulus ring. 【F:Preimage_Sampler/Perturbation_Sampling.go†L536-L542】

## `Preimage_Sampler/Preimage_Sampling.go`

Demonstrates the full sampling flow.

- `SpectralBound(n, k, base)` — computes the analytic spectral bound for parameter selection. 【F:Preimage_Sampler/Preimage_Sampling.go†L15-L24】
- `CalculateParams(base, n, k)` — returns `(sigmaT, s)` used by the sampler. 【F:Preimage_Sampler/Preimage_Sampling.go†L27-L33】
- `ZtoZhat(Z, ringQ)` — converts integer gadget rows into NTT polynomials. 【F:Preimage_Sampler/Preimage_Sampling.go†L36-L97】
- `GaussSamp(ringQ, A, rHat, eHat, u, sigma, s, base, k)` — Algorithm 2 of the scheme. Builds a perturbation via `SamplePz`, performs discrete G‑sampling with `SampleGDiscrete`, then assembles the final vector. 【F:Preimage_Sampler/Preimage_Sampling.go†L99-L410】
- `Main()` — example demonstrating trapdoor creation, syndrome selection, sampling and verification. 【F:Preimage_Sampler/Preimage_Sampling.go†L413-L474】

## `vSIS-HASH/vSIS-BBS.go`

Exact ring implementation of the BBS hash used in the signature scheme.

- `GenerateB(ringQ, prng)` — samples four random polynomials in coefficient domain. The caller should NTT-lift them if needed. 【F:vSIS-HASH/vSIS-BBS.go†L33-L47】
- `ComputeBBSHash(ringQ, B, m, x0, x1)` — exact computation in NTT domain using Hadamard products and slot-wise inversion. Note it NTT-lifts `m`, `x0`, `x1` in place. 【F:vSIS-HASH/vSIS-BBS.go†L75-L116】
