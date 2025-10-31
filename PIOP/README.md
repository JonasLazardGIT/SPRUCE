# PIOP Verifier Notes

`VerifyNIZK` replays the Fiat–Shamir transcript using only the serialized proof
snapshot. The prover ships DECS openings in their packed form (all evaluation
vectors are stored inside the 20-bit `PvalsBits`/`MvalsBits` streams and Merkle
paths are encoded through the fixed-width `PathBits` bitstream).

The verifier therefore calls `expandPackedOpening` before re-running any DECS
check. This helper rebuilds `Pvals`, `Mvals`, and the per-branch path indices
from the packed buffers so that `decs.VerifyEvalAt` can operate without access
to the original prover state. When adding new proof fields, keep this workflow
in mind – new packed artifacts must either be expanded before use or handled by
APIs that understand the packed representation directly.

The “proof size” reported by tools such as `ntrucli` is the exact byte footprint
of this transcript material: the verifier counts every serialized field it must
read (`Salt`, `Ctr`, digests, mask commit data, packed openings, `BarSets`,
`VTargets`, etc.) and ignores anything it can deterministically re-derive
locally (coefficient matrices, evaluation points, public parameters). This
mirrors the accounting done in `proofSizeBreakdown` / `MeasureProofSize`, so the
CLI’s size totals match the data that really crosses the wire.

As part of the snapshot round-trip tests (`TestVerifyNIZKSnapshotRoundTrip` and
`TestVerifyNIZKSmallFieldRoundTrip`), we explicitly compare the packed opening
that `expandPackedOpening` produces against the prover’s unpacked reference.
These tests will fail if the packing format changes or if any clone logic drops
metadata required to rehydrate the opening.

`cloneDECSOpening` preserves zero-length slices as nil so that packed openings
remain distinguishable from unpacked ones. If you modify the packing logic in
`DECS`, double-check that `cloneDECSOpening` and the round-trip tests still
agree on the resulting serialization.

## Merkle commits and compression

The DECS layer authenticates every evaluation row with a Merkle tree whose
leaves encode the prover’s *entire* per-column record:

* the masked polynomial values `P_j(ω_i)` (one limb per row `j`);
* the masking polynomials `M_k(ω_i)` for each DECS repetition;
* the leaf index `i`, stored as a little-endian `uint16`; and
* a per-leaf nonce `ρ_i` derived from a global seed (so two different proofs
  never collide on the same transcript even if their evaluations match).

`DECS/prover.go` constructs the leaf buffer as a tightly-packed little-endian
byte slice (`4·(r + η) + 2 + NonceBytes` bytes) and hashes it with SHAKE-256,
prefixed with `0x00`, to obtain a 16-byte leaf digest. Internal nodes are
derived by concatenating the left/right child hashes with a `0x01` prefix and
rehashing, so the overall tree is collision-resistant while remaining compact.
Padding leaves are deterministically filled with the digest of the single byte
`0x00` to keep the tree a perfect power of two; they never participate in any
openings because the prover only ever exposes real indices.

### Why the transcript stores a frontier instead of paths

During an evaluation the prover must reveal Merkle authentication data for
`ℓ` challenged coordinates. Serializing all `ℓ·log₂N` sibling hashes naively
would dominate the proof size (each sibling is 16 bytes), so the DECS commit
protocol transmits a *frontier* instead:

1. The prover groups leaves that traverse the same internal nodes and tags, for
   each level, whether that branch consumes a freshly-transmitted sibling hash
   or reuses a sibling that is already present in the set.
2. The sibling hashes that actually have to cross the wire are stored once in
   `FrontierNodes`. A short reference stream (`FrontierRefsBits`, with width
   `FrontierRefWidth` and length `FrontierRefCount`) records, for each proof
   event, which union entry should be used.
3. Two bitmaps (`FrontierProof` and `FrontierLR`) track, for every opened leaf
   and every depth, whether a proof node is used and whether the proven node is
   on the left or right of its sibling. Both bitmaps are packed densely so we
   amortize their cost over thousands of leaves.
4. `FrontierDepth` records the number of Merkle levels so the verifier can
   reconstruct the tree height without shipping dag metadata.

On the verifier side, `EnsureMerkleDecoded` (in `DECS/decs_frontier.go`) walks
the frontier, recomputes the per-leaf hashes, and rebuilds the explicit
`Nodes`/`PathIndex` matrices on demand. This allows older consumers or tests to
inspect traditional Merkle paths without forfeiting the bandwidth savings
obtained by the packed representation.

### Compression ratio

For typical parameters (`N = 2¹⁸`, `ℓ = 26`, `η = 7`, `NonceBytes = 16`) the
frontier encoding cuts the Merkle payload from ~74 KiB (raw paths) to ~8 KiB.
Only 26 sibling hashes (one per level) are transmitted because all opened
indices share the same frontier. The remaining metadata shrinks to a few
hundred bytes thanks to the bit-packed `FrontierProof`/`FrontierLR` vectors.
This optimization is the main reason why the PACS proof fits in a few tens of
kilobytes instead of hundreds.

### Numeric streams

Matrices such as `MR`, `BarSets`, and `VTargets` now share a common packed
representation: a 10-byte header (rows, cols, bit width) followed by a
fixed-width payload. The encoder automatically drops to 16-bit streams when the
coefficients fit below `2¹⁶`, falling back to 20+ bits otherwise. Proof
snapshots, verifier replays, and the size tooling all consume the packed form,
so the savings propagate to every report.

### End-to-end flow

1. `CommitInit` samples the nonce seed, builds the Merkle tree, and caches both
   the root and the per-column leaf buffers. The root is what the prover
   commits to in round 1 and is the only Merkle artifact that reaches the
   verifier before openings are requested.
2. `EvalOpen` gathers the requested leaves, de-duplicates sibling hashes, and
   emits the compact frontier. The opening bundle carries just enough metadata
   for the verifier to re-expand the frontier deterministically.
3. `VerifyEvalAt` asks `EnsureMerkleDecoded` to inflate the frontier if it
   needs traditional paths, recomputes the hashes from the transmitted
   evaluation values/nonces, and checks the root matches the commitment.

These three steps are reflected in the simulation tests
(`TestPACSMaskCommitTamper`, `TestDECS/Merkle` scenarios, and the NIZK snapshot
round-trips) so that any change to the hashing domain separators, leaf layout,
or frontier packing will result in an immediate regression test failure.
