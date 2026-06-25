# Prover (NeutronNova / spartan2) memory profile

How memory is spent when proving the SPHINCS+ `C_core` with NeutronNova, where the peaks are, what
has been optimized, and the remaining levers to make the **full** verify core prove at scale.

Backend: local `spartan2` fork at `../csp/spartan2-debug` (wired in via
`[patch.crates-io] spartan2 = { path = "../csp/spartan2-debug" }`).

> Context: the full verify `C_core` is ≈ **49M constraints** (see `docs/SOUNDNESS_AUDIT.md` /
> `docs/VERIFY_CORE.md`). Memory is dominated by terms that are **O(constraints)** or
> **O(variables)** in that core. The durable fix is to *shrink* `C_core` by folding more SHA work
> into `C_step` instances (FORS/WOTS/hypertree trace linking); everything below reduces constant
> factors on top of a circuit of a given size.

## Where the memory goes

### 1. Setup — `ShapeCS` → sparse matrices (`bellpepper/r1cs.rs::r1cs_shape`)

`ShapeCS` collects every constraint as a triple of linear combinations:

```rust
pub constraints: Vec<(LinearCombination, LinearCombination, LinearCombination)>
```

For the full core that is ≈ 49M triples. Each `LinearCombination` holds `Vec<(usize, Scalar)>`
terms (`Scalar` = 32 bytes). SHA-256 constraints have several terms across A/B/C, so the term
storage dominates (tens of GB), with the `Vec` spine (~192 B/constraint ≈ 9 GB) on top.

These are then converted into three CSR `SparseMatrix` (`A`, `B`, `C`).

**Optimization applied:** the conversion loop now **consumes** the constraints by value
(`std::mem::take` + `into_iter`) and drops `ShapeCS` first, so each `(A,B,C)` LC triple's heap is
freed as it is folded into the matrices — instead of the old `iter()` borrow that kept the entire
`Vec<(LC,LC,LC)>` alive *alongside* the three finished matrices. This roughly halves the
setup-phase transient (you no longer hold the full constraint list and the full matrices at the
same time). The CSR `indptr` arrays are also `reserve`d up front to avoid O(log n) reallocations.
Semantics are unchanged (identical matrices); verified by the 8 NeutronNova prove+verify tests.

### 2. Shape stores up to three matrix representations (`r1cs/mod.rs::SplitR1CSShape`)

```rust
A, B, C: SparseMatrix,                       // ~40 B / nonzero (data: 32B Scalar + indices: 8B)
precomp_A/B/C: OnceCell<PrecomputedSparseMatrix>,  // lazy; ~4-5 B / nonzero for ±1 / small coeffs
filtered_A/B/C: OnceCell<FilteredSpmv>,            // lazy
```

The `Precomputed` form is far leaner than the original sparse: most R1CS coefficients from SHA are
`±1` and are stored as a bare `u32` column index with **no** field element. Once the precomputed
(and filtered) accelerators are built during prove, the original `SparseMatrix` `data`/`indices`
are largely dead weight — but they are **load-bearing**: the shape **digest** (`write_digest_bytes`)
and a `multiply_vec` path read `self.A/B/C`, and the split routine clones them. Dropping/Compacting
them safely is a larger change (see Levers).

### 3. Witness — multiple full-size copies (`r1cs.rs::r1cs_instance_and_witness`)

During prove the witness exists as up to three `Vec<Scalar>` of length `num_vars`
(≈ tens of millions × 32 B ≈ 1.5 GB each):

- `ps.cs.aux_assignment` — retained in `PrecommittedState` for re-synthesis on the next fold round.
- `ps.W` — reallocated fresh each call (the previous one is moved out).
- `w_vec` — the moved-out witness handed to `R1CSWitness`.

This triple-buffering is **intentional** for multi-round fold reuse (the rest section is re-copied
from `aux_assignment` on the next call), so it is not safe to collapse without reworking the
fold-round state machine.

## Optimizations applied

| Area | Change | Effect | Risk |
|------|--------|--------|------|
| `r1cs_shape` | Consume constraints by value + drop `ShapeCS` before/while building matrices; reserve `indptr` | ~halves setup-phase transient (constraint list no longer co-resident with finished matrices) | Low — semantics-preserving, output identical |

## Remaining levers (ranked by impact, with risk)

1. **Shrink `C_core` (durable, highest impact).** Trace-link FORS / WOTS / hypertree SHA so those
   compressions move into folded `C_step` instances. This reduces *every* term above
   proportionally. This is the real "run at scale" fix; tracked as the main remaining feature.
2. **Compact the original `SparseMatrix` after precompute (large permanent win, medium risk).**
   After `precomp_*` / `filtered_*` are built, the only remaining readers of `self.A/B/C` are the
   shape **digest** and one `multiply_vec` path. If the digest is computed once and cached, and the
   matvec is routed through the precomputed form, the original `data`/`indices` (~40 B/nz) could be
   freed — at 49M constraints this is tens of GB. Needs an audit that no release-mode prove path
   reads `self.A/B/C` after precompute, plus keeping serialization/digest correct.
3. **Reduce witness triple-buffering (medium win, higher risk).** Reuse one buffer across
   `aux_assignment` / `W` / `w_vec` where a single fold round is used. Requires reworking the
   `PrecommittedState` reuse contract; correctness across fold rounds must be preserved.
4. **Streaming commitment / chunked MSM (prover backend).** Commit to the witness in chunks rather
   than materializing committed intermediates; spartan2-internal.
5. **`u32` indices / small-value packing.** `SparseMatrix.indices: Vec<usize>` could be `u32`
   (≤ 4B variables), halving index storage; `PrecomputedSparseMatrix` already uses `u32`.

## Why full-scale before/after isn't measured here

The only circuit large enough to show a meaningful difference is the full 49M-constraint core,
which does not fit in this machine's RAM — the exact problem being addressed. The applied change is
semantics-preserving and validated for correctness by the NeutronNova prove+verify suite
(`fold_verify_core_hash_message`, `fold_verify_core_hash_message_public_io`). Quantitative
full-scale numbers should be taken on a high-RAM host.
