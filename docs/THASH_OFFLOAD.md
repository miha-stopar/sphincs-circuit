# `thash` offload — moving SPHINCS+ compressions out of `C_core` into folded steps

This document describes the architecture that lets NeutronNova keep only *glue*
in `C_core` and prove each SPHINCS+ SHA-256 compression as a tiny folded `C_step`
instance, instead of synthesizing the ~49M-constraint monolith in one relation.

It corresponds to **MASTER_PLAN items 6 & 7** ("don't put millions of SHA
constraints in one `C_core`" / "trace-link FORS / WOTS / hypertree too").

## TL;DR status

- **Done (this increment):** the *sound, self-contained mechanism* for the WOTS+
  chain `F` function — the single biggest family in the core (~75%). See
  `crates/sphincs-circuit/src/thash_link.rs`.
  - Measured: a full 15-step WOTS chain costs **349,058** constraints in-core but
    only **2,093** glue constraints once offloaded — a **~167× core reduction**
    for that family (test `core_link_shrinks_core_vs_in_core`).
  - Soundness is proven by four tamper tests (input / addr / seeded-state / out)
    plus a joint-relation satisfiability test and a fold-decomposition smoke test.
- **Next increments (not yet wired):**
  1. Replace `wots::gen_chain` with `thash_link::gen_chain_linked` inside
     `synthesize_verify_core`'s WOTS path.
  2. Teach the prover to emit one `thash_f_step` `C_step` per chain step and to
     populate the bus values, folding them through `spartan2`.
  3. Generalize the bus/step to the other `thash` families (FORS leaf/node, Merkle
     node, WOTS-pk compression, hypertree).

## Why the existing trace-linking did not offload anything

The pre-existing shared-witness bus (`shared_link.rs`) links **digest boundaries**
only — 32-byte (`8×u32`) chaining values `h_in`/`h_out`. It has no way to bind a
compression's 512-bit *message block*. Because a `thash` block contains variable
data (`addr ‖ in`), digest-boundary sharing alone cannot soundly move the
compression out of the core: a malicious prover could fold a step over a different
`in`/`addr` (this is the BUG-1 class — see `SOUNDNESS_AUDIT.md`).

As a result, even `hash_message`'s "trace-linked" path **recomputes** its
compressions in `C_core` (feeding constant blocks through
`sha256_compression_function`) for soundness; the `shared` links sit *alongside*
the in-core SHA rather than replacing it. So before this work, no compression was
actually removed from `C_core`.

## The `thash`-F structure (`inblocks = 1`)

```text
thash_F(in, addr) = SHA256( pub_seed(16) ‖ 0^48 ‖ addr(22) ‖ in(16) )[0:16]
```

The 102-byte preimage is exactly **two** SHA-256 blocks:

| block | content                                            | variable? |
|-------|----------------------------------------------------|-----------|
| 0     | `pub_seed(16) ‖ 0^48`                               | no — global constant `S = Compress(IV, block0)` |
| 1     | `addr(22) ‖ in(16) ‖ 0x80 ‖ 0^17 ‖ len_be(816)`    | only `addr` and `in` |

`S` depends only on `pub_seed`, so it is constant for the whole proof (it equals
PQClean's precomputed `state_seeded`). Therefore one `thash`-F is **one variable
compression** `Compress(S, block1)` whose truncated output `[0:16]` is the chain
step result — that is exactly what we fold.

## The bus (minimal-slice binding)

Per `thash`-F call the shared witness carries **three** field elements:

| slot   | width   | meaning                                       |
|--------|---------|-----------------------------------------------|
| `addr` | 176-bit | big-endian value of the 22-byte address       |
| `in`   | 128-bit | big-endian value of the 16-byte chain input   |
| `out`  | 128-bit | big-endian value of the 16-byte chain output  |

### `C_step` — `thash_f_step` (the folded instance)

1. Pins `h_in = S` and the 26 pad bytes to **constants**.
2. Allocates only `addr‖in` (38 bytes) as block witness.
3. Runs **one** `sha256_compression_function`.
4. Binds `addr`, `in`, and the output `[0:16]` to the bus slot.

### `C_core` — `thash_f_core_link` (the glue)

Performs **no** compression. It:

1. binds the bus `addr` to the compile-time **topology constant** (layer / tree /
   chain / hash-position address);
2. binds the bus `in` to the **upstream wire** (previous chain value / signature);
3. returns the bus `out` as fresh downstream bits.

### Why this is sound

- `S` is pinned in the step ⇒ the prover cannot decouple the output from the real
  seeded state.
- `addr` and `in` are bound on **both** sides ⇒ the folded compression operates on
  exactly the bytes `C_core` expects.
- `out` flows from the step's real compression and is bound to the bus ⇒ the
  downstream wire equals the genuine `thash` output.

Together these close the BUG-1 class for the offloaded compression. The four
`rejects_*` tests in `thash_link.rs` exercise each binding.

## How the SatCheckCS tests model the fold

In the real fold, `C_step` (many folded instances of one shape) and `C_core` (one
instance) communicate only through the shared commitment `comm_W_shared`. The
`offload_*` tests build both relations in a single `SatCheckCS` over the *same*
shared `addr/in/out` columns: satisfiability there ⇔ "there exist shared values
making both relations hold", which is exactly the NeutronNova joint check. The
`steps_are_independent_instances_sharing_the_bus` test additionally synthesizes
each step in its **own** constraint system to model the per-instance decomposition.

What these tests do **not** yet cover is the `spartan2` commitment/fold protocol
plumbing itself (separate commitments, `fold.rs`); that is the next increment.

## Public API (`sphincs_circuit::thash_link`)

| item | role |
|------|------|
| `seeded_state(pub_seed)` | the constant `S` (native) |
| `thash_f_block / thash_f_full_digest / thash_f_out` | native references |
| `thash_f_chain_bus_values(...)` | native WOTS chain → per-step `(addr,in,out)` + final |
| `ThashFBusValue` | one bus entry's native values |
| `alloc_thash_f_slot / alloc_thash_f_bus` | allocate shared columns |
| `thash_f_step(...)` | folded `C_step` body |
| `thash_f_core_link(...)` | `C_core` glue for one call |
| `gen_chain_linked(...)` | trace-linked replacement for `wots::gen_chain` |

## Roadmap to fully shrink `C_core`

1. **Wire WOTS in-core (`verify.rs`).** Swap `gen_chain` → `gen_chain_linked` in
   the hypertree WOTS path, threading a bus segment per chain. `C_core` then holds
   only WOTS glue for ~3,600 chain steps instead of ~7M+ SHA constraints.
2. **Prover fold (`sphincs-prover`).** Build the bus values from the PQClean trace
   (each `thash`-F's second compression is one trace row with `h_in == S`), emit a
   `thash_f_step` `C_step` per step, and fold via `spartan2` with the bus columns
   concatenated into `comm_W_shared` next to the existing link digests.
3. **Other families.** Generalize the bus to multi-block `thash`es:
   - FORS leaf `F` and Merkle node `H` (`inblocks = 1` / `2` → 2 compressions),
   - FORS root and WOTS-pk compression (`inblocks = 14` / `35` → 5 / 11
     compressions: share the chain of intermediate states, keep only the first
     constant `S` boundary fixed),
   - hypertree Merkle layers (same `H` as above).
   The `in`/`out` slot widths stay 128-bit; multi-block calls add intermediate
   state-boundary slots (reuse `shared_link`'s `8×u32` digest slots for those).
