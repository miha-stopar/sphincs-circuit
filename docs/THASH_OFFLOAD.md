# `thash` offload — moving SPHINCS+ compressions out of `C_core` into folded steps

This document describes the architecture that lets NeutronNova keep only *glue*
in `C_core` and prove each SPHINCS+ SHA-256 compression as a tiny folded `C_step`
instance, instead of synthesizing the ~49M-constraint monolith in one relation.

It corresponds to **MASTER_PLAN items 6 & 7** ("don't put millions of SHA
constraints in one `C_core`" / "trace-link FORS / WOTS / hypertree too").

## TL;DR status

- **Done — mechanism:** the *sound, self-contained mechanism* for the WOTS+
  chain `F` function — the single biggest family in the core (~75%). See
  `crates/sphincs-circuit/src/thash_link.rs`.
  - Measured: a full 15-step WOTS chain costs **349,058** constraints in-core but
    only **2,093** glue constraints once offloaded — a **~167× core reduction**
    for that family (test `core_link_shrinks_core_vs_in_core`).
  - Soundness is proven by four tamper tests (input / addr / seeded-state / out)
    plus a joint-relation satisfiability test and a fold-decomposition smoke test.
- **Done — verify-core wiring:** `synthesize_verify_core_wots_linked` (in
  `verify.rs`) threads a per-layer WOTS bus through all 7 hypertree layers using
  `gen_chain_linked`; FORS, the leaf `thash`, and the Merkle walk stay in-core.
  Validated on a real PQClean KAT (test
  `valid_signature_satisfies_core_wots_linked`).
- **Done — prover fold:** `thash_fold.rs` (in `sphincs-prover`) folds the WOTS+
  chain `thash`-F compressions as real NeutronNova `C_step` instances bound to a
  WOTS chain `C_core` over the shared `addr/in/out` bus. Proves **and verifies**
  end-to-end through `spartan2` (test `fold_thash_f_chain_prove_and_verify`).
  - The bus columns hold wide field elements, so the fold uses the general
    commitment path (`fold_and_prove_general`, `is_small = false`) rather than the
    small-scalar path the `u32`-limbed digest bus uses — see the note below.
- **Next increment:** generalize the bus/step to the other `thash` families (FORS
  leaf/node, Merkle node, WOTS-pk compression, hypertree).

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

The `spartan2` commitment/fold protocol plumbing itself is now covered by
`fold_thash_f_chain_prove_and_verify` (`sphincs-prover`), which runs the real
NeutronNova `setup → prove → verify` over `N` folded `thash_f_step` instances + a
WOTS chain core sharing one `addr/in/out` bus.

### `is_small` and wide bus columns

NeutronNova's commitment has a fast *small-scalar* path (`is_small = true`) valid
only when **every** committed witness element fits a machine word — the case for
the existing `8×u32` digest bus (`bound.rs`). The `thash`-F bus packs each
`addr`/`in`/`out` as one wide field element (176-/128-bit), so it must use the
**general** commitment path (`is_small = false`, via `fold_and_prove_general`).
Using the small path with wide columns yields a commitment that disagrees with the
witness and fails verification with `InvalidPCS { "… First equation failed" }`.
(A future optimization could `u32`-limb the bus to re-enable the small path.)

## Public API (`sphincs_circuit::thash_link`)

| item | role |
|------|------|
| `seeded_state(pub_seed)` | the constant `S` (native) |
| `thash_f_block / thash_f_full_digest / thash_f_out` | native references |
| `thash_f_chain_bus_values(...)` | native WOTS chain → per-step `(addr,in,out)` + final |
| `ThashFBusValue` | one bus entry's native values |
| `alloc_thash_f_slot / alloc_thash_f_bus` | allocate shared columns |
| `thash_f_step(...)` | folded `C_step` body (fixed slot) |
| `thash_f_step_values(...)` | compute step `addr/in/out` bits without binding (for muxed fold steps) |
| `thash_f_core_link(...)` | `C_core` glue for one call |
| `gen_chain_linked(...)` | trace-linked replacement for `wots::gen_chain` |

WOTS layer / verify-core helpers:

| item | crate · role |
|------|--------------|
| `wots::wots_pk_from_sig_bits_linked` / `_root_bits_linked` | `sphincs-circuit` · WOTS pk recovery over a bus |
| `wots::wots_pk_bus_values` / `wots_step_count` | `sphincs-circuit` · native bus builder / bus sizing |
| `verify::synthesize_verify_core_wots_linked` | `sphincs-circuit` · full verify core with WOTS offloaded |
| `thash_fold::{FoldThashFStepCircuit, FoldThashFCoreCircuit, thash_f_chain_fold}` | `sphincs-prover` · NeutronNova fold of a WOTS chain |
| `fold::fold_and_prove_general` | `sphincs-prover` · prove with the general (wide-column) commitment path |

## Roadmap to fully shrink `C_core`

1. ~~**Wire WOTS in-core (`verify.rs`).**~~ **Done** — `gen_chain_linked` threaded
   through all 7 hypertree layers via `synthesize_verify_core_wots_linked`; the
   core holds only WOTS glue instead of the chain SHA constraints.
2. ~~**Prover fold (`sphincs-prover`).**~~ **Done (chain-level)** — `thash_fold.rs`
   folds a WOTS chain's `thash`-F steps and proves+verifies through `spartan2`.
   Remaining: drive the bus from a full PQClean verify trace and fold all 7 layers'
   steps + the full `synthesize_verify_core_wots_linked` core in one proof (extend
   `comm_W_shared` to carry the `link_digests` *and* the `thash`-F bus together).
3. **Other families.** Generalize the bus to multi-block `thash`es:
   - FORS leaf `F` and Merkle node `H` (`inblocks = 1` / `2` → 2 compressions),
   - FORS root and WOTS-pk compression (`inblocks = 14` / `35` → 5 / 11
     compressions: share the chain of intermediate states, keep only the first
     constant `S` boundary fixed),
   - hypertree Merkle layers (same `H` as above).
   The `in`/`out` slot widths stay 128-bit; multi-block calls add intermediate
   state-boundary slots (reuse `shared_link`'s `8×u32` digest slots for those).
