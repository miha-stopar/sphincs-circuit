# Variable public `mlen` — design notes (Phase 2c+)

**Status:** step C landed (short/long mux); fixed `circuit_mlen` per instance still required for preimage sizes. Steps D–E remain.

**Related:** [VERIFY_CORE.md](VERIFY_CORE.md) · [FOLDING.md](FOLDING.md) §4.2 · [HACKMD_NEUTRONNOVA_PLAN.md](HACKMD_NEUTRONNOVA_PLAN.md) §Phase 2 `mlen` table

---

## Goal

One **universal** `FoldVerifyCoreCircuit` where the Spartan public scalar `mlen` is chosen at **prove time** (not baked into the circuit struct). The verifier checks `(PK, M_padded, mlen)`; the prover supplies `σ` and trace witness matching that length.

Today:

- `FoldVerifyCoreCircuit::mlen` is a **synthesis-time constant** — SHA preimage length and compression topology are fixed when the circuit is built.
- Public `mlen` is **constrained to equal** that constant via [`enforce_public_matches_statement`](../crates/sphincs-circuit/src/verify_public_io.rs).

---

## PQClean `hash_message` branches

From `third_party/.../hash_sha2.c` (mirrored in [`hash_message_seed_path`](../crates/sphincs-circuit/src/hash_msg.rs)):

| Condition | Path | Behavior |
|-----------|------|----------|
| `48 + mlen < 64` | `ShortFinalize` | One `shaX_inc_finalize` on `R ‖ PK ‖ M` |
| else | `LongBlockThenFinalize` | `shaX_inc_blocks` on padded 64 B buffer, then `shaX_inc_finalize` on `M` tail |

Constants (128s): `HASH_MESSAGE_PREFIX_BYTES = 48`, `HASH_MESSAGE_INBUF_BYTES = 64`.

**Boundary:** `mlen = 15` → short; `mlen = 16` → long (first block consumes all 16 message bytes).

Helpers:

```rust
hash_message_seed_path(mlen)
hash_message_first_block_message_bytes(mlen)
hash_message_tail_message_bytes(mlen)
hash_message_compression_budget(mlen)  // rough: 2 + ⌈mlen/64⌉ — see FOLDING.md
```

**Tests:**

```bash
cargo test -p sphincs-circuit hash_message_seed_path
```

---

## Implementation sketch

### 1. In-circuit `mlen` from public IO

- Read `input.mlen` as `UInt32` (already inputized).
- Range-check `mlen ≤ MESSAGE_MAX_BYTES` — [`enforce_public_mlen_in_range`](../crates/sphincs-circuit/src/verify_public_io.rs) (wired in `FoldVerifyCoreCircuit` when `public_io`).
- Drop synthesis-time `enforce_public_matches_statement` equality to a **constant** `mlen`; instead tie gadget behavior to **public** `mlen`.

### 2. Variable-length SHA preimage

Options (pick one for v1 universal circuit):

| Approach | Pros | Cons |
|----------|------|------|
| **Mux short vs long path** | Matches PQClean exactly | Two SHA topologies + selector constraints |
| **Always long path** | Single topology | Must prove short messages still match PQClean when tail is empty |
| **Incremental SHA chain** | Aligns with folded `C_step` | Largest engineering effort; links core compressions to trace |

Current bellpepper [`sha256`](../crates/sphincs-circuit/src/hash_msg.rs) gadget takes a **fixed** `preimage_bits` vector at synthesis time — variable `mlen` requires either:

- building max-length preimage with inactive message bits forced to zero **and** correct SHA padding for each `mlen` (padding length depends on `mlen`), or
- switching to per-compression gadgets shared with `C_step`.

### 3. Trace alignment

Folded step count for `hash_message` grows with `mlen` ([FOLDING.md](FOLDING.md)):

```text
hash_message compressions ≈ 2 + ⌈mlen / 64⌉   (plus MGF1 — mostly fixed for 128s)
```

The universal circuit must:

1. Select the correct compression rows from the trace (or prove dummy rows are unused).
2. Equate `C_core` in-gadget SHA outputs to folded accumulator at link boundaries (future trace↔core linking).

### 4. Public message tail

Already enforced: [`enforce_public_inactive_chunks_zero`](../crates/sphincs-circuit/src/verify_public_io.rs) zeros full 32-byte chunks after `mlen`. Partial final chunk handling follows v1 padded-message policy in [DECISIONS.md](DECISIONS.md).

---

## Suggested rollout

| Step | Deliverable | Test |
|------|-------------|------|
| **A** (done) | `hash_message_seed_path` + helpers | `hash_message_seed_path_boundaries` |
| **B** (done) | In-circuit `mlen` range check on public scalar | `enforce_public_mlen_in_range` |
| **C** (done) | Mux short/long native SHA paths in R1CS (no trace yet) | `hash_message_variable_mlen_matches_native` |
| **D** | Wire variable path through `synthesize_verify_core_public` | `valid_signature_satisfies_core_variable_mlen` |
| **E** | Trace compression count selector | integration with `fold_verify_core_*` |

Do **not** block Phase 2b/full-core KATs on step E — fixed-`mlen` instances remain valid deployment mode.

---

## What works today without variable `mlen`

- Public `(mlen, PK, M)` with **fixed** `mlen` per proof instance: [`with_public_io()`](../crates/sphincs-prover/src/verify_core.rs)
- SHA preimage from public columns: [`synthesize_hash_message_parsed_public`](../crates/sphincs-circuit/src/hash_msg.rs)
- Full verify path: [`synthesize_verify_core_public`](../crates/sphincs-circuit/src/verify.rs)
- NeutronNova smoke: `fold_verify_core_hash_message_public_io` (CI), `fold_verify_core_full_public_io_*` (`#[ignore]`)

See [VERIFY_CORE_TESTS.md](VERIFY_CORE_TESTS.md) for commands.
