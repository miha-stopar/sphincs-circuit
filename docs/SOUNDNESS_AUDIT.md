# Soundness audit — `hash_message` trace linking & verify core

Audit of the trace-linked `hash_message` path and the public-IO / variable-`mlen` statement
checks in `FoldVerifyCoreCircuit`. One **critical** soundness bug was found and fixed; the
remaining items are documented with their current trust assumptions.

**Scope:** `crates/sphincs-circuit/src/hash_message_trace.rs`,
`crates/sphincs-circuit/src/sha256_compress.rs`,
`crates/sphincs-circuit/src/verify.rs`,
`crates/sphincs-circuit/src/verify_public_io.rs`,
`crates/sphincs-prover/src/verify_core.rs`.

---

## BUG-1 (critical, FIXED): trace-linked seed-SHA was not bound to `(R, PK, M)`

### Symptom

`synthesize_hash_message_with_trace` computed the seed hash
`SHA256(R ‖ PK ‖ M[0..mlen])` by feeding the SHA-256 compression gadget the **prover-supplied
trace witnesses** (`StepInput { h_in, block, h_out }`) via
`synthesize_compression_trace_row_for_fold` /
`synthesize_compression_chain_for_fold_with_shared`.

In those gadgets:

- `h_in` was `words_from_state_bytes(&row.h_in)` — a **free witness** (never pinned to the
  SHA-256 IV).
- `block` was `block_to_allocated_bits(&row.block)` — **free witness bits** (never pinned to
  `R ‖ PK ‖ M`).
- Only `h_out == Compress(h_in, block)` and the inter-row chaining were enforced.

### Impact

The seed compression's input block (which is supposed to contain the message) was entirely
unconstrained. A malicious prover could:

1. Take a genuine signature for some message `M'` under `PK`.
2. Set the trace blocks / `hm_mgf` to the real values for `M'`.
3. Set the **public** message columns to an unrelated `M`.

The hypertree still verifies against `PK.root` (the only value bound to a trusted constant),
so the proof is accepted while the public statement claims `M`. This **breaks the verify
relation for the message** — i.e. message forgery in the public-IO statement. The non-public
trace path had the analogous gap (the circuit claimed to verify over `self.message` but hashed
arbitrary trace blocks).

Existing tests did not catch it because honest provers always supply consistent trace blocks;
the bug is a *soundness* (malicious-prover) gap, not a *completeness* one.

### Fix

`hash_message_trace.rs` now reconstructs the seed preimage **from the statement** and binds the
compressions to constants:

- `hash_message_seed_blocks(r, pk, message, mlen)` rebuilds the standard SHA-256 padded 64-byte
  blocks of `R ‖ PK ‖ M[0..mlen]`. (PQClean's incremental absorb produces exactly these blocks,
  so the chunk count matches the trace seed-row count one-for-one.)
- `seed_hash_words_bound(...)`:
  - pins the first compression's `h_in` to the SHA-256 IV (`SHA256_IV` constant);
  - feeds each compression a **constant** block derived from `(R, PK, M)` (not trace witnesses);
  - rejects (`SynthesisError::Unsatisfiable`) any trace whose seed-row count disagrees with the
    statement-derived count;
  - optionally links internal boundaries to folded `C_step` instances via `shared` — now an
    *optimization*, since soundness no longer depends on it.

`M` is bound to the **public** columns transitively: `FoldVerifyCoreCircuit` still runs
`enforce_public_matches_statement` (fixed `mlen`) or `enforce_public_matches_pk_message`
(variable `mlen`), tying the public `PK` / `M` columns to the same `self.pk` / `self.message`
constants used to rebuild the blocks.

The seed compressions now constant-fold for a fixed statement (same as the non-trace
`sha256(...)` path), so a wrong message is rejected at synthesis time (constant
`mgf_bits != hm_mgf`) — strictly stronger than an unsatisfied constraint.

### Regression tests

- `hash_message_trace::tests::hash_message_trace_rejects_message_mismatch` — wrong message,
  honest `hm_mgf` ⇒ rejected.
- `verify::tests::verify_core_trace_rejects_message_mismatch` (`#[ignore]`, release) — same at
  full-core level.

---

## FINDING-2 (documented): non-public `hash_message` uses free-witness preimage

`hash_message_bits` (the fixed-`mlen`, non-public path) allocates the seed preimage with
`alloc_input_bits` (`thash.rs`), which produces **free witness bits** hinted to `R ‖ PK ‖ M`
but not constrained to them.

- **Production path is sound:** when `public_io` is enabled, `synthesize_hash_message_parsed_public`
  → `hash_message_bits_from_public_muxed` wires the preimage `PK` / `M` bits from the **public
  columns** (`public_pk_sha_bits` / `public_message_sha_bits`, each enforcing `word == column`).
  `R` is part of the (private) signature.
- **Non-public path semantics:** without public IO there is no on-chain statement binding `M`,
  so the relation is "prover knows *some* `(M, sig)` valid under `PK`". This is acceptable for
  the smoke/test configurations that use it, but it is **not** a fixed-`M` statement.

**Recommendation (future hardening):** if the non-public path is ever used to prove a fixed
public `M`, bind the preimage bits to constants the way `seed_hash_words_bound` now does, or
require `public_io`.

---

## FINDING-3 (documented): variable public `mlen` is a per-statement specialization

With `with_variable_public_mlen`:

- `enforce_public_mlen_in_range` constrains `0 ≤ mlen ≤ MESSAGE_MAX_BYTES`.
- `enforce_public_matches_pk_message` ties the **full** 4096-byte message buffer and `PK` to the
  public columns (so every byte, including any partial-final-chunk tail, is bound).
- `enforce_public_inactive_chunks_zero_variable` forces fully-inactive 32-byte chunks to zero
  using the **public** `mlen` scalar.

What is **not** yet enforced: the seed-block padding still encodes the **baked** `self.mlen`
(the circuit is specialized per `mlen` at setup). There is no in-circuit constraint forcing
`public mlen == baked mlen`. This is sound under the "one circuit per statement, verifier trusts
setup" model, but a single **universal** circuit serving many `mlen` values (one setup) requires
a muxed / length-driven preimage. Tracked in [VARIABLE_MLEN.md](VARIABLE_MLEN.md).

---

## BUG-5 (critical completeness, FIXED): verify-core hypertree `wots_addr` missing layer

### Symptom

The full verify core (`synthesize_verify_core` and all variants) did **not** reproduce
`PK.root` for a genuine KAT signature. The first failing constraint was
`verify_tail/pk_root/bit_eq_1/enforce equal to zero` (the final `root == PK.root` check), at
constraint index ≈ 49.29M.

### Root cause

In the hypertree loop, `wots_addr` was rebuilt each iteration with `set_type` / `set_tree_addr` /
`set_keypair_addr` but **without `set_layer_addr(layer)`** (left at layer 0). PQClean derives
`wots_addr` via `copy_subtree_addr(wots_addr, tree_addr)`, so it inherits the current `layer`.
For `layer == 0` the circuit was coincidentally correct (so FORS and the bottom hypertree layer
passed), but layers `1..SPX_D` hashed WOTS with the wrong ADRS, producing a wrong leaf → wrong
subtree root → wrong final root. `wots_pk_addr` was unaffected because it is derived from
`tree_addr` (which does set the layer).

### Why it was never caught

All `valid_signature_satisfies_core*` tests were `#[ignore]` and built the circuit in
`bellpepper_core::test_cs::TestConstraintSystem`, which needs tens of GB for the full core and
swap-dies before completing — so the bug sat latent. The component gadget tests
(`wots`, `merkle`, `hypertree`, `fors`) pass because they construct addresses manually, and they
happened to exercise layer 0 / direct addresses. The NeutronNova `*_full_*_setup` tests only
check R1CS **shape** (`setup` + equalize), not satisfiability against a real witness.

### Fix

Add `wots_addr = set_layer_addr(&wots_addr, layer as u32);` in the hypertree loop
(`crates/sphincs-circuit/src/verify.rs`). After the fix the full core is satisfiable for KAT
signatures:

- `valid_signature_satisfies_core_public` ✅ (~32s)
- `valid_signature_satisfies_core_trace` ✅ (~35s, also exercises BUG-1's bound seed)

### Tooling that exposed it: `SatCheckCS`

`crates/sphincs-circuit/src/satcheck.rs` is a memory-light `ConstraintSystem` that evaluates each
`A · B = C` against the running witness and discards the linear combinations, so peak memory is
`O(num_variables)` instead of `O(num_constraints × lc_size)`. It turns the full-core
satisfiability check from a multi-hour swap-death into a ~30s run and reports the **index and
namespace path** of the first failing constraint (how this bug was localized). The
`valid_signature_satisfies_core*` tests now use it.

---

## FINDING-4 (documented, not a bug): MGF1 folded rows are metadata only

`trace.mgf1_rows` is intentionally unused by the core. The core derives the MGF1 digest one-shot
(`mgf1_digest_bits`) over `R ‖ pk_seed ‖ seed_hash` and enforces `mgf_bits == hm_mgf`; the
folded MGF1 `C_step` instances (selected by the prover from `mgf1_rows`) are redundant proof
work, not a correctness dependency. The one-shot MGF1 starts from the SHA-256 IV inside the
bellpepper `sha256` gadget, so it is self-contained and sound.

`thash` / FORS / hypertree SHA-256 are still computed in-gadget (not trace-linked); that is a
performance item, not a soundness gap.

---

## Trusted bindings after the fix (verify relation)

| Quantity | Bound to | How |
|----------|----------|-----|
| `PK.root` | constant from `pk[SPX_N..]` | hypertree `root == pk_root` |
| seed hash `SHA256(R‖PK‖M)` | `(R, PK, M)` constants + IV | `seed_hash_words_bound` |
| `hm_mgf` | MGF1(seed) | `mgf_bits == hm_mgf` |
| public `PK` / `M` columns | `self.pk` / `self.message` | `enforce_public_matches_statement` / `_pk_message` |
| public `mlen` | range only (variable mode) | `enforce_public_mlen_in_range` + tail-zero |
| folded seed `C_step` h_out | core seed boundary | `enforce_words_eq_shared` (optimization) |
