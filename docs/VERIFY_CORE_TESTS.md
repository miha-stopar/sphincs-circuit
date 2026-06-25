# Verify-core test guide

How to run tests for **Phase 2** (`FoldVerifyCoreCircuit` / `C_core`) and what each test checks.

**Design context:** [VERIFY_CORE.md](VERIFY_CORE.md) · **Witness layout:** [SHARED_WITNESS_DEBUG.md](SHARED_WITNESS_DEBUG.md)

---

## Quick start (CI-sized, ~30s total)

Run these after touching verify-core or public IO:

```bash
# --- Unit tests (no NeutronNova, no pqclean feature on sphincs-circuit) ---

# Public IO pack / inputize / enforce (6 tests)
cargo test -p sphincs-circuit verify_public_io

# hash_message + public preimage wiring
cargo test -p sphincs-circuit hash_message_public
cargo test -p sphincs-circuit parsed_output_matches_native
cargo test -p sphincs-circuit wrong_hm_mgf

# circuit-spec layout constant
cargo test -p circuit-spec verify_public_scalar_layout

# --- NeutronNova integration (needs --features pqclean) ---

# Phase 2a: hash_message only in C_core (~14s debug)
cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message

# Phase 2c: public IO on HashMessage path (~14s debug)
cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message_public_io

# Witness builder smoke
cargo test -p sphincs-prover --features pqclean fold_verify_core_from_pqclean_builds
```

**One-liner (copy-paste):**

```bash
cargo test -p sphincs-circuit verify_public_io && \
cargo test -p sphincs-circuit hash_message_public && \
cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message && \
cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message_public_io
```

---

## Test tiers

| Tier | When to run | Typical time | `--release`? | `--ignored`? |
|------|-------------|--------------|--------------|--------------|
| **A — unit** | Every verify-core change | seconds | no | no |
| **B — NeutronNova smoke** | After adapter / witness layout changes | ~15–30s debug | optional | no |
| **C — full core local R1CS** | Before large refactors to FORS/hypertree | minutes | **yes** | **yes** |
| **D — full core NeutronNova** | Before merging big `C_core` changes | ~7 min+ | **yes** | **yes** |

---

## Tier A — `sphincs-circuit` unit tests

### Public IO (`verify_public_io.rs`)

```bash
cargo test -p sphincs-circuit verify_public_io
```

| Test | What it checks |
|------|----------------|
| `pack_len_matches_layout_constant` | `pack_verify_public` length == `VERIFY_PUBLIC_NUM_SCALARS` (1033) |
| `inputize_and_enforce_satisfies_for_honest_statement` | Honest `(mlen, PK, M)` public tuple satisfies R1CS after `inputize` |
| `enforce_public_mlen_in_range_accepts_max_and_honest` | Honest `mlen` and `mlen = MESSAGE_MAX_BYTES` pass |
| `enforce_public_mlen_in_range_rejects_too_large` | `mlen > MESSAGE_MAX_BYTES` fails |
| `enforce_public_inactive_chunks_zero_accepts_honest_padding` | Zero tail on public message chunks after `mlen` passes |
| `enforce_public_inactive_chunks_zero_rejects_nonzero_tail_chunk` | Nonzero byte in an inactive 32-byte chunk fails |
| `public_pk_sha_bits_matches_native` | `public_pk_sha_bits` ties public PK words to assignment bytes |

### `hash_message` (`hash_msg.rs`)

```bash
cargo test -p sphincs-circuit parsed_output_matches_native
cargo test -p sphincs-circuit hash_message_public
cargo test -p sphincs-circuit wrong_hm_mgf
```

| Test | What it checks |
|------|----------------|
| `parsed_output_matches_native` | `synthesize_hash_message_parsed` + `parse_mgf_output` agree with PQClean |
| `hash_message_public_preimage_matches_native` | SHA preimage `R‖PK‖M` built from **public** columns, not witness-only bytes |
| `hash_message_seed_path_boundaries` | PQClean short vs long branch at `mlen=15/16` |
| `hash_message_variable_mlen_matches_native` | Short/long muxed public `hash_message` at mlen 5 / 16 / 100 |
| `hash_message_seed_paths_match_native` | Native long vs short seed hash agrees with single-shot SHA |
| `native_matches_pqclean_short_message` | Native `hash_message` matches PQClean reference |
| `wrong_hm_mgf_unsatisfies` (in `hash_msg`) | Corrupt MGF1 witness breaks constraints |

### Verify core gadget (`verify.rs`)

```bash
cargo test -p sphincs-circuit wrong_hm_mgf_unsatisfies_parsed_hash_message
cargo test -p sphincs-circuit message_padding
```

| Test | What it checks |
|------|----------------|
| `wrong_hm_mgf_unsatisfies_parsed_hash_message` | Corrupt `hm_mgf` fails `mgf_bits == hm_mgf` on parsed path |
| `message_padding_rejects_nonzero_tail_at_synthesis` | `enforce_message_padding` rejects nonzero inactive suffix at synthesis |
| `message_padding_mgf_padded_buffer_satisfies` | Honest zero-tail padded buffer + hash_message satisfies |

### `circuit-spec`

```bash
cargo test -p circuit-spec verify_public_scalar_layout
```

| Test | What it checks |
|------|----------------|
| `verify_public_scalar_layout` | `1 + 8 + 1024 == VERIFY_PUBLIC_NUM_SCALARS` |

---

## Tier B — NeutronNova smoke (`sphincs-prover`, `pqclean` feature)

Requires `cargo test -p sphincs-prover --features pqclean`.

### Phase 2a — `fold_verify_core_hash_message.rs`

```bash
cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message
```

| Test | What it checks |
|------|----------------|
| `fold_verify_core_hash_message_smoke` | Bound folded steps + `C_core` running **only** `hash_message` → NeutronNova prove + verify |
| `fold_verify_core_hash_message_plain_steps` | Same core with **plain** steps (no shared link digests) — isolates core size |

**Env:** `FOLD_VERIFY_CORE_STEPS` — power-of-two step count (default `4`).

### Phase 2c — `fold_verify_core_hash_message_public_io.rs`

```bash
cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message_public_io
```

| Test | What it checks |
|------|----------------|
| `fold_verify_core_hash_message_public_io_smoke` | Phase 2a + **`with_public_io()`**: 1033 public scalars, SHA preimage from public `PK`/`M`, end-to-end prove/verify |

### Witness builder (`verify_witness.rs`)

```bash
cargo test -p sphincs-prover --features pqclean fold_verify_core_from_pqclean_builds
```

| Test | What it checks |
|------|----------------|
| `fold_verify_core_from_pqclean_builds_full_circuit` | PQClean KAT → `fold_verify_core_from_pqclean` builds consistent `FoldVerifyCoreCircuit::full` |

---

## Tier C — full core local R1CS (`#[ignore]`)

These synthesize the **entire** M2 verify gadget in a `TestConstraintSystem` (no NeutronNova).

```bash
# Witness-only hash_message path (~minutes in release)
cargo test -p sphincs-circuit valid_signature_satisfies_core --release -- --ignored --nocapture

# Public-wired hash_message path (Phase 2c Full)
cargo test -p sphincs-circuit valid_signature_satisfies_core_public --release -- --ignored --nocapture
```

| Test | What it checks |
|------|----------------|
| `valid_signature_satisfies_core` | Full `synthesize_verify_core` on PQClean KAT signature |
| `valid_signature_satisfies_core_public` | Full `synthesize_verify_core_public` — FORS + hypertree + root with public `PK`/`M` in SHA preimage |

### WOTS root-bits path (optional)

```bash
cargo test -p sphincs-circuit root_bits_path_matches_byte_message --release -- --ignored --nocapture
```

| Test | What it checks |
|------|----------------|
| `root_bits_path_matches_byte_message` | `wots_pk_from_sig_root_bits` chain matches byte-message path (~2 min debug) |

---

## Tier D — full core NeutronNova (`#[ignore]`, release)

File: `crates/sphincs-prover/tests/fold_verify_core_full.rs`

### Minimum recommended before merging large `C_core` changes

```bash
cargo test -p sphincs-prover --features pqclean --release \
  --test fold_verify_core_full fold_verify_core_full_setup -- --ignored --nocapture
```

~7 minutes. Runs `NeutronNovaZkSNARK::setup` only (R1CS shape + `equalize`), no witness generation.

### Full core + public IO setup

```bash
cargo test -p sphincs-prover --features pqclean --release \
  --test fold_verify_core_full fold_verify_core_full_public_io_setup -- --ignored --nocapture

cargo test -p sphincs-prover --features pqclean --release \
  --test fold_verify_core_full fold_verify_core_full_public_io_smoke -- --ignored --nocapture
```

`fold_verify_core_from_pqclean(...).with_public_io()` — full gadget + 1033 public scalars.

### Full prove/verify suite (very slow)

```bash
cargo test -p sphincs-prover --features pqclean --release \
  --test fold_verify_core_full -- --ignored --nocapture
```

| Test | NeutronNova stage | What it checks |
|------|-------------------|----------------|
| `fold_verify_core_full_setup` | `setup` | R1CS compiles + equalizes with bound steps |
| `fold_verify_core_full_prep_prove` | `prep_prove` | Witness generation for all instances |
| `fold_verify_core_full_smoke` | prove + verify | End-to-end with bound steps + shared links |
| `fold_verify_core_full_plain_steps` | prove + verify | Full core + plain steps (no shared) |
| `fold_verify_core_full_public_io_setup` | `setup` | Full core + `public_io` shape |
| `fold_verify_core_full_public_io_smoke` | prove + verify | Full core + `public_io` end-to-end |

**Env:** `FOLD_VERIFY_CORE_STEPS` (default `4`, must be power of two ≥ 2).

---

## What is *not* covered yet

- **Variable public `mlen`** in one universal circuit (muxed SHA preimage).
- **Full trace scale** (~2k compressions) — tests use 4-step prefixes.
- **Trace ↔ core SHA linking** inside `C_core` beyond shared link digests at chain boundaries.
- Routine CI does **not** run Tier C/D — mark `#[ignore]` and run manually before big merges.

---

## Troubleshooting

| Symptom | Likely cause | What to run |
|---------|--------------|-------------|
| `equalize` / witness layout failure | Shared vs precommitted column mismatch | Tier B smoke, then `SHARED_WITNESS_DEBUG.md` |
| Public IO unsat with honest KAT | `mlen` mismatch or nonzero message tail | `verify_public_io`, `enforce_public_inactive` |
| Full core setup OOM / hours in debug | Gadget size | Use `--release --ignored` only |
| `AssignmentMissing` on padding | Nonzero `message[mlen..]` at synthesis | `enforce_message_padding` unit test |
