# `FoldVerifyCoreCircuit` — real SPHINCS+ glue in NeutronNova `C_core`

This document describes **Phase 2** of porting the M2 verify gadgets (`sphincs-circuit`) into the NeutronNova prover (`sphincs-prover`). It supersedes the placeholder [`FoldCoreCircuit`](../crates/sphincs-prover/src/fold.rs) for anything that needs real SPHINCS+ structure.

**Related:** [CIRCUIT.md](CIRCUIT.md) (gadget decomposition), [FOLDING.md](FOLDING.md) (step vs core), [SHARED_WITNESS_DEBUG.md](SHARED_WITNESS_DEBUG.md) (witness layout), [TRACE.md](TRACE.md) (compression linking).

### Phase 2c status (in progress)

- **Done:** Removed separate `hm_expected` from `FoldVerifyCoreCircuit` / `synthesize_verify_core`. Parsed fields come from witness `mgf_bits` enforced against `hm_mgf` ([`synthesize_hash_message_parsed`](../crates/sphincs-circuit/src/hash_msg.rs)).
- **Done (step 1):** Public Spartan IO for fixed `(PK, M, mlen)` per circuit — [`with_public_io`](../crates/sphincs-prover/src/verify_core.rs), encoding in [`verify_public_io.rs`](../crates/sphincs-circuit/src/verify_public_io.rs), test `fold_verify_core_hash_message_public_io`.
- **Done (step 1b):** `hash_message` SHA preimage wired from public `PK` / `M` columns when `public_io` — [`hash_message_bits_from_public`](../crates/sphincs-circuit/src/hash_msg.rs), [`synthesize_hash_message_parsed_public`](../crates/sphincs-circuit/src/hash_msg.rs).
- **Done (step 1c):** Full phase uses [`synthesize_verify_core_public`](../crates/sphincs-circuit/src/verify.rs) when `public_io` (same public preimage wiring through entire verify path).
- **Done (step 2):** WOTS topology from chained `root_bits` via [`witness_bytes_from_bits`](../crates/sphincs-circuit/src/thash.rs) — no `intermediate_roots` field on `FoldVerifyCoreCircuit`.
- **Done (variable `mlen` step B):** [`enforce_public_mlen_in_range`](../crates/sphincs-circuit/src/verify_public_io.rs) — public `mlen ≤ MESSAGE_MAX_BYTES` in R1CS.
- **Done (variable `mlen` step D):** [`public_message_bits_for_mlen`](../crates/sphincs-circuit/src/verify_public_io.rs) masks inactive message bytes from public `mlen`; full core test `valid_signature_satisfies_core_variable_mlen`.

---

## Public Spartan IO (Phase 2c step 1)

When [`FoldVerifyCoreCircuit::public_io`] is true, `public_values()` returns **1033** scalars
(`circuit_spec::VERIFY_PUBLIC_NUM_SCALARS`) encoding the statement from [DECISIONS.md](DECISIONS.md):

| Segment | Scalars | Encoding |
|---------|---------|----------|
| `mlen` | 1 | `Scalar::from(mlen)` |
| `pk` | 8 | `state_bytes_to_words` on 32-byte PK |
| `message` | 1024 | 128 × 32-byte chunks, 8 SHA-state words each |

Implementation: [`verify_public_io.rs`](../crates/sphincs-circuit/src/verify_public_io.rs). Each scalar is
`inputize`d in `precommitted()`. With `public_io` on Phase 2a, [`synthesize_hash_message_parsed_public`](../crates/sphincs-circuit/src/hash_msg.rs) wires the SHA preimage from public `PK` / `M` columns; [`enforce_public_matches_statement`](../crates/sphincs-circuit/src/verify_public_io.rs) and [`enforce_public_inactive_chunks_zero`](../crates/sphincs-circuit/src/verify_public_io.rs) check the full public tuple.

**Limitation:** `mlen` is still a **synthesis-time constant** for `hash_message_bits` SHA length; the
public scalar must equal that constant. One universal circuit accepting runtime `mlen` needs muxed
preimage (later step).

**Tests:** see [VERIFY_CORE_TESTS.md](VERIFY_CORE_TESTS.md) §Quick start and §Phase 2c.

```bash
cargo test -p sphincs-circuit verify_public_io
cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message_public_io
```

---

## Problem

NeutronNova always uses **two** R1CS relations in one proof:

| Circuit | Role |
|---------|------|
| **`C_step`** | One SHA-256 compression per folded instance (~2k–3k instances at full scale) |
| **`C_core`** | Everything else: SPHINCS+ dataflow + (eventually) trace digest linking |

M2 implemented the full PQClean verify pipeline in bellpepper as [`synthesize_verify_core`](../crates/sphincs-circuit/src/verify.rs). Phase 2 **wraps** that gadget inside [`FoldVerifyCoreCircuit`](../crates/sphincs-prover/src/verify_core.rs) so it can serve as `C_core` in `NeutronNovaZkSNARK::setup/prove/verify`.

---

## Architecture

```text
                    NeutronNova proof (one π)
┌─────────────────────────────────────────────────────────────────┐
│  C_step × N  (FoldStepBoundCircuit or FoldStepCircuit)          │
│    shared[0..24]  ←── link digests (8 words × num_links)        │
│    precommitted   ←── SHA compress gadget per instance          │
├─────────────────────────────────────────────────────────────────┤
│  C_core  (FoldVerifyCoreCircuit)                                │
│    shared[0..24]  ←── SAME link digest variables as steps       │
│    precommitted   ←── VerifyCorePhase::{HashMessage | Full}     │
└─────────────────────────────────────────────────────────────────┘
```

**SpartanCircuit phase mapping** (`FoldVerifyCoreCircuit`):

| Spartan2 hook | What runs |
|---------------|-----------|
| `shared()` | `alloc_digest_shared` for each `link_digests[k]` (24 field elems when `num_links=3`) |
| `precommitted()` | Phase gadget + `enforce_bytes_eq_shared` on links + dummy `inputize core_x` |
| `synthesize()` | Empty (all constraints in `precommitted`, like other fold circuits) |
| `public_values()` | `[0]` placeholder, or **1033** scalars when `public_io` — see §Public Spartan IO |

---

## Incremental phases (`VerifyCorePhase`)

Rollout is deliberately **staged** so NeutronNova integration can be debugged before the full multi-million-constraint core is exercised.

| Phase | Enum | R1CS in `precommitted()` | NeutronNova test | Status |
|-------|------|--------------------------|------------------|--------|
| **2a** | `HashMessage` | `enforce_message_padding` + `synthesize_hash_message` + shared link checks | `fold_verify_core_hash_message` | ✅ CI |
| **2b** | `Full` | `synthesize_verify_core` (entire PQClean verify path) + shared link checks | `fold_verify_core_full_*` (`#[ignore]`, release) | ✅ setup verified |
| **2c** | `public_io` on [`FoldVerifyCoreCircuit`] | Public `(mlen, PK, M)` via `inputize` (fixed `mlen` per instance) | `fold_verify_core_hash_message_public_io` | ✅ CI |
| **2c+** | Variable public `mlen` | Trace-linked seed + dynamic public tail; `with_variable_public_mlen` | See [VARIABLE_MLEN.md](VARIABLE_MLEN.md) | Partial |

See [HACKMD §Phase 2](HACKMD_NEUTRONNOVA_PLAN.md) for the public `mlen` table.

### Phase 2a — `HashMessage`

**Constructor:** `FoldVerifyCoreCircuit::hash_message(pk, message, mlen, r, hm_mgf, link_digests)`

- Hashes `R ‖ PK ‖ M[0..mlen]` and checks MGF1 output (`hm_mgf`).
- Does **not** run FORS / hypertree / root check.
- Used to validate `C_core` witness layout with a medium-sized gadget (padding fix landed here — see [SHARED_WITNESS_DEBUG §Core padding](SHARED_WITNESS_DEBUG.md)).

### Phase 2b — `Full`

**Constructor:** `FoldVerifyCoreCircuit::full(...)` or [`fold_verify_core_from_pqclean`](../crates/sphincs-prover/src/verify_witness.rs).

Calls [`synthesize_verify_core`](../crates/sphincs-circuit/src/verify.rs):

```text
hash_message(R, PK, M) → mhash, tree, idx_leaf
fors_pk_from_sig(sig_fors, mhash) → root
for layer in 0..7:
    wots_pk_from_sig → thash(leaf) → compute_root → root
root == PK.root
```

**Extra inputs** (beyond Phase 2a):

| Field | Source | In-circuit enforcement |
|-------|--------|------------------------|
| `signature` | Private witness (7856 B) | Wired inside FORS/WOTS/Merkle gadgets |
| `hm_mgf` | PQClean `hash_message_mgf_buf` | ✅ `mgf_bits == hm_mgf`; parsed fields from same witness bits |
| *(removed)* `intermediate_roots` | — | ✅ WOTS `chain_lengths` from witness `root_bits` via [`witness_bytes_from_bits`](../crates/sphincs-circuit/src/thash.rs) |

---

## Witness preparation (`verify_witness.rs`)

The prover does **not** derive all hints inside the R1CS yet. [`verify_witness.rs`](../crates/sphincs-prover/src/verify_witness.rs) (feature `pqclean`) builds a consistent `FoldVerifyCoreCircuit` from a PQClean KAT:

```text
(pk, sig, msg)
    │
    ├─ padded_message(msg) → (message[4096], mlen)
    ├─ sig_r(sig) → r
    ├─ hash_message_mgf_buf → hm_mgf (30 B, enforced in-circuit)
    └─ FoldVerifyCoreCircuit::full(...)   // no hm_expected, no intermediate_roots
```

**Consistency obligation:**

1. `hm_mgf == hash_message_mgf_buf(r, pk, msg, mlen)` (enforced in R1CS)
2. `link_digests[k]` = trace bytes at local-chain boundaries (when using bound steps)

---

## Tests

**Full guide (commands, tiers, what each test checks):** [VERIFY_CORE_TESTS.md](VERIFY_CORE_TESTS.md)

### CI default (run after verify-core changes)

```bash
cargo test -p sphincs-circuit verify_public_io && \
cargo test -p sphincs-circuit hash_message_public && \
cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message && \
cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message_public_io
```

### Summary table

| Test file | Test | What it checks | Default CI |
|-----------|------|----------------|------------|
| `hash_msg::tests::parsed_output_matches_native` | — | Phase 2c: `synthesize_hash_message_parsed` + `parse_mgf_output` agree with PQClean | ✅ runs |
| `hash_msg::tests::hash_message_public_preimage_matches_native` | — | SHA preimage wired from public IO columns | ✅ runs |
| `hash_msg::tests::hash_message_variable_mlen_matches_native` | — | Short/long seed SHA mux from public `mlen` (fixed `circuit_mlen`) | ✅ runs |
| `verify::tests::wrong_hm_mgf_unsatisfies_parsed_hash_message` | — | Corrupt `hm_mgf` breaks `mgf_bits == hm_mgf` | ✅ runs |
| `verify::tests::valid_signature_satisfies_core_public` | — | Full core + public-wired `hash_message` on PQClean KAT | `#[ignore]` release |
| [`fold_verify_core_hash_message.rs`](../crates/sphincs-prover/tests/fold_verify_core_hash_message.rs) | `smoke`, `plain_steps` | Phase 2a end-to-end prove/verify | ✅ runs |
| [`fold_verify_core_hash_message_public_io.rs`](../crates/sphincs-prover/tests/fold_verify_core_hash_message_public_io.rs) | `smoke` | Phase 2c public IO (1033 scalars) | ✅ runs |
| [`fold_verify_core_full.rs`](../crates/sphincs-prover/tests/fold_verify_core_full.rs) | `full_setup` | Phase 2b `NeutronNovaZkSNARK::setup` (R1CS shape + equalize) | `#[ignore]` (~7 min release) |
| | `full_public_io_setup` | Full core + `public_io` setup / equalize | `#[ignore]` release |
| | `full_public_io_smoke` | Full core + `public_io` prove + verify | `#[ignore]` release |
| | `full_prep_prove` | Witness generation for full core | `#[ignore]` |
| | `full_smoke` | Full prove + verify with bound steps | `#[ignore]` |
| | `full_plain_steps` | Full core + plain steps (no shared) | `#[ignore]` |

**Slow tests:** see [VERIFY_CORE_TESTS.md](VERIFY_CORE_TESTS.md) §Tier C–D for exact `--release --ignored` commands.

---

## What is NOT done yet (Phase 2c+)

1. **Variable public `mlen` (partial)** — [`with_variable_public_mlen`](../crates/sphincs-prover/src/verify_core.rs) + trace-linked seed; full universal circuit (all `mlen` topologies, one setup) in [VARIABLE_MLEN.md](VARIABLE_MLEN.md).
2. **In-circuit tree/leaf bit mux** — addresses still use synthesis-time constants from parsed mgf witness (optional hardening; see [CIRCUIT.md](CIRCUIT.md)).
3. **Full trace scale** — tests use 4-step chain prefix, not ~2k compressions.
4. **`hash_message` trace linking (done)** — seed-SHA wired to NeutronNova `shared` links in Phase 2a and **Full** core (`synthesize_verify_core_with_trace`). MGF1 via folded `C_step`. **`thash` / FORS / hypertree** still use in-gadget SHA.
5. **Variable public `mlen`** — muxed preimage / incremental SHA in `hash_message_bits`.

---

## File map

| File | Purpose |
|------|---------|
| `crates/sphincs-circuit/src/verify.rs` | `synthesize_verify_core`, padding policy |
| `crates/sphincs-prover/src/verify_core.rs` | `FoldVerifyCoreCircuit`, `VerifyCorePhase`, Spartan hooks |
| `crates/sphincs-prover/src/verify_witness.rs` | PQClean → circuit builder (`pqclean` feature) |
| `crates/sphincs-circuit/src/verify_public_io.rs` | Public Spartan IO pack / inputize / enforce |
| `crates/sphincs-prover/tests/fold_verify_core_hash_message.rs` | Phase 2a NeutronNova tests |
| `crates/sphincs-prover/tests/fold_verify_core_hash_message_public_io.rs` | Phase 2c public IO NeutronNova test |
| `crates/sphincs-prover/tests/fold_verify_core_full.rs` | Phase 2b NeutronNova tests |
| `docs/VERIFY_CORE_TESTS.md` | **Test guide** — commands, tiers, per-test descriptions |
| `docs/VARIABLE_MLEN.md` | Variable public `mlen` design + PQClean branch helpers |
