# Circuit decomposition: SPHINCS+ verify

Supersedes the old prepare/show credential layout. Scope: prove `Verify(PK, M, σ) = 1` only.

See [TRACE.md](TRACE.md) (compression trace + core wiring), [SPHINCS.md](SPHINCS.md) (algorithm), [CODEMAP.md](CODEMAP.md) (PQClean files), [VERIFY_CORE.md](VERIFY_CORE.md) (NeutronNova `C_core` adapter).

---

## Relation `R_verify`

**Public:** `PK`, `M[0..M_MAX]`, `mlen`  
**Private:** `σ`, SHA compression trace, aux (indices, WOTS lengths, etc.)

**Constraints (mirror PQClean [`sign.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/sign.c)):**

1. `|M| = mlen`; padding bytes zero beyond `mlen` ([DECISIONS.md](DECISIONS.md)).
2. Every trace entry satisfies `C_step` (one compression).
3. Core links compressions per logical hash call ([TRACE.md](TRACE.md) §2).
4. SPHINCS+ dataflow: `hash_message` → `fors_pk_from_sig` → 7× (`wots_pk_from_sig` → `thash` → `compute_root`) → `root == PK.root`.

See also **[§Synthesis-time hints](#synthesis-time-hints-trusted-witness-prep)** — values passed into gadgets at circuit-build time that are not yet fully enforced in R1CS (production must close these gaps or document verifier-side checks).

---

## Sub-circuits (gadget modules)

| Module | PQClean | Arithmetization |
|--------|---------|-----------------|
| `sha256_compress` | [`common/sha2.c`](../third_party/PQClean/common/sha2.c) `crypto_hashblocks_sha256` | **`C_step`** — folded |
| `hash_message` | [`hash_sha2.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/hash_sha2.c) | Core + trace |
| `thash` | [`thash_sha2_simple.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/thash_sha2_simple.c) | Core + trace |
| `fors_verify` | [`fors.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/fors.c) `fors_pk_from_sig` | Core |
| `wots_verify` | [`wots.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/wots.c) | Core + many `thash` traces |
| `compute_root` | [`utils.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/utils.c) | Core + `thash(2)` traces |

---

## Folding

All compressions share one `C_step` template → NeutronNova fold → Spartan2 with `C_core`. Details: [FOLDING.md](FOLDING.md).

---

## Implementation order

1. `sha256_compress` (bellpepper, match trace)
2. `hash_message` + `mgf1` for bounded `M_MAX`
3. `fors_pk_from_sig`
4. `wots_pk_from_sig` + `gen_chain`
5. `compute_root` + top-level `sphincs_verify`
6. Spartan2 + NeutronNova integration

Milestones: [PLAN.md](PLAN.md).

---

## Synthesis-time hints (trusted witness prep)

Several M2 gadgets take **Rust parameters** at circuit synthesis that affect constraint **topology** or **constants**, but are not yet derived from in-circuit witness. Honest proving uses PQClean / `sphincs-ref` oracles (`witness.rs`, test helpers). For production ZK, each row must either move **in-circuit** or be covered by **public IO + verifier checks**.

| Input / parameter | Where | Enforced in R1CS today? | Risk if wrong | Production fix |
|-------------------|-------|-------------------------|---------------|----------------|
| **`hm_mgf`** (30 B MGF1 output) | `synthesize_hash_message` / `_parsed` | ✅ `mgf_bits == hm_mgf` | — | Keep |
| **`mhash`**, **`tree`**, **`leaf_idx`** | `synthesize_verify_core` via [`synthesize_hash_message_parsed`](../crates/sphincs-circuit/src/hash_msg.rs) | ⚠️ Parsed at **synthesis** from witness `mgf_bits` (same bits as `hm_mgf` check); FORS/hypertree **addresses** still use Rust `u64`/`u32` constants, not in-circuit bit mux | Attacker cannot pass a separate wrong `hm_expected` oracle; address topology still fixed at synthesis from assigned mgf witness | Optional hardening: in-circuit `parse_mgf_output` bit masks wiring tree/leaf into address gadgets |
| **`intermediate_roots` / `root_in_bytes`** | `hypertree_layer_from_root_bits` | ✅ `chain_lengths` from witness `root_bits` via [`witness_bytes_from_bits`](../crates/sphincs-circuit/src/thash.rs) at synthesis | Topology still fixed at synthesis from assigned root witness (not in-circuit max-unroll) | Max-unroll + mask in `wots.rs` (optional hardening) |
| **`message`**, **`mlen`** | `hash_message_bits`, `FoldVerifyCoreCircuit` | ✅ With `public_io`: 1033 public scalars `inputize`d and tied to statement bytes; `mlen` still synthesis-time constant for SHA length | Forged public statement without matching witness fails `enforce_public_matches_statement` | Variable public `mlen` in one universal circuit ([HACKMD](HACKMD_NEUTRONNOVA_PLAN.md) §Phase 2) |
| **`pk`**, **`signature`** bytes | Many gadgets (`R`, `pub_seed`, sig chunks) | Mixed: some `alloc_input_bits` (witness), some `Boolean::constant` | Constants can't be forged at prove time, but aren't yet public statement inputs | Wire as public IO where statement requires (`PK` public; `σ` private witness) |
| **PQClean trace** (`sha256_compressions`, link digests) | `C_step`, shared links | ✅ per-compression + link equalities (when bound) | Bad trace → local `is_sat` fail | Keep; trace is private witness |
| **Addresses** (`fors_addr`, `wots_addr`, …) | Built from `tree` / `idx_leaf` | Constants from synthesis-time parse of constrained `mgf_bits` (see above) | Topology fixed at synthesis; must match assigned mgf witness | Wire tree/leaf bits into address allocation (optional) |

**Witness-generator obligation:** use [`fold_verify_core_from_pqclean`](../crates/sphincs-prover/src/verify_witness.rs) or ensure `hm_mgf == MGF1(...)`. See [VERIFY_CORE.md](VERIFY_CORE.md).

**Not the same as trusted setup:** these are implementation gaps in the arithmetization, not a ceremony. Closing them is Phase 2 `Full` / production hardening ([PLAN.md](PLAN.md) M3–M4).
