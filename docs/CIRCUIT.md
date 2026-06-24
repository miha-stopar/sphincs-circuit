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
| **`intermediate_roots[layer]`** / **`root_in_bytes`** | `hypertree_layer_from_root_bits` | ⚠️ `enforce_bits_equal_bytes(root_in_bits, root_in_bytes)` ties witness root to hint bytes; **`chain_lengths(root_in_bytes)`** fixes WOTS unroll counts at synthesis | Wrong topology (chain step counts) if hint ≠ witness root | Derive lengths from `root_in_bits` in-circuit, or max-unroll + mask (see `wots.rs`) |
| **`message`**, **`mlen`** | `hash_message_bits`, `FoldVerifyCoreCircuit` | ⚠️ `mlen` is synthesis-time constant; only `M[0..mlen]` wired; tail not in R1CS | OK while `M` is build-time constant; breaks once `M` is public prover input | Public `VerifyPublic` + padding policy (off-circuit or on public `M`); variable public `mlen` in Phase 2c ([HACKMD](HACKMD_NEUTRONNOVA_PLAN.md) §Phase 2) |
| **`pk`**, **`signature`** bytes | Many gadgets (`R`, `pub_seed`, sig chunks) | Mixed: some `alloc_input_bits` (witness), some `Boolean::constant` | Constants can't be forged at prove time, but aren't yet public statement inputs | Wire as public IO where statement requires (`PK` public; `σ` private witness) |
| **PQClean trace** (`sha256_compressions`, link digests) | `C_step`, shared links | ✅ per-compression + link equalities (when bound) | Bad trace → local `is_sat` fail | Keep; trace is private witness |
| **Addresses** (`fors_addr`, `wots_addr`, …) | Built from `tree` / `idx_leaf` | Constants from synthesis-time parse of constrained `mgf_bits` (see above) | Topology fixed at synthesis; must match assigned mgf witness | Wire tree/leaf bits into address allocation (optional) |

**Witness-generator obligation:** use [`fold_verify_core_from_pqclean`](../crates/sphincs-prover/src/verify_witness.rs) or ensure `hm_mgf == MGF1(...)`, `intermediate_roots` from [`intermediate_roots_oracle`](../crates/sphincs-prover/src/verify_witness.rs) with `parse_mgf_output(hm_mgf)` for indices. See [VERIFY_CORE.md](VERIFY_CORE.md).

**Not the same as trusted setup:** these are implementation gaps in the arithmetization, not a ceremony. Closing them is Phase 2 `Full` / production hardening ([PLAN.md](PLAN.md) M3–M4).
