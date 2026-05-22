# Circuit decomposition: SPHINCS+ verify

Supersedes the old prepare/show credential layout. Scope: prove `Verify(PK, M, σ) = 1` only.

See [TRACE.md](TRACE.md) (compression trace + core wiring), [SPHINCS.md](SPHINCS.md) (algorithm), [CODEMAP.md](CODEMAP.md) (PQClean files).

---

## Relation `R_verify`

**Public:** `PK`, `M[0..M_MAX]`, `mlen`  
**Private:** `σ`, SHA compression trace, aux (indices, WOTS lengths, etc.)

**Constraints (mirror PQClean [`sign.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/sign.c)):**

1. `|M| = mlen`; padding bytes zero beyond `mlen` ([DECISIONS.md](DECISIONS.md)).
2. Every trace entry satisfies `C_step` (one compression).
3. Core links compressions per logical hash call ([TRACE.md](TRACE.md) §2).
4. SPHINCS+ dataflow: `hash_message` → `fors_pk_from_sig` → 7× (`wots_pk_from_sig` → `thash` → `compute_root`) → `root == PK.root`.

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
