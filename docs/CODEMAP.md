# PQClean code map (SPHINCS+-SHA2-128s-simple)

Vendored at `third_party/PQClean/` (run `scripts/vendor-pqclean.sh` if missing).

Rust wrapper: `crates/sphincs-ref` (builds `clean/` + `common/sha2.c`).

## Entry points

| Symbol | File |
|--------|------|
| `PQCLEAN_…_crypto_sign_verify` | [`api.h`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/api.h) |
| `crypto_sign_verify` (macro) | [`nistapi.h`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/nistapi.h) → [`sign.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/sign.c) |

## Verify pipeline (file order)

| Step | Function | File |
|------|----------|------|
| Init SHA state with `pub_seed` | `initialize_hash_function` → `seed_state` | [`context_sha2.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/context_sha2.c) |
| Message → `mhash`, tree, leaf | `hash_message` | [`hash_sha2.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/hash_sha2.c) |
| FORS PK from sig | `fors_pk_from_sig` | [`fors.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/fors.c) |
| WOTS+ PK from sig | `wots_pk_from_sig` | [`wots.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/wots.c) |
| WOTS pk → leaf | `thash` | [`thash_sha2_simple.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/thash_sha2_simple.c) |
| Merkle path | `compute_root` | [`utils.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/utils.c) |
| Parameters | `SPX_*` macros | [`params.h`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/params.h) |

## SHA-256 (where compressions happen)

| API | File | Compression primitive |
|-----|------|------------------------|
| `sha256_inc_blocks` / `sha256_inc_finalize` | [`common/sha2.c`](../third_party/PQClean/common/sha2.c) | `crypto_hashblocks_sha256` (loop `while (inlen >= 64)`) |
| `sha256` one-shot | same | same |
| `mgf1_256` | [`hash_sha2.c`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/hash_sha2.c) | calls `sha256` |

## Spartan2 / bellpepper SHA (ZK circuit, not PQClean)

| Component | URL / path |
|-----------|------------|
| bellpepper `sha256` gadgets | [bellpepper::gadgets::sha256](https://docs.rs/bellpepper/latest/bellpepper/gadgets/sha256/index.html) |
| Spartan2 SHA benches | [microsoft/Spartan2 `benches/sha256_spartan.rs`](https://github.com/microsoft/Spartan2/blob/main/benches/sha256_spartan.rs), [`sha256_neutronnova.rs`](https://github.com/microsoft/Spartan2/blob/main/benches/sha256_neutronnova.rs) |

## KATs

PQClean checks implementations against NIST-style vectors via `test/crypto_sign/nistkat.c`. Scheme metadata: [`META.yml`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/META.yml) (`nistkat-sha256` hash).
