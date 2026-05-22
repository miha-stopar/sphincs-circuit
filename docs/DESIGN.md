# Architecture: ZK proof of SPHINCS+ signature verification

**Scope:** Prove in zero knowledge that `SPHINCS+.Verify(PK, M, σ) = 1`. No credentials, attributes, or prepare/show protocols.

Locked v1 choices: [DECISIONS.md](DECISIONS.md). Milestones: [PLAN.md](PLAN.md).

---

## Problem statement

Given public key `PK`, message `M`, and signature `σ`, the prover convinces a verifier that `σ` is valid for `(PK, M)` **without revealing `σ`** (ZK variant A).

Native reference: PQClean [`crypto_sign_verify`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/sign.c) — see [CODEMAP.md](CODEMAP.md), [SPHINCS.md](SPHINCS.md).

---

## Statement

```
R_verify(PK, M, mlen, σ, w) = 1  ⟺  Verify(PK, M, σ) = 1
```

| | v1 (locked) |
|--|-------------|
| **Public** | `PK`, `M` padded to `M_MAX`, `mlen` |
| **Private** | `σ` (7856 B), SHA compression trace, SPHINCS+ aux |

---

## SPHINCS+ implementation

### Primary: PQClean `sphincs-sha2-128s-simple`

- Path: [`third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/)
- Rust wrapper: [`crates/sphincs-ref`](../crates/sphincs-ref/)
- **SHA-256** throughout verify → matches bellpepper / Spartan2 SHA gadgets and NeutronNova folding
- **simple** variant: NIST “simple” parameter set (faster verify; heuristic hash assumption)

### Cross-check

[`sphincs/sphincsplus`](https://github.com/sphincs/sphincsplus) for KATs and differential testing.

### Parameter trade-offs

| Alternative | Why not (for v1) |
|-------------|------------------|
| SHAKE / Haraka | Heavier or custom gadgets in prime-field R1CS |
| `128f` | Larger σ (~17 KB); similar circuit cost |
| `192s` / `256s` | More hash work; defer until 128s works |
| Rust-only crate | PQClean anchor for liboqs / reproducible witness |

**Chosen:** `SPHINCS+-SHA2-128s` simple — σ ≈ 7856 B, PK 32 B. Details: [PARAMETERS.md](PARAMETERS.md).

---

## Circuit architecture

Two R1CS parts — see [TRACE.md](TRACE.md) for chaining semantics.

| Part | Role |
|------|------|
| **`C_step`** | One SHA-256 compression: `(H_in, block) → H_out` |
| **`C_core`** | SPHINCS+ glue: compression linking within each hash call + 16-byte dataflow (hash_message → FORS → 7× WOTS/Merkle → `root == PK.root`) |

```
Witness: σ, compression trace (~2k–3k entries), aux
         │
         ├─► C_step × N  ──NeutronNova fold──► acc_N
         │
         └─► C_core(PK, M, mlen, σ, trace) ──► accept
                    │
                    └── Spartan2 prove(step + core) → π
```

**VegaMC-style** (folded SHA step + core) is the target arithmetization. Single unrolled circuit is a debug baseline only.

---

## Proof system (v1)

| Component | Choice |
|-----------|--------|
| R1CS frontend | bellpepper ([`gadgets::sha256`](https://docs.rs/bellpepper/latest/bellpepper/gadgets/sha256/index.html)) |
| Uniform work | NeutronNova fold on `C_step` ([Spartan2 bench](https://github.com/microsoft/Spartan2/blob/main/benches/sha256_neutronnova.rs)) |
| SNARK | Spartan2 [`SpartanZkSNARK`](https://docs.rs/spartan2/latest/spartan2/spartan_zk/index.html) |
| Engine / PCS | **`T256HyraxEngine`** — Hyrax PCS on T256 field (Spartan2 SHA benchmarks; transparent, no trusted setup) |
| ZK | Nova-style folding on verifier checks (Spartan ZK mode) |
| Witness layout | **Single proof** for v1 — no SplitSpartan commit split yet |

SplitSpartan (multiple Hyrax commitments, cross-proof linking) is **optional later** for multi-phase credential systems — see [PROOF_SYSTEM.md](PROOF_SYSTEM.md).

### Why SHA-256 in-circuit (not Poseidon)

The statement is “verify **this** SPHINCS+ signature,” which is defined over SHA-256. Poseidon would prove a different relation unless the issuer changed algorithms.

### Message length

**Padded `M` + public `mlen`** — not length-hiding in v1. See [DECISIONS.md](DECISIONS.md).

---

## Polynomial commitments (Hyrax)

Spartan2 is PCS-generic; this project follows upstream SHA examples:

- **PCS:** [Hyrax](https://docs.rs/spartan2/latest/spartan2/provider/pcs/hyrax_pc/index.html) (`provider::pcs::hyrax_pc`)
- **Engine:** `T256HyraxEngine` — commits to the R1CS witness (including hidden `σ` and trace) inside Spartan’s prove/verify flow

v1 does **not** use separate Pedersen attribute commitments or prepare/show reblind pools.

| Scheme | v1 |
|--------|-----|
| Hyrax (via Spartan2) | **Yes** — witness commitments for ZK |
| KZG / Groth16 | No — trusted setup |
| SplitSpartan slice commitments | No — until multi-phase proofs |

---

## Security (sketch)

- **Soundness:** SPHINCS+ unforgeability + R1CS correctness + Spartan soundness.
- **ZK (variant A):** Verifier sees `(PK, M, mlen)` and accept bit; `σ` and trace simulated without the witness.
- **PQ:** Issuer signature is PQ; ZK layer is classical (DL-based Hyrax) until a lattice PCS is plugged in later.

---

## Related docs

| Doc | Contents |
|-----|----------|
| [PLAN.md](PLAN.md) | Milestones M0–M4 |
| [SPHINCS.md](SPHINCS.md) | Verify flow diagrams |
| [TRACE.md](TRACE.md) | Compression trace + core wiring |
| [FOLDING.md](FOLDING.md) | NeutronNova fold, hash budget |
| [PROOF_SYSTEM.md](PROOF_SYSTEM.md) | Spartan2, SplitSpartan vs single proof |
| [CODEMAP.md](CODEMAP.md) | PQClean file map |

---

## Future (out of scope for this repo v1)

A credential stack may **reuse** `R_verify` as a submodule (offline prove sig valid, later predicates on attributes). That would add SplitSpartan witness slices and optional length-hiding — not part of current milestones.
