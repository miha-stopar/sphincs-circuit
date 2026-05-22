# Locked design decisions (v1)

Decisions agreed for the signature-verification circuit. Change only via explicit doc update.

## ZK variant

**Variant A** — see [PLAN.md](PLAN.md) §1.2.

| | |
|--|--|
| **Public** | `PK`, message `M`, active length `mlen` |
| **Private** | signature `σ`, compression trace, SPHINCS+ aux witness |
| **Verifier learns** | That a valid signature exists for `(PK, M)` — not `σ`, not auth paths |

**Rationale:** Matches future credential use (“prove issuer signed this payload” without revealing `σ`). Variant B/C deferred.

## Message length

**Padded message (not length-hiding)** — see [PLAN.md](PLAN.md) §1.3.

| | |
|--|--|
| **Circuit input** | `M_padded[M_MAX]` + public `mlen ≤ M_MAX` |
| **Constraints** | Bytes `M[mlen..M_MAX]` are zero; `hash_message` uses only first `mlen` bytes |
| **Initial `M_MAX`** | 4096 (`circuit-spec::MESSAGE_MAX_BYTES`) — adjust when profiling |

**Deferred:** Vega-style digest lookup (private length or hidden `M`).

## Native reference

**PQClean** `sphincs-sha2-128s-simple` / `clean/` — [CODEMAP.md](CODEMAP.md).

## Proof system (v1)

| Layer | Choice |
|-------|--------|
| Hash in circuit | Bit-accurate **SHA-256** (bellpepper), not Poseidon |
| Uniform work | **NeutronNova** fold on one compression step circuit |
| SNARK | **Spartan2** |
| Witness commitments | **Single** Spartan proof for v1; **no SplitSpartan commit split** until credential phases need it — [PROOF_SYSTEM.md](PROOF_SYSTEM.md) |

## Parameter set

**SPHINCS+-SHA2-128s simple** — [PARAMETERS.md](PARAMETERS.md).
