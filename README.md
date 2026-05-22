# SPHINCS+ ZK signature verification circuit

Prove in zero knowledge that you know a valid **SPHINCS+** signature for a message under a public key — implemented as an R1CS circuit with **folded SHA-256 compression steps** and a **Spartan2** transparent proof.

**Not in scope:** credentials, selective disclosure, device binding, or issuer/attribute protocols.

## Statement (v1)

**Public:** `PK`, message `M`  
**Private:** signature `σ` (+ hash trace witness `w`)  
**Prove:** `SPHINCS+.Verify(PK, M, σ) = 1`

## Docs

| Doc | Contents |
|-----|----------|
| [docs/PLAN.md](docs/PLAN.md) | Milestones, gadgets, success criteria |
| [docs/SPHINCS.md](docs/SPHINCS.md) | How SPHINCS+ verify works (diagrams) |
| [docs/FOLDING.md](docs/FOLDING.md) | Step vs core, NeutronNova folding, hash budget |
| [docs/PARAMETERS.md](docs/PARAMETERS.md) | 128s simple byte sizes |
| [docs/CODEMAP.md](docs/CODEMAP.md) | PQClean file ↔ function map |
| [docs/TRACE.md](docs/TRACE.md) | Compression trace + chaining |
| [docs/DECISIONS.md](docs/DECISIONS.md) | Locked v1 choices (ZK-A, padding) |
| [docs/PROOF_SYSTEM.md](docs/PROOF_SYSTEM.md) | Spartan2, SplitSpartan vs single proof |

## Stack

- **Impl:** PQClean `sphincs-sha2-128s-simple`
- **Circuit:** `C_step` = one SHA-256 compression; `C_core` = SPHINCS+ verify glue
- **Proof:** Spartan2 + NeutronNova fold (no trusted setup)

## Layout

```
docs/           PLAN, SPHINCS, FOLDING
crates/
  circuit-spec/ Verify relation types
  sphincs-ref/  Native PQClean verify wrapper (M0)
circuits/       R1CS gadgets (planned)
third_party/    PQClean (vendored locally)
```

## Status

**M0 (in progress):** PQClean `crypto_sign_verify` linked in `sphincs-ref`.

```bash
cargo test -p sphincs-ref
```

**Next:** SHA-256 compression trace on verify, then bellpepper `sha256_compress` (M1).

## Reference

- SPHINCS+ spec: https://sphincs.org/data/sphincs+-specification.pdf
- PQClean: `third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/`
