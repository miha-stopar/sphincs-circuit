# Parameter sets

## Production target

| Field | Value |
|-------|-------|
| Algorithm | SPHINCS+-SHA2-128s |
| Variant | simple (`*_simple` in PQClean) |
| PQClean dir | `crypto_sign/sphincssha2128ssimple` |
| NIST level | 1 (128-bit classical / 64-bit quantum target) |

## Signature / key sizes (simple, SHA2-128s)

| Object | Bytes |
|--------|------:|
| `CRYPTO_PUBLICKEYBYTES` | 32 |
| `CRYPTO_SECRETKEYBYTES` | 64 |
| `CRYPTO_BYTES` (signature) | 7856 |

## Feature flags (planned)

```toml
[features]
default = ["sha2-128s-simple"]
sha2-128s-robust = []   # conservative hash assumptions
sha2-128f-simple = []   # faster signing, larger σ
```

## Field for R1CS

Use **Spartan2 `T256HyraxEngine`** scalar field (same as upstream SHA benchmarks). See [DESIGN.md](DESIGN.md), [PROOF_SYSTEM.md](PROOF_SYSTEM.md).

## Benchmarks to collect

1. Native `crypto_sign_verify` latency (PQClean)
2. SHA-256 compression count inside verify (instrumentation)
3. R1CS constraint count per submodule
4. Spartan2 prove / verify time on KATs
