# Plan: ZK proof of SPHINCS+ signature verification

**Scope:** Prove in zero knowledge that a SPHINCS+ signature is valid for a message under a public key. No credentials, parsing, attributes, or device binding.

**Reference implementation:** PQClean `sphincs-sha2-128s-simple` (`crypto_sign_verify` in `sign.c`).

**Proof system:** Transparent SNARK — Spartan2 + NeutronNova folding over SHA-256 compression steps (see [FOLDING.md](FOLDING.md)).

---

## 1. Statement (what we prove)

### 1.1 Relation `R_verify`

```
R_verify(PK, M, σ, w) = 1  ⟺  SPHINCS+.Verify(PK, M, σ) = 1
```

- `PK` — 32-byte public key (`pub_seed ‖ root`)
- `M` — message bytes, length `|M|` (bounded by `M_max` in circuit)
- `σ` — 7856-byte signature (128s simple)
- `w` — auxiliary witness (intermediate hashes, compression trace)

The R1CS checks the same logic as PQClean `crypto_sign_verify`, not a simplified approximation.

### 1.2 ZK variant — **locked: A**

| | |
|--|--|
| **Public** | `PK`, `M`, `mlen` |
| **Private** | `σ`, compression trace, aux |
| **Verifier learns** | Valid signature for `(PK, M)` — not `σ` |

See [DECISIONS.md](DECISIONS.md). Variants B/C deferred.

### 1.3 Message length — **locked: padded**

- `M` padded to `MESSAGE_MAX_BYTES` (4096); public `mlen`.
- Inactive suffix bytes constrained to zero.
- Matches [`hash_message`](../third_party/PQClean/crypto_sign/sphincs-sha2-128s-simple/clean/hash_sha2.c) branches.

Length-hiding deferred to v2. See [DECISIONS.md](DECISIONS.md).

---

## 2. How SPHINCS+ verification works (circuit target)

See [SPHINCS.md](SPHINCS.md) for diagrams. Verify pipeline (PQClean order):

1. `initialize_hash_function` — absorb `pub_seed` into SHA-256 state  
2. `hash_message` — derive `mhash`, tree index, leaf index from `R ‖ PK ‖ M`  
3. `fors_pk_from_sig` — recover FORS public key from `mhash` + FORS sig  
4. For each of `SPX_D = 7` hypertree layers:  
   - `wots_pk_from_sig` — recover WOTS+ public key from current root + WOTS sig  
   - `thash` — hash WOTS+ pk to leaf  
   - `compute_root` — walk Merkle auth path to subtree root  
5. Compare final root to `PK.root`

All cryptographic work is **SHA-256** (`thash`, `mgf1`, incremental hash) plus **bit / index logic**.

---

## 3. Circuit architecture

### 3.1 Two-part split (step + core)

| Part | Role |
|------|------|
| **Step circuit `C_step`** | One SHA-256 compression: `(H_in, block) → H_out` |
| **Core circuit `C_core`** | SPHINCS+ glue: per-hash compression linking + 16-byte dataflow (FORS→WOTS→Merkle); see [TRACE.md](TRACE.md) |

**Why split:** ~2k–3k compressions per verify (see [FOLDING.md](FOLDING.md) §4.4). Folding collapses them for proving efficiency.

### 3.2 Witness layout

```
w = (
  σ,                          // 7856 B
  R,                          // 16 B (from σ prefix)
  mhash, tree, idx_leaf,      // derived / checked
  all (H_in, block, H_out)_i, // i = 1..N_comp
  fors / wots / ht aux,       // siblings from σ, indices
)
```

Public: `PK`, `M`, `mlen` (if padded model).

### 3.3 Gadget dependency order

```
Phase 1: sha256_compress          (step circuit template)
Phase 2: sha256_incremental       (init / blocks / finalize — or map to compressions)
Phase 3: thash                    (clone seeded state + finalize)
Phase 4: hash_message + mgf1
Phase 5: fors_verify
Phase 6: wots_verify (gen_chain)
Phase 7: compute_root / hypertree loop
Phase 8: sphincs_verify_top       (core — composes 4–7)
Phase 9: Spartan2 integration + fold
```

---

## 4. Folding plan

1. Instrument PQClean verify → list every compression with `(H_in, block, H_out)` and global index `i`.  
2. Assign each compression to step instance `i`.  
3. Core adds equality constraints linking consecutive `H` values per `thash` / `hash_message` path.  
4. Run **NeutronNova** fold over all step instances → `acc_N`.  
5. **Spartan** prove `C_step(acc_N) ∧ C_core(PK, M, σ, …)`.

No credential SHA, no Pedersen attribute commitments for v1 — only Hyrax (or Spartan internal PCS) over witness for ZK.

Details: [FOLDING.md](FOLDING.md).

---

## 5. Proof system (minimal)

| Component | Choice |
|-----------|--------|
| Arithmetization | R1CS (Circom → bellpepper, or bellpepper native) |
| Uniform part | NeutronNova fold on `C_step` |
| SNARK | Spartan2 (transparent) |
| ZK | Nova-style fold on verifier checks (Spartan ZK mode) |
| PCS | Hyrax (or Spartan2 default PCS) — commit to `σ` and hash witness |

No trusted setup. Groth16 not used.

---

## 6. Milestones

### M0 — Reference & trace (1–2 weeks)

- [x] Vendor PQClean `sphincs-sha2-128s-simple`
- [x] `sphincs-ref`: wrap `crypto_sign_verify`
- [x] Instrument SHA-256: emit compression trace on verify (`SPX_SHA256_TRACE` in `sha2.c`)
- [x] `verify_with_trace`, `sign_deterministic`, tests + `sphincs-trace-stats` binary
- [x] Export trace JSON for circuit witness generator (`trace_to_json`)

### M1 — Step circuit (2–3 weeks)

- [x] Bit-accurate `sha256_compress` in bellpepper (`crates/sphincs-circuit`)
- [x] Test: trace witness satisfies `C_step` for each compression (first 20 rows + neg test)
- [x] Constraint count per compression (~19.5k on BLS12-381 test CS)

### M2 — Core sub-gadgets (4–6 weeks)

- [x] `thash` (fixed `inblocks` ∈ {1, 2, 14, 35}) — `crates/sphincs-circuit/src/thash.rs`, validated bit-for-bit vs PQClean (`thash_oracle`)
- [ ] `hash_message` + `mgf1` for bounded `M_max`
- [ ] `fors_pk_from_sig`
- [ ] `wots_pk_from_sig` + `gen_chain`
- [ ] `compute_root` × (FORS height + HT height)
- [ ] End-to-end witness gen from PQClean trace vs circuit witness diff

### M3 — Folding + prove (3–4 weeks)

- [ ] Wire NeutronNova fold pipeline
- [ ] Spartan2 proof of full verify on KAT
- [ ] Benchmark: prove time, verify time, proof size vs native verify

### M4 — Hardening (ongoing)

- [ ] Variant B (hidden `M`) if needed
- [ ] `128s` robust parameter feature flag
- [ ] Constraint / proving optimizations (lookup for small XORs, etc.)

---

## 7. Success criteria

1. **Correctness:** For all PQClean KATs, circuit accepts iff `crypto_sign_verify` returns 0.  
2. **Soundness:** Standard R1CS + Spartan soundness reduction.  
3. **ZK (variant A):** Simulator with `(PK, M)` only, no `σ`.  
4. **Performance target (initial):** Prove full verify in < 60s desktop (stretch: < 10s); verify < 100ms — tune after M3.

---

## 8. Out of scope (this repo)

- Verifiable credentials, SD-JWT, prepare–show, Pedersen attributes  
- Device binding, predicates, reblind pools  
- ML-DSA / ECDSA circuits  
- Signing or key generation in-circuit  

Architecture: [DESIGN.md](DESIGN.md). Circuits: [CIRCUIT.md](CIRCUIT.md), [SPHINCS.md](SPHINCS.md), [FOLDING.md](FOLDING.md).

---

## 9. Repository actions

| Action | Status |
|--------|--------|
| `docs/PLAN.md` (this file) | Done |
| `docs/SPHINCS.md` — structure & verify flow | Done |
| Simplify `circuit-spec` to `VerifyRelation` only | Done |
| Update `README.md` | Done |
| `circuits/` — implement per §3.3 | Pending M1 |
