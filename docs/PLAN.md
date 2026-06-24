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

- [x] `thash` (fixed `inblocks` ∈ {1, 2, 14, 35}) — `crates/sphincs-circuit/src/thash.rs`, validated bit-for-bit vs PQClean (`thash_oracle`). Exposes composable `thash_digest_bits` (returns output wires).
- [x] `compute_root` × (FORS height 12 + HT height 9) — `crates/sphincs-circuit/src/merkle.rs`, chains `thash(2)` per level, validated bit-for-bit vs PQClean (`compute_root_oracle`) across both parities
- [x] `wots_pk_from_sig` + `gen_chain` — `crates/sphincs-circuit/src/wots.rs`, chains `thash(1)` per Winternitz step (35 chains), validated bit-for-bit vs PQClean (`wots_pk_from_sig_oracle`)
- [x] `fors_pk_from_sig` — `crates/sphincs-circuit/src/fors.rs`, 14× (`sk_to_leaf` + `compute_root`) + horizontal `thash(14)`, validated vs `fors_pk_from_sig_oracle`
- [x] Hypertree layer glue (`wots_pk_from_sig` → leaf `thash(35)` → `compute_root(9)`) — `crates/sphincs-circuit/src/hypertree.rs`, validated vs composed PQClean oracles
- [x] `hash_message` + `mgf1` for bounded `M_max` — `crates/sphincs-circuit/src/hash_msg.rs`, SHA256(`R‖pk‖M`) + MGF1 wired seed→output; validated vs `hash_message_oracle`
- [x] Top-level verify core glue — `crates/sphincs-circuit/src/verify.rs`: `hash_message` → FORS → 7× hypertree → `root == PK.root` (full test `#[ignore]`, slow in debug)
- [x] End-to-end witness from PQClean trace + `C_step` validation — `crates/sphincs-circuit/src/witness.rs` (`witness_from_trace`, `validate_trace_steps`, local chain analysis)

### M3 — Folding + prove (3–4 weeks)

- [x] Wire NeutronNova fold pipeline (`sphincs-prover`: step + placeholder core, 4-step smoke test)
- [x] Local-chain core: `FoldCoreChainCircuit` + `chain::synthesize_sha256_state_equal` (boundary bytes; fold IO TBD)
- [x] Fold longest local chain prefix (`fold_local_chain` test, default 16 steps)
- [x] Sound local-chain wiring in one step (`FoldPackedChainCircuit<N>`, wire `h_out[i]→h_in[i+1]`)
- [x] Bind core link witnesses to per-instance folded step wires — uniform selector in [`FoldStepBoundCircuit`](../crates/sphincs-prover/src/bound.rs); `fold_bound_shared` passes (see [SHARED_WITNESS_DEBUG.md](SHARED_WITNESS_DEBUG.md))
- [x] Fold prefix of full trace (`fold_trace_batch`: 8 steps CI, 32 ignored)
- [x] Real `C_core` in prover — [`FoldVerifyCoreCircuit`](../crates/sphincs-prover/src/verify_core.rs): `hash_message` smoke passes (`fold_verify_core_hash_message`); full `synthesize_verify_core` next
- [ ] Public `mlen` in Spartan IO — **deferred:** smoke/full-core KATs use fixed `mlen` per circuit instance; variable public `mlen` + trace alignment in final v1 IO (see [HACKMD_NEUTRONNOVA_PLAN.md](HACKMD_NEUTRONNOVA_PLAN.md) §Phase 2 `mlen` table)
- [ ] Spartan2 proof of full verify on KAT (~all trace compressions)
- [ ] Close synthesis-time hint gaps — [CIRCUIT.md](CIRCUIT.md) §Synthesis-time hints (`hm_expected` parse, `chain_lengths` from witness, public `M`/`mlen`)
- [x] Bench harness: `cargo run -p sphincs-prover --features pqclean --release --bin fold-bench -- N`
- [ ] Benchmark: full trace prove/verify vs native verify

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
