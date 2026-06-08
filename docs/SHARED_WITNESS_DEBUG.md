# Shared witness debug environment

Isolated reproduction of the Spartan2 0.9.0 NeutronNova verify failure that blocks **split** step↔core binding (`FoldStepBoundCircuit` / `fold_bound_shared`).

No PQClean, no SPHINCS trace — synthetic circuits in [`neutronnova_shared_debug.rs`](../crates/sphincs-prover/tests/neutronnova_shared_debug.rs).

---

## What problem are we debugging?

**Goal (production):** connect folded step compressions to a separate core circuit using `SpartanCircuit::shared` — one witness prefix both sides read.

**Symptom:** `prove` succeeds, `verify` fails:

```text
ProofVerifyError { reason: "Relaxed Spartan verify failed: InvalidSumcheckProof" }
```

**Not the same as:** split `FoldStepCircuit` + `FoldCoreChainCircuit` (verify passes but digests are **not** wired together).

---

## Root cause (localized)

| Finding | Detail |
|---------|--------|
| **Not** `num_shared > 0` alone | L1–L3 and L4a pass with 1, 8, and **24** shared scalars |
| **Fixed (2025-05)** | Old `enforce_num_eq_u32` zipped `to_bits_le` vs `into_bits_be` — **locally unsatisfiable** with intended witness; fixed via UInt32 LE bit reconstruction |
| **L4** | Core-only `enforce_bytes_eq_shared` — **verify OK** after fix |
| **L4b** | `FoldStepBoundCircuit` shared pin chain + core alloc-only — **verify FAIL** → remaining bug is **step-side** shared wiring under NeutronNova fold |
| **L5 / `fold_bound_shared`** | Step + core — still fail until step-side issue is resolved |

Scalar equality (`aux == shared[i]`) works. Core byte glue works after reconstruction. Step `u32_words_from_shared` / `enforce_words_eq_shared` under folded instances does not verify yet.

---

## Files

| File | Role |
|------|------|
| [`crates/sphincs-prover/tests/neutronnova_shared_debug.rs`](../crates/sphincs-prover/tests/neutronnova_shared_debug.rs) | Debug ladder L0–L5 |
| [`crates/sphincs-prover/tests/neutronnova_replica.rs`](../crates/sphincs-prover/tests/neutronnova_replica.rs) | Control: Microsoft SHA bench, `shared() → []` |
| [`crates/sphincs-prover/tests/fold_bound_shared.rs`](../crates/sphincs-prover/tests/fold_bound_shared.rs) | Full SPHINCS path (ignored, needs `pqclean`) |
| [`crates/sphincs-circuit/src/shared_link.rs`](../crates/sphincs-circuit/src/shared_link.rs) | Bit-decomposition glue (suspect) |
| [`crates/sphincs-prover/src/bound.rs`](../crates/sphincs-prover/src/bound.rs) | Production binding attempt |

---

## Circuit shape requirement

Spartan2 0.9.0 NeutronNova builds a **verifier circuit** whose outer sum-check rounds index into `prior_round_vars[round][0..4]` (step) and `[4..8]` (core). With only a handful of R1CS constraints, verify panics:

```text
zk.rs:719: range end index 4 out of range for slice of length 2
```

Every ladder level uses **one SHA-256 compression** in step `precommitted` (same gadget as `neutronnova_replica`, ≈26k constraints). Shared-witness logic is layered on top.

---

## Debug ladder (L0 → L5)

Each level runs: `setup` → `prep_prove` → `prove` → `verify` on **4 step instances + 1 core** (`NUM_STEPS = 4`).

| Level | `num_shared` | Shared glue style | verify |
|-------|-------------|-------------------|--------|
| **L0** | 0 | — (replica circuits) | **OK** |
| **L1** | 1 | scalar `aux == shared` | **OK** |
| **L2** | 8 | scalar (one digest width) | **OK** |
| **L3** | 1 | alloc only, no precommitted refs | **OK** |
| **L4a** | 24 | scalar eq, 3 digest links | **OK** |
| **L4** | 24 | `enforce_bytes_eq_shared` (core glue) | **OK** (after `enforce_num_eq_u32` fix) |
| **L4b** | 24 | `FoldStepBoundCircuit` chain + core alloc-only | isolates step-side shared pins |
| **L5** | 24 | `FoldStepBoundCircuit` + `FoldCoreBoundCircuit` (consistent chain) | full split binding |

**L4 vs L4a** isolated the old `enforce_num_eq_u32` bug (LE vs BE bit zip). **L4b** isolates step-side shared pins without core glue.

---

## How to run

From repo root:

```bash
# Full ladder + summary (recommended)
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_summary_all_phases -- --nocapture

# Key isolation tests
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4a_multi_link_scalar_equality_core -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4_bound_style_core_bit_decomposition -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_5_production_bound_circuits_synthetic -- --nocapture

# Control: real SHA steps, empty shared (should pass)
cargo test -p sphincs-prover --test neutronnova_replica -- --nocapture

# Full SPHINCS binding (same verify error, needs pqclean)
cargo test -p sphincs-prover --features pqclean --test fold_bound_shared -- --ignored --nocapture
```

No `--features pqclean` needed for the isolated ladder.

---

## Phase-by-phase output

`run_neutronnova` prints:

```text
setup: ok
prep_prove: ok
prove: ok
verify: ok | FAILED — …
```

Typical failure (L4, L5, `fold_bound_shared`):

```text
verify: FAILED — ProofVerifyError: Relaxed Spartan verify failed: InvalidSumcheckProof
```

Failure is in the **relaxed Spartan** leg of verify (after NIFS on the verifier circuit), not in bellpepper synthesis.

---

## Relationship to SPHINCS paths

```text
┌─────────────────────────────────────────────────────────────┐
│ L0–L3, L4a          Shared witness OK (scalar / alloc-only) │
│ L4, L5, fold_bound  FAIL — bit-decomposition shared glue    │
│ fold_split_step_core verify OK, NO wire binding             │
│ fold_bound_packed_core verify OK, glue inside C_step        │
└─────────────────────────────────────────────────────────────┘
```

---

## Next steps

1. Fix `enforce_num_eq_u32` / shared↔`UInt32` wiring so prover and verifier R1CS layouts match under NeutronNova (or use scalar equality if sound for T256 limb range).
2. Minimal upstream repro for [Spartan2](https://github.com/Microsoft/Spartan2): L4 vs L4a pair.
3. Re-run `fold_bound_shared` (remove `#[ignore]`) after fix.
4. Until then, use `FoldPackedCoreBoundCircuit` for sound local-chain demos.

---

*Spartan2 version: 0.9.0 (see workspace `Cargo.toml`).*
