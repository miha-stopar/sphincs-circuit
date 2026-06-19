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
| **L4b** | 24 | `FoldStepBoundCircuit` chain + core alloc-only | **FAIL** — full step chain |
| **L4b-in** | 24 | step 1: `u32_words_from_shared` only | **OK** — IN-from-shared works |
| **L4b-single** | 24 | step 0: `enforce_words_eq_shared` only | **FAIL** — OUT-pin fails |
| **L4b-out-1link** | 8 | step 0 out-pin, one digest | **FAIL** — not a width issue |
| **L4c-indirect** | 24 | `digest_eq` + `enforce_bytes_eq_shared` on all steps (equalized) | prep **OK**, verify **FAIL** |
| **L4c-mirror** | 24 | `digest_eq` + alloc mirror + `enforce_words_eq_shared` (equalized) | prep **OK**, verify **FAIL** |
| **L5** | 24 | step + core (consistent chain) | full split binding |

**L4 vs L4a** fixed the old `enforce_num_eq_u32` bug. **L4b splits** show verify fails on **`enforce_words_eq_shared`** (compression output → shared), not on `u32_words_from_shared` (shared → compression input).

**L4c** tried core-style and mirror workarounds with **equalized precommitted layout** on every folded step instance (padding row duplicates penultimate step). `prep_prove` passes; verify still fails with `InvalidSumcheckProof` — the bug is not fixed by routing through byte glue or an allocated mirror.

**Local R1CS (2025-05):** `enforce_words_eq_shared` on real compression gadget output is **locally satisfiable** (`shared_link` unit test + `local_r1cs_l4b_single_step0_out_pin_satisfied`). The failure is **not** unsatisfiable constraints — prove/verify disagree under NeutronNova fold.

**Direction asymmetry (2025-05):**

| Pattern | verify |
|---------|--------|
| **IN** partial: `u32_words_from_shared` on one link slot (L4b-in) | **OK** |
| **OUT** partial: any out-pin to one link slot (L4b-single, L4c, L4d scalar decoupled) | **FAIL** |
| **All shared** referenced in every step `precommitted` (L4e: scalar `aux == shared[i]` for all 24) | **OK** |
| L4e + step-0 `enforce_words_eq_shared` out-pin (L4f) | **FAIL** |

So NeutronNova verify tolerates **read-from-shared** and **touch-all-shared-scalars**, but breaks on **write-to-shared** (compression output → shared slot), even with scalar-only decoupled witnesses (no `UInt32` wire to gadget).

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
│ L0–L3, L4a, L4, L4b-in   verify OK                          │
│ L4b-single/out, L4b, L5  FAIL — enforce_words_eq_shared     │
│ L4c indirect/mirror      prep OK, verify FAIL (same error)  │
│ fold_bound_shared        same (out-pin to shared)           │
│ fold_bound_packed_core   verify OK, glue inside C_step      │
└─────────────────────────────────────────────────────────────┘
```

---

## L4b sub-ladder (step-side splits)

```bash
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4b -- --nocapture
```

| Test | What it isolates | verify |
|------|------------------|--------|
| `ladder_4b_in_step1_shared_h_in_only` | `u32_words_from_shared` on step 1 | **OK** |
| `ladder_4b_single_step0_out_pin_only` | `enforce_words_eq_shared` on step 0 only | **FAIL** |
| `ladder_4b_out_one_link_step0_only` | out-pin with 8 shared (one link) | **FAIL** |
| `ladder_4b_step_shared_pin_chain_core_alloc_only` | full in+out chain | **FAIL** |

Folded steps must share the same `precommitted` gadget path; mixing replica SHA on some instances causes `Precommitted variables are not allocated correctly`.

## L4c out-pin workarounds (equalized layout)

```bash
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4c -- --nocapture
```

| Test | Pin strategy | prep_prove | verify |
|------|--------------|------------|--------|
| `ladder_4c_out_pin_indirect_bytes` | `enforce_digest_bytes_eq_words` + `enforce_bytes_eq_shared` on every step | **OK** | **FAIL** |
| `ladder_4c_out_pin_mirror_alloc_words` | gadget → alloc mirror → `enforce_words_eq_shared` on every step | **OK** | **FAIL** |
| `ladder_4c_out_pin_indirect_bytes_step0_only` | indirect pin on step 0 only (unequal aux) | **FAIL** | — |

Unequal per-instance `precommitted` aux counts break `prep_prove` (`Precommitted variables are not allocated correctly`). Production `bound.rs` must not add digest/bytes glue on only some step indices without equalizing all instances.

## L4d–L4f isolation (write vs read, partial vs all-shared)

```bash
cargo test -p sphincs-circuit shared_link::tests::enforce_words_eq_shared_compress_gadget_output_is_satisfied -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug local_r1cs -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4e -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4f -- --nocapture
```

| Test | What it shows |
|------|----------------|
| `local_r1cs_l4b_single_step0_out_pin_satisfied` | Out-pin R1CS is satisfiable in bellpepper |
| `ladder_4d_scalar_decoupled_out_pin_full_layout` | Out-pin without gadget wire still fails verify |
| `ladder_4e_fold_gadget_all_shared_scalar_eq` | Referencing **all** shared scalars every step passes |
| `ladder_4f_all_shared_scalar_eq_plus_step0_out_pin` | Adding out-pin on top of L4e breaks verify again |

## Internals walkthrough (what happens in our case)

Spartan2 NeutronNova treats one proof as **two R1CS relations** (`S_step`, `S_core`) glued in the **proof algebra** (NIFS fold + batched sum-check), not as one bellpepper `ConstraintSystem`.

### Witness layout (fixed at `setup`)

`setup(step_proto, core_proto, num_steps)` synthesizes **`step_proto` = `steps[0]`** once and records segment sizes:

```text
z_step = [ W_shared | W_precommitted | W_rest | 1 | public_values ]
           ^^^^^^^^   ^^^^^^^^^^^^^^
           24 scalars  ~26k compress gadget aux (same WIDTH every instance)
```

`SplitR1CSShape::equalize(S_step, S_core)` pads the **smaller** shape so step and core share the same `num_shared`, `num_precommitted`, `num_rest` **counts** (matrices still differ).

**Prototype rule:** every folded step instance must allocate **≥ `num_precommitted_unpadded`** aux vars in `precommitted()` or `prep_prove` fails (`Precommitted variables are not allocated correctly`). Logic may differ by `step_index`; aux **count** may not (unless the big SHA gadget dominates).

### Phase 1 — `shared_witness` (once)

From `neutronnova_zk.rs` `prep_prove`:

1. Call `step_circuits[0].shared(cs)` only — **not** per-instance.
2. Copy first `num_shared_unpadded` aux values into `W[0..24]`.
3. PCS-commit → `comm_W_shared`.

For `FoldStepBoundCircuit`, `shared()` is `alloc_digest_shared` over all `link_digests` (24 field elements). **Every** step instance and the core will reuse this **same** `W_shared` prefix and **same** `comm_W_shared`.

### Phase 2 — `precommitted_witness` (per instance)

For each `step_circuits[i]` (parallel):

1. Clone prep state (shared witness + `comm_W_shared` already fixed).
2. Run `step_circuits[i].precommitted(cs, shared_handles)`.
3. Copy next `num_precommitted_unpadded` aux into `W[24..]`.
4. PCS-commit → `comm_W_precommitted` (per instance).

**Our case — L4b-single (verify FAIL):**

| Instance | `precommitted` logic | Coupling to `W_shared` |
|----------|----------------------|-------------------------|
| Step 0 | compress + **`enforce_words_eq_shared(out, shared[0..8])`** | **write**: gadget output → shared slot 0 |
| Steps 1–3 | compress only | no shared refs |

**Our case — L4b-in (verify OK):**

| Instance | `precommitted` logic | Coupling to `W_shared` |
|----------|----------------------|-------------------------|
| Step 0 | compress | none |
| Step 1 | **`u32_words_from_shared(shared[0..8])`** + compress | **read**: shared slot 0 → gadget input |
| Steps 2–3 | compress | none |

Locally, both satisfy R1CS (`local_r1cs_*` tests). `W_shared` values are identical across instances (from step 0 `shared()`). Per-instance `W_precommitted` differs (different `block`, different active constraints).

### Phase 3 — matvec cache (`prep_prove`, our circuits)

Our ladder circuits have `num_rest = 0` and `num_challenges = 0`, so Spartan2 caches per step instance:

```text
z = [ W | 1 | public_values ]
(Az, Bz, Cz) = S_step.multiply_vec(z)
```

Also builds `cached_step_i64` for fast NIFS round 0; positions where values don't fit `i64` go to `large_positions` and are zeroed in the i64 cache (corrected in field arithmetic later).

This cache is **deterministic** from `prep_prove` and reused in `prove` (must match same `public_values`).

### Phase 4 — `prove`

1. **Rerandomize** PCS blinds; all step instances **reuse core's `comm_W_shared`** (`rerandomize_with_shared_in_place`).
2. `r1cs_instance_and_witness` per step (fast path: no `synthesize` — witness already complete).
3. **NIFS** folds 4 step `(U_i, W_i)` → `(U_fold, W_fold)` using cached matvec / i64 layers + verifier-circuit Fiat–Shamir.
4. **Batched sum-check** over folded step polynomials + core polynomials.
5. **Relaxed Spartan SNARK** proving the NeutronNova **verifier circuit** trace.

### Phase 5 — `verify` (where we fail)

Verify reconstructs the same transcript and checks, in order:

1. Per-instance commitment / challenge consistency (`U.validate`).
2. NIFS `verify` + **`relaxed_snark.verify`** on the verifier circuit ← we fail here: `InvalidSumcheckProof`.
3. (Later) recomputed `quotient_step`, `quotient_core`, public IO equality.

So the failure is **not** bellpepper synthesis at verify time; it's that the **proof π** (sum-check / relaxed Spartan leg) doesn't match what the verifier recomputes from `vk` + π.

### What the out-pin constraint actually does

`enforce_words_eq_shared` adds rows coupling:

- `W_shared[k]` (committed once, indices 0..7 for link 0)
- `W_precommitted[j]` (compression output `UInt32` bits, deep in SHA gadget)

via `enforce_num_eq_u32`: `shared_limb - Σ bit_i·2^i = 0`.

That is a **cross-segment** constraint (shared column ↔ precommitted column). IN-pin does the same algebra but wires shared → **fresh** input `UInt32` consumed by compress, not compress **output**.

### Debugging checklist

```bash
# 1. Local R1CS (bellpepper only — no Spartan)
cargo test -p sphincs-circuit shared_link::tests::enforce_words_eq_shared_compress_gadget_output_is_satisfied -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug local_r1cs -- --nocapture

# 2. Minimal pass vs fail under NeutronNova
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4b_in_step1_shared_h_in_only -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4b_single_step0_out_pin_only -- --nocapture

# 3. Isolation ladder (direction / all-shared touch)
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4e -- --nocapture   # pass
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4f -- --nocapture   # fail

# 4. Spartan2 internal spans (if tracing enabled in your build)
RUST_LOG=spartan2=info cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4b_single -- --nocapture
```

**Interpretation guide:**

| If this fails… | Likely layer |
|----------------|--------------|
| `local_r1cs_*` | Our constraint / witness encoding |
| `prep_prove` | Aux layout vs prototype (`steps[0]`) |
| `prove` | Synthesis / instance generation |
| `verify` + `InvalidSumcheckProof` | NIFS / sum-check / relaxed Spartan (prover π ≠ verifier) |

**Prep vs verify failures are different bugs.** Unequal aux layout → prep. Satisfiable R1CS + prep OK + verify fail → proof-system path (current out-pin issue).

### Hypotheses to test next (ordered)

1. **NIFS i64 path:** out-pin constraints produce `large_positions` entries that are mishandled during fold (compare `large_positions.len()` L4b-in vs L4b-single — needs Spartan2 logging or fork).
2. **Partial shared write:** Spartan2 only tested `shared() → []` or “touch all shared scalars” (L4e); partial **write** may be unsupported.
3. **Verifier circuit / NIFS transcript:** prover and verifier disagree on folded instance claims when cross-segment coupling is present on compress **outputs**.

---

## Next steps

1. Spartan2 upstream repro: **L4b-in (read)** vs **L4b-single (write)** with identical fold gadget; attach `local_r1cs_*` showing constraints are satisfiable.
2. Ask whether partial shared **write** in `precommitted` is supported, or whether integrators must touch every shared limb (L4e) — and whether OUT-pin is expected to work at all.
3. Re-run `fold_bound_shared` after Spartan2 fix.
4. Until then, use `FoldPackedCoreBoundCircuit` for sound local-chain demos.

---

*Spartan2 version: 0.9.0 (see workspace `Cargo.toml`).*
