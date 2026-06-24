# Shared witness debug environment

Isolated reproduction of the Spartan2 0.9.0 NeutronNova verify failure that **blocked** split step↔core binding (`FoldStepBoundCircuit` / `fold_bound_shared`). **Status: resolved** — see [Fix (uniform selector binding)](#fix-uniform-selector-binding).

No PQClean, no SPHINCS trace — synthetic circuits in [`neutronnova_shared_debug.rs`](../crates/sphincs-prover/tests/neutronnova_shared_debug.rs).

---

## Current status

| Path | verify |
|------|--------|
| **L6** uniform selector (`BoundStyleStepUniform`) | **OK** |
| **L5** production `FoldStepBoundCircuit` + `FoldCoreBoundCircuit` | **OK** |
| **`fold_bound_shared`** (full SPHINCS+ trace, needs `pqclean`) | **OK** |
| **L4b–L4f** (old per-step conditional pins) | **FAIL** — kept as negative controls |
| **`FoldPackedCoreBoundCircuit`** (glue inside one step) | **OK** — still valid, no longer required |

Split step↔core binding works. Production code is in [`bound.rs`](../crates/sphincs-prover/src/bound.rs); reusable gadgets are `one_hot_select` and `enforce_cond_link_eq_u32` in [`shared_link.rs`](../crates/sphincs-circuit/src/shared_link.rs).

---

## What problem were we debugging?

**Goal (production):** connect folded step compressions to a separate core circuit using `SpartanCircuit::shared` — one witness prefix both sides read.

**Symptom (before fix):** `prove` succeeds, `verify` fails:

```text
ProofVerifyError { reason: "Relaxed Spartan verify failed: InvalidSumcheckProof" }
```

**Not the same as:** split `FoldStepCircuit` + `FoldCoreChainCircuit` (verify passes but digests are **not** wired together).

---

## Root cause

| Finding | Detail |
|---------|--------|
| **Not** `num_shared > 0` alone | L1–L3 and L4a pass with 1, 8, and **24** shared scalars |
| **Fixed (2025-05)** | Old `enforce_num_eq_u32` zipped `to_bits_le` vs `into_bits_be` — **locally unsatisfiable** with intended witness; fixed via UInt32 LE bit reconstruction |
| **L4** | Core-only `enforce_bytes_eq_shared` — **verify OK** after bit-order fix |
| **L4b–L4f (historical)** | Per-step conditional pins (`if step_index == k { pin link k }`) — **verify FAIL** |
| **L5 / `fold_bound_shared` (before fix)** | Same conditional pattern in production `bound.rs` — **verify FAIL** |
| **Fixed (2025-06)** | **Uniform selector binding** — identical R1CS shape on every folded instance; L5, L6, `fold_bound_shared` **verify OK** |

### What actually broke (not an IN vs OUT Spartan2 bug)

The ladder initially suggested an **IN vs OUT asymmetry**: read-from-shared (L4b-in) passed, write-to-shared (L4b-single) failed. L4c–L4f explored equalized layouts, byte glue, mirror alloc words, and scalar decoupling — all still failed when any per-step OUT-pin was present.

The real issue was **R1CS shape mismatch across folded instances**:

- NeutronNova `setup` synthesizes **one** step shape from prototype `steps[0]`.
- All N folded instances are checked against that **same** matrix.
- The old design branched on `step_index`: step 0 pinned OUT to `link[0]`, step 1 pinned IN from `link[0]` and OUT to `link[1]`, etc. Each instance synthesized **different constraints on different shared columns**.
- Only the prototype instance was satisfiable; steps `1..n` failed `is_sat`, corrupting NIFS, and verify failed downstream (often surfacing as an unrelated verifier-circuit row, e.g. "row 132").

`enforce_words_eq_shared` itself is fine — it is locally satisfiable (`shared_link` unit tests, `local_r1cs_*`). The failure was **our circuit structure**, not Spartan2 rejecting shared writes.

---

## Fix (uniform selector binding)

Every folded step instance now runs the **same** constraint structure. Per-step variation lives only in witness **values**, not in which constraints are allocated.

1. **One-hot `pos`** — `pos[i] = (i == step_index)`, boolean + sums to 1.
2. **Public `step_index`** — `Σ i·pos[i] == step_index` (soundness: selectors can't be forged).
3. **Mux over all links** — `one_hot_select` reads `link[step_index - 1]` as `h_in` and writes `link[step_index]` as `h_out`, referencing **every** shared column on **every** instance.
4. **Boundary gates** — `enforce_cond_link_eq_u32` with `pos[0]` skips IN-pin on step 0; `pos[last]` skips OUT-pin on the last step.

Implementation: [`bound.rs`](../crates/sphincs-prover/src/bound.rs) `FoldStepBoundCircuit::synthesize_precommitted_linked`. Synthetic mirror: `BoundStyleStepUniform` in the debug test file (L6).

**Cost:** `step_index` is now a public input; each step adds selector + mux constraints (`O(num_steps × num_links)` per step). That is the price of uniform shape under NeutronNova's single-shape folding model.

---

## Files

| File | Role |
|------|------|
| [`crates/sphincs-prover/tests/neutronnova_shared_debug.rs`](../crates/sphincs-prover/tests/neutronnova_shared_debug.rs) | Debug ladder L0–L6 |
| [`crates/sphincs-prover/tests/neutronnova_replica.rs`](../crates/sphincs-prover/tests/neutronnova_replica.rs) | Control: Microsoft SHA bench, `shared() → []` |
| [`crates/sphincs-prover/tests/fold_bound_shared.rs`](../crates/sphincs-prover/tests/fold_bound_shared.rs) | Full SPHINCS path (needs `pqclean`) |
| [`crates/sphincs-circuit/src/shared_link.rs`](../crates/sphincs-circuit/src/shared_link.rs) | Shared-link gadgets (`one_hot_select`, `enforce_cond_link_eq_u32`, …) |
| [`crates/sphincs-prover/src/bound.rs`](../crates/sphincs-prover/src/bound.rs) | Production split binding (`FoldStepBoundCircuit`, `FoldCoreBoundCircuit`) |

---

## Circuit shape requirement

Spartan2 0.9.0 NeutronNova builds a **verifier circuit** whose outer sum-check rounds index into `prior_round_vars[round][0..4]` (step) and `[4..8]` (core). With only a handful of R1CS constraints, verify panics:

```text
zk.rs:719: range end index 4 out of range for slice of length 2
```

Every ladder level uses **one SHA-256 compression** in step `precommitted` (same gadget as `neutronnova_replica`, ≈26k constraints). Shared-witness logic is layered on top.

**Folded step rule (critical):** every instance must synthesize the **same** `precommitted` constraint structure and reference the **same** witness columns. Branching on `step_index` to pin different link slots breaks NeutronNova unless you equalize with a uniform selector (the fix) or pack glue into a single circuit (`FoldPackedCoreBoundCircuit`).

---

## Debug ladder (L0 → L6)

Each level runs: `setup` → `prep_prove` → `prove` → `verify` on **4 step instances + 1 core** (`NUM_STEPS = 4`).

| Level | `num_shared` | Shared glue style | verify |
|-------|-------------|-------------------|--------|
| **L0** | 0 | — (replica circuits) | **OK** |
| **L1** | 1 | scalar `aux == shared` | **OK** |
| **L2** | 8 | scalar (one digest width) | **OK** |
| **L3** | 1 | alloc only, no precommitted refs | **OK** |
| **L4a** | 24 | scalar eq, 3 digest links | **OK** |
| **L4** | 24 | `enforce_bytes_eq_shared` (core glue) | **OK** |
| **L4b** | 24 | old conditional step chain + core alloc-only | **FAIL** (historical) |
| **L4b-in** | 24 | step 1 only: `u32_words_from_shared` | **OK** |
| **L4b-single** | 24 | step 0 only: `enforce_words_eq_shared` | **FAIL** (historical) |
| **L4b-out-1link** | 8 | step 0 out-pin, one digest | **FAIL** (historical) |
| **L4c-indirect** | 24 | equalized byte glue on all steps | **FAIL** (historical) |
| **L4c-mirror** | 24 | equalized mirror + out-pin on all steps | **FAIL** (historical) |
| **L5** | 24 | production step + core (uniform selector) | **OK** |
| **L6** | 24 | synthetic `BoundStyleStepUniform` | **OK** |

L4b–L4f tests are **negative controls** — they reproduce the old per-step conditional pattern and should keep failing unless someone reintroduces that bug.

---

## How to run

From repo root:

```bash
# Full ladder + summary (L0–L5; L4b–L4c still print FAIL in summary)
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_summary_all_phases -- --nocapture

# Fix validation
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_6_uniform_selector -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_5_production_bound_circuits_synthetic -- --nocapture

# Key isolation tests
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4a_multi_link_scalar_equality_core -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4_bound_style_core_bit_decomposition -- --nocapture

# Control: real SHA steps, empty shared (should pass)
cargo test -p sphincs-prover --test neutronnova_replica -- --nocapture

# Full SPHINCS binding (needs pqclean)
cargo test -p sphincs-prover --features pqclean --test fold_bound_shared fold_bound_shared_links_prove_and_verify -- --nocapture
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

Historical failure pattern (L4b–L4f, old L5):

```text
verify: FAILED — ProofVerifyError: Relaxed Spartan verify failed: InvalidSumcheckProof
```

Failure was in the **relaxed Spartan** leg of verify (after NIFS on the verifier circuit), not in bellpepper synthesis. With the uniform selector fix, L5/L6/`fold_bound_shared` reach `verify: ok`.

---

## Relationship to SPHINCS paths

```text
┌─────────────────────────────────────────────────────────────┐
│ L0–L3, L4a, L4, L4b-in, L5, L6          verify OK            │
│ fold_bound_shared                        verify OK            │
│ L4b-single/out, L4b, L4c, L4d–L4f       FAIL (historical)   │
│ fold_bound_packed_core                   verify OK (packed)   │
└─────────────────────────────────────────────────────────────┘
```

---

## L4b–L4f sub-ladder (historical negative controls)

These tests document the **old broken pattern**. They should **fail** verify — that is expected.

### L4b (per-step conditional pins)

```bash
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4b -- --nocapture
```

| Test | What it isolates | verify |
|------|------------------|--------|
| `ladder_4b_in_step1_shared_h_in_only` | `u32_words_from_shared` on step 1 only | **OK** |
| `ladder_4b_single_step0_out_pin_only` | `enforce_words_eq_shared` on step 0 only | **FAIL** |
| `ladder_4b_out_one_link_step0_only` | out-pin with 8 shared (one link) | **FAIL** |
| `ladder_4b_step_shared_pin_chain_core_alloc_only` | full conditional in+out chain | **FAIL** |

### L4c (equalized layout workarounds — still failed)

```bash
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4c -- --nocapture
```

| Test | Pin strategy | prep_prove | verify |
|------|--------------|------------|--------|
| `ladder_4c_out_pin_indirect_bytes` | byte glue on every step | **OK** | **FAIL** |
| `ladder_4c_out_pin_mirror_alloc_words` | mirror alloc + out-pin on every step | **OK** | **FAIL** |
| `ladder_4c_out_pin_indirect_bytes_step0_only` | indirect pin on step 0 only | **FAIL** | — |

Equalizing aux **count** on every instance was necessary but not sufficient — the remaining bug was **which columns** each instance's constraints referenced.

### L4d–L4f (misleading IN/OUT asymmetry trail)

```bash
cargo test -p sphincs-prover --test neutronnova_shared_debug local_r1cs -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4e -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4f -- --nocapture
```

| Test | What it showed (in hindsight) |
|------|-------------------------------|
| `local_r1cs_l4b_single_step0_out_pin_satisfied` | Out-pin R1CS is satisfiable in bellpepper — not a local encoding bug |
| `ladder_4d_scalar_decoupled_out_pin_full_layout` | Per-step partial OUT-pin still shape-mismatched |
| `ladder_4e_fold_gadget_all_shared_scalar_eq` | Touching **all** shared columns every step passes (uniform column set) |
| `ladder_4f_all_shared_scalar_eq_plus_step0_out_pin` | Adding step-0-only OUT-pin reintroduces shape mismatch |

---

## Internals walkthrough

Spartan2 NeutronNova treats one proof as **two R1CS relations** (`S_step`, `S_core`) glued in the **proof algebra** (NIFS fold + batched sum-check), not as one bellpepper `ConstraintSystem`.

### Witness layout (fixed at `setup`)

`setup(step_proto, core_proto, num_steps)` synthesizes **`step_proto` = `steps[0]`** once and records segment sizes:

```text
z_step = [ W_shared | W_precommitted | W_rest | 1 | public_values ]
           ^^^^^^^^   ^^^^^^^^^^^^^^
           24 scalars  ~26k compress gadget aux (same WIDTH every instance)
```

`SplitR1CSShape::equalize(S_step, S_core)` pads the **smaller** relation so step and core matrices have the **same total witness dimension** (`num_shared + num_precommitted + num_rest`) and the same number of constraint rows. It grows **`num_rest`** (dummy tail variables) on the shorter side; **`num_shared` and `num_precommitted` per side are unchanged** — only the combined length matches. Matrices `A,B,C` still differ (different constraints); column indices for public IO are shifted accordingly.

**Prototype rule:** every folded step instance must synthesize the **same** constraint structure in `precommitted()` referencing the **same** witness columns, or non-prototype instances will not satisfy `S_step` and NIFS will fold bad witnesses.

### Phase 1 — `shared_witness` (once)

From `neutronnova_zk.rs` `prep_prove`:

1. Call `step_circuits[0].shared(cs)` only — **not** per-instance.
2. Copy first `num_shared_unpadded` aux values into `W[0..24]`.
3. PCS-commit → `comm_W_shared`.

For `FoldStepBoundCircuit`, `shared()` is `alloc_digest_shared` over all `link_digests` (24 field elements). **Every** step instance and the core reuse this **same** `W_shared` prefix and **same** `comm_W_shared`.

### Phase 2 — `precommitted_witness` (per instance)

For each `step_circuits[i]` (parallel):

1. Clone prep state (shared witness + `comm_W_shared` already fixed).
2. Run `step_circuits[i].precommitted(cs, shared_handles)`.
3. Copy next `num_precommitted_unpadded` aux into `W[24..]`.
4. PCS-commit → `comm_W_precommitted` (per instance).

**Old broken pattern — L4b-single (verify FAIL):**

| Instance | `precommitted` logic | Problem |
|----------|----------------------|---------|
| Step 0 | compress + OUT-pin to `shared[0..8]` | shape A |
| Steps 1–3 | compress only, no shared refs | shape B ≠ A |

**Fix — uniform selector (L5/L6, verify OK):**

| Instance | `precommitted` logic |
|----------|----------------------|
| All steps | same: `pos` one-hot + mux all links + compress + conditional IN/OUT bind |

Per-instance witnesses differ (`pos`, `block`, `h_in` values), but the R1CS **shape** is identical.

### Core padding bug (`enforce_message_padding` witness bloat)

**Symptom:** `FoldVerifyCoreCircuit` + old per-byte padding → `core: FAIL — UnSat`; without padding, core OK.

**Cause:** Old `enforce_message_padding` allocated ~`(M_MAX - mlen)` private `AllocatedBit`s in `C_core.precommitted()` that were **not** part of `hash_message_bits` (which only allocates `M[0..mlen]`). Those slots still occupied `W_precommitted` indices and R1CS columns. Combined with a different `num_precommitted` than the step prototype expected after `equalize`, witness assignment no longer satisfied `A·z ∘ B·z = C·z`.

**Fix:** Synthesis-time zero tail check only ([`verify.rs`](../crates/sphincs-circuit/src/verify.rs)); per-byte witness padding preserved as `enforce_message_padding_witness` for other paths.

```text
C_step W:  [ shared(24) | precommitted_step(~26k compress) | rest_pad | 1 | pub ]
C_core W:  [ shared(24) | precommitted_core(hash+…)       | rest_pad | 1 | pub ]
             ^^^^^^^^^^^   ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
             same commit   DIFFERENT width & meaning per circuit

equalize:  len(W_step) == len(W_core)  by growing num_rest on the shorter side
           (num_precommitted_step ≠ num_precommitted_core is normal)
```

### Phase 3 — matvec cache (`prep_prove`)

Our ladder circuits have `num_rest = 0` and `num_challenges = 0`, so Spartan2 caches per step instance:

```text
z = [ W | 1 | public_values ]
(Az, Bz, Cz) = S_step.multiply_vec(z)
```

This cache is **deterministic** from `prep_prove` and reused in `prove` (must match same `public_values`).

### Phase 4 — `prove`

1. **Rerandomize** PCS blinds; all step instances **reuse core's `comm_W_shared`**.
2. `r1cs_instance_and_witness` per step (fast path: witness already complete).
3. **NIFS** folds 4 step `(U_i, W_i)` → `(U_fold, W_fold)`.
4. **Batched sum-check** over folded step polynomials + core polynomials.
5. **Relaxed Spartan SNARK** proving the NeutronNova **verifier circuit** trace.

### Phase 5 — `verify`

Verify reconstructs the same transcript and checks NIFS + relaxed Spartan. With valid per-instance witnesses (uniform shape), this passes. With shape-mismatched instances, `is_sat` fails for steps `1..n`, NIFS folds inconsistent data, and verify fails with `InvalidSumcheckProof`.

### What the link-pin constraint does

`enforce_words_eq_shared` / `enforce_cond_link_eq_u32` couple:

- `W_shared[k]` (committed once)
- `W_precommitted[j]` (compression `UInt32` bits)

via `shared_limb - Σ bit_i·2^i = 0` (or gated variant). This cross-segment coupling is fine **when every instance uses the same column layout**.

### Debugging checklist

```bash
# 1. Local R1CS (bellpepper only — no Spartan)
cargo test -p sphincs-circuit shared_link::tests::enforce_words_eq_shared_compress_gadget_output_is_satisfied -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug local_r1cs -- --nocapture

# 2. Fix validation
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_6_uniform_selector -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_5_production_bound_circuits_synthetic -- --nocapture

# 3. Historical failures (should still fail)
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4b_single_step0_out_pin_only -- --nocapture
cargo test -p sphincs-prover --test neutronnova_shared_debug ladder_4f -- --nocapture
```

**Interpretation guide:**

| If this fails… | Likely layer |
|----------------|--------------|
| `local_r1cs_*` | Constraint / witness encoding |
| `prep_prove` | Aux layout vs prototype (`steps[0]`) |
| `prove` | Synthesis / instance generation |
| `verify` + `InvalidSumcheckProof` | Bad per-instance witnesses (often shape mismatch) or proof-system bug |

**Prep vs verify failures are different bugs.** Unequal aux layout → prep. Satisfiable R1CS + prep OK + verify fail → check whether all folded instances share the same R1CS shape.

---

*Spartan2 version: 0.9.0 (see workspace `Cargo.toml`).*
