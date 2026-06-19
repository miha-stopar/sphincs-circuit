//! Isolated NeutronNova + **shared witness** debug ladder (no PQClean / SPHINCS).
//!
//! Purpose: reproduce Spartan2 0.9.0 verify failure when `num_shared > 0` with
//! synthetic shared-witness glue on top of the same SHA-256 step/core shape as
//! `neutronnova_replica` (tiny R1CS circuits break VC round indexing in Spartan2 0.9.0).
//!
//! See `docs/SHARED_WITNESS_DEBUG.md` for how to run and interpret results.

use std::marker::PhantomData;

use bellpepper::gadgets::{sha256::sha256_compression_function, uint32::UInt32};
use bellpepper_core::{
    boolean::{AllocatedBit, Boolean},
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::Field;
use spartan2::{
    neutronnova_zk::NeutronNovaZkSNARK,
    provider::T256HyraxEngine,
    traits::{circuit::SpartanCircuit, Engine},
};
use bellpepper_core::test_cs::TestConstraintSystem;
use sphincs_circuit::{
    alloc_digest_shared, enforce_bytes_eq_shared, enforce_digest_bytes_eq_words,
    enforce_words_eq_shared, link_shared_slice,
    sha256_compress::{
        state_bytes_to_words, synthesize_compression_for_fold_h_words,
        synthesize_compression_for_fold_with_out,
    },
    u32_words_from_shared, DIGEST_WORDS,
};
use sphincs_circuit::step::StepInput;
use sphincs_prover::{bound_steps_from_inputs, FoldCoreBoundCircuit};

type E = T256HyraxEngine;
type Scalar = <E as Engine>::Scalar;

const BLOCK_BYTES: usize = 64;

const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

/// Enforce `a == b` in R1CS: `(a - b) * 1 = 0`.
fn enforce_equal<Scalar, CS>(
    mut cs: CS,
    label: &str,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    cs.enforce(
        || label,
        |lc| lc + a.get_variable() - b.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(())
}

/// Allocate `n` shared field elements with known values.
fn alloc_shared<Scalar, CS>(
    mut cs: CS,
    label: &str,
    values: &[Scalar],
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    values
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            AllocatedNum::alloc(cs.namespace(|| format!("{label}_{i}")), move || Ok(v))
        })
        .collect()
}

// --- Step circuit (folded N times) -----------------------------------------------------------

#[derive(Clone, Debug)]
struct DebugStepCircuit {
    /// Values assigned to shared slots (must match core).
    shared_values: Vec<Scalar>,
    /// Per-instance block (distinct step witness, same shared layout) — like `ReplicaStepCircuit`.
    block: [u8; BLOCK_BYTES],
    _p: PhantomData<Scalar>,
}

impl DebugStepCircuit {
    fn new(shared_values: Vec<Scalar>, block: [u8; BLOCK_BYTES]) -> Self {
        Self {
            shared_values,
            block,
            _p: PhantomData,
        }
    }
}

impl SpartanCircuit<E> for DebugStepCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_shared(cs.namespace(|| "step_shared"), "link", &self.shared_values)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let input_bits: Vec<Boolean> = self
            .block
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
            .enumerate()
            .map(|(i, b)| {
                AllocatedBit::alloc(cs.namespace(|| format!("block bit {i}")), Some(b))
                    .map(Boolean::from)
            })
            .collect::<Result<_, _>>()?;

        let current_hash: Vec<UInt32> = SHA256_IV.iter().map(|&v| UInt32::constant(v)).collect();
        let _next = sha256_compression_function(
            cs.namespace(|| "sha256 compression"),
            &input_bits,
            &current_hash,
        )?;

        // Step "uses" shared: aux_i == shared[i]
        for (i, s) in shared.iter().enumerate() {
            let aux = AllocatedNum::alloc(cs.namespace(|| format!("aux_{i}")), || {
                s.get_value().ok_or(SynthesisError::AssignmentMissing)
            })?;
            enforce_equal(cs.namespace(|| format!("eq_{i}")), "eq", &aux, s)?;
        }

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
        _precommitted: &[AllocatedNum<Scalar>],
        _challenges: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

// --- Core circuit (single instance, not folded) ----------------------------------------------

#[derive(Clone, Debug)]
struct DebugCoreCircuit {
    shared_values: Vec<Scalar>,
    _p: PhantomData<Scalar>,
}

impl DebugCoreCircuit {
    fn new(shared_values: Vec<Scalar>) -> Self {
        Self {
            shared_values,
            _p: PhantomData,
        }
    }
}

impl SpartanCircuit<E> for DebugCoreCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // Must mirror step shared layout (same count, same order) for equalize + comm_W_shared.
        alloc_shared(cs.namespace(|| "core_shared"), "link", &self.shared_values)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let input_bits: Vec<Boolean> = (0..512)
            .map(|i| {
                AllocatedBit::alloc(cs.namespace(|| format!("core bit {i}")), Some(false))
                    .map(Boolean::from)
            })
            .collect::<Result<_, _>>()?;

        let current_hash: Vec<UInt32> = SHA256_IV.iter().map(|&v| UInt32::constant(v)).collect();
        let _next = sha256_compression_function(
            cs.namespace(|| "core sha256 compression"),
            &input_bits,
            &current_hash,
        )?;

        // Core "glue": expected constant bytes == shared slots (like FoldCoreBoundCircuit).
        for (i, (&expected, s)) in self.shared_values.iter().zip(shared.iter()).enumerate() {
            let exp = AllocatedNum::alloc(cs.namespace(|| format!("exp_{i}")), || Ok(expected))?;
            enforce_equal(cs.namespace(|| format!("core_eq_{i}")), "core_eq", s, &exp)?;
        }

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
        _precommitted: &[AllocatedNum<Scalar>],
        _challenges: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

// --- Empty-shared baseline (byte-for-byte `neutronnova_replica` circuits) --------------------

#[derive(Clone, Debug)]
struct ReplicaStepCircuit {
    block: [u8; BLOCK_BYTES],
    _p: PhantomData<Scalar>,
}

impl ReplicaStepCircuit {
    fn new(block: [u8; BLOCK_BYTES]) -> Self {
        Self {
            block,
            _p: PhantomData,
        }
    }
}

impl SpartanCircuit<E> for ReplicaStepCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(&self, _: &mut CS) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let input_bits: Vec<Boolean> = self
            .block
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
            .enumerate()
            .map(|(i, b)| {
                AllocatedBit::alloc(cs.namespace(|| format!("block bit {i}")), Some(b))
                    .map(Boolean::from)
            })
            .collect::<Result<_, _>>()?;

        let current_hash: Vec<UInt32> = SHA256_IV.iter().map(|&v| UInt32::constant(v)).collect();
        let _next = sha256_compression_function(
            cs.namespace(|| "sha256 compression"),
            &input_bits,
            &current_hash,
        )?;

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct ReplicaCoreCircuit(PhantomData<Scalar>);

impl ReplicaCoreCircuit {
    fn new() -> Self {
        Self(PhantomData)
    }
}

impl SpartanCircuit<E> for ReplicaCoreCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(&self, _: &mut CS) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let input_bits: Vec<Boolean> = (0..512)
            .map(|i| {
                AllocatedBit::alloc(cs.namespace(|| format!("core bit {i}")), Some(false))
                    .map(Boolean::from)
            })
            .collect::<Result<_, _>>()?;

        let current_hash: Vec<UInt32> = SHA256_IV.iter().map(|&v| UInt32::constant(v)).collect();
        let _next = sha256_compression_function(
            cs.namespace(|| "core sha256 compression"),
            &input_bits,
            &current_hash,
        )?;

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

// --- Runner ----------------------------------------------------------------------------------

/// NeutronNova pads to power-of-two; Spartan2 VC needs ≥ 4 instances in practice (see `neutronnova_replica`).
const NUM_STEPS: usize = 4;

/// `num_steps − 1` link digests (24 shared scalars when `NUM_STEPS = 4`).
fn sample_link_digests(num_links: usize, seed: u8) -> Vec<[u8; 32]> {
    (0..num_links)
        .map(|k| {
            let mut d = [0u8; 32];
            d[0] = seed.wrapping_add(k as u8);
            d[31] = k as u8;
            d
        })
        .collect()
}

fn alloc_all_digests<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    label: &str,
    digests: &[[u8; 32]],
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    let mut nums = Vec::with_capacity(digests.len() * DIGEST_WORDS);
    for (k, digest) in digests.iter().enumerate() {
        nums.extend(alloc_digest_shared(
            cs.namespace(|| format!("{label}_{k}")),
            "link",
            *digest,
        )?);
    }
    Ok(nums)
}

// --- L4: bound-style core glue (bit decomposition, no SHA in core) ---------------------------

/// Step with same `shared()` layout as core but no precommitted refs (required for equalize).
#[derive(Clone, Debug)]
struct BoundStyleStepAllocOnly {
    block: [u8; BLOCK_BYTES],
    link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for BoundStyleStepAllocOnly {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_digests(cs, "step_shared", &self.link_digests)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let input_bits: Vec<Boolean> = self
            .block
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
            .enumerate()
            .map(|(i, b)| {
                AllocatedBit::alloc(cs.namespace(|| format!("block bit {i}")), Some(b))
                    .map(Boolean::from)
            })
            .collect::<Result<_, _>>()?;

        let current_hash: Vec<UInt32> = SHA256_IV.iter().map(|&v| UInt32::constant(v)).collect();
        let _next = sha256_compression_function(
            cs.namespace(|| "sha256 compression"),
            &input_bits,
            &current_hash,
        )?;

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct BoundStyleCoreCircuit {
    link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for BoundStyleCoreCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_digests(cs, "core_shared", &self.link_digests)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        for (k, digest) in self.link_digests.iter().enumerate() {
            enforce_bytes_eq_shared(
                cs.namespace(|| format!("core_link_{k}")),
                "trace",
                digest,
                link_shared_slice(shared, k),
            )?;
        }
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

/// SHA-256 IV as 32-byte big-endian state (PQClean / RFC 6234 layout).
fn sha256_iv_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, &w) in SHA256_IV.iter().enumerate() {
        b[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    b
}

/// One compression via the same gadget as `FoldStepBoundCircuit`; returns `h_out` bytes.
fn compress_h_out(h_in: &[u8; 32], block: &[u8; BLOCK_BYTES]) -> [u8; 32] {
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let out_words =
        synthesize_compression_for_fold_with_out(&mut cs, h_in, block).expect("compress synth");
    let mut bytes = [0u8; 32];
    for (i, word) in out_words.iter().enumerate() {
        let mut w = 0u32;
        for (j, bit) in word.clone().into_bits().iter().enumerate() {
            if bit.get_value() == Some(true) {
                w |= 1 << j;
            }
        }
        bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    bytes
}

/// `num_steps` compressions chained `h_in_{i+1} = h_out_i`; link digests are each step's `h_out`.
fn build_consistent_bound_batch(
    num_steps: usize,
) -> (Vec<StepInput>, Vec<[u8; 32]>) {
    let mut h_in = sha256_iv_bytes();
    let mut inputs = Vec::with_capacity(num_steps);
    let mut digests = Vec::with_capacity(num_steps.saturating_sub(1));
    for i in 0..num_steps {
        let block = [i as u8; BLOCK_BYTES];
        let h_out = compress_h_out(&h_in, &block);
        inputs.push(StepInput { h_in, block, h_out });
        if i + 1 < num_steps {
            digests.push(h_out);
        }
        h_in = h_out;
    }
    (inputs, digests)
}

/// NeutronNova padding row: duplicate penultimate step so last instance can mirror its link slot.
fn pad_last_step_duplicate_prev(inputs: &mut [StepInput]) {
    let last = inputs.len() - 1;
    let prev = last.saturating_sub(1);
    inputs[last] = inputs[prev].clone();
}

/// L4b-single: only `step_index == 0` pins `h_out → shared[0]`; other steps ignore shared.
#[derive(Clone, Debug)]
struct BoundStyleStepPinOutSingle {
    step_index: usize,
    input: StepInput,
    link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl BoundStyleStepPinOutSingle {
    fn new(step_index: usize, input: StepInput, link_digests: Vec<[u8; 32]>) -> Self {
        Self {
            step_index,
            input,
            link_digests,
            _p: PhantomData,
        }
    }

    /// Finer precommitted() row map: h_in → compress → (optional) OUT-pin → public x.
    fn debug_dump_precommitted_milestones(&self) -> Result<(), SynthesisError> {
        use spartan2::bellpepper::shape_cs::ShapeCS;

        let mut cs = ShapeCS::<E>::new();
        let shared = self.shared(&mut cs)?;
        let base = cs.num_constraints();

        let h_words: Vec<UInt32> = state_bytes_to_words(&self.input.h_in)
            .iter()
            .enumerate()
            .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)))
            .collect::<Result<_, _>>()?;
        let after_h_in = cs.num_constraints();

        let out_words = synthesize_compression_for_fold_h_words(
            cs.namespace(|| "compress"),
            &h_words,
            &self.input.block,
        )?;
        let after_compress = cs.num_constraints();

        let after_out_pin = if self.step_index == 0 {
            enforce_words_eq_shared(
                cs.namespace(|| "link_out_0"),
                "h_out",
                &out_words,
                link_shared_slice(&shared, 0),
            )?;
            cs.num_constraints()
        } else {
            after_compress
        };

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        let after_x = cs.num_constraints();

        eprintln!(
            "  precommitted milestones (step_index={}):",
            self.step_index
        );
        eprintln!(
            "    rows [{base:5}..{after_h_in:5})  count={:5}  h_in UInt32 alloc",
            after_h_in - base
        );
        eprintln!(
            "    rows [{after_h_in:5}..{after_compress:5})  count={:5}  SHA compress gadget",
            after_compress - after_h_in
        );
        if self.step_index == 0 {
            eprintln!(
                "    rows [{after_compress:5}..{after_out_pin:5})  count={:5}  OUT-pin link_out_0 (enforce_words_eq_shared)",
                after_out_pin - after_compress
            );
        } else {
            eprintln!("    (no OUT-pin — step_index != 0)");
        }
        eprintln!(
            "    rows [{after_out_pin:5}..{after_x:5})  count={:5}  public input x",
            after_x - after_out_pin
        );
        Ok(())
    }
}

impl SpartanCircuit<E> for BoundStyleStepPinOutSingle {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_digests(cs, "step_shared", &self.link_digests)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // Same fold compression gadget on every instance (required for precommitted equalize).
        let h_words = state_bytes_to_words(&self.input.h_in)
            .iter()
            .enumerate()
            .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)))
            .collect::<Result<Vec<_>, _>>()?;
        let out_words = synthesize_compression_for_fold_h_words(
            cs.namespace(|| "compress"),
            &h_words,
            &self.input.block,
        )?;
        if self.step_index == 0 {
            enforce_words_eq_shared(
                cs.namespace(|| "link_out_0"),
                "h_out",
                &out_words,
                link_shared_slice(shared, 0),
            )?;
        }
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

/// How step 0 pins compression output to `shared[0]` (L4c isolation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OutPinMode {
    /// `enforce_words_eq_shared(computed out_words, shared)` — fails verify today.
    DirectWords,
    /// `out_words == bytes` then `enforce_bytes_eq_shared(bytes, shared)` — core-style path.
    IndirectBytes,
    /// `out_words == alloc(expected)` then `enforce_words_eq_shared(alloc, shared)`.
    MirrorAllocWords,
}

/// Parameterized step for out-pin strategy tests (step 0 only pins when `pin_mode` set).
#[derive(Clone, Debug)]
struct BoundStyleStepPinOutMode {
    step_index: usize,
    input: StepInput,
    link_digests: Vec<[u8; 32]>,
    pin_mode: Option<OutPinMode>,
    _p: PhantomData<Scalar>,
}

impl BoundStyleStepPinOutMode {
    fn new(
        step_index: usize,
        input: StepInput,
        link_digests: Vec<[u8; 32]>,
        pin_mode: Option<OutPinMode>,
    ) -> Self {
        Self {
            step_index,
            input,
            link_digests,
            pin_mode,
            _p: PhantomData,
        }
    }
}

impl SpartanCircuit<E> for BoundStyleStepPinOutMode {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_digests(cs, "step_shared", &self.link_digests)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let h_words = state_bytes_to_words(&self.input.h_in)
            .iter()
            .enumerate()
            .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)))
            .collect::<Result<Vec<_>, _>>()?;
        let out_words = synthesize_compression_for_fold_h_words(
            cs.namespace(|| "compress"),
            &h_words,
            &self.input.block,
        )?;
        let h_out = self.input.h_out;
        // Indirect/mirror: every instance ties `out_words` to `input.h_out` (equalize-safe).
        if matches!(
            self.pin_mode,
            Some(OutPinMode::IndirectBytes) | Some(OutPinMode::MirrorAllocWords)
        ) {
            enforce_digest_bytes_eq_words(
                cs.namespace(|| "h_out_row_eq"),
                "h_out",
                &out_words,
                &h_out,
            )?;
        }
        if let Some(mode) = self.pin_mode {
            let link_ix = self.step_index.min(self.link_digests.len().saturating_sub(1));
            match mode {
                OutPinMode::DirectWords if self.step_index == 0 => {
                    enforce_words_eq_shared(
                        cs.namespace(|| "link_out_direct"),
                        "h_out",
                        &out_words,
                        link_shared_slice(shared, 0),
                    )?;
                }
                OutPinMode::IndirectBytes if self.step_index < self.link_digests.len() => {
                    enforce_bytes_eq_shared(
                        cs.namespace(|| format!("link_out_bytes_{}", self.step_index)),
                        "link",
                        &h_out,
                        link_shared_slice(shared, self.step_index),
                    )?;
                }
                OutPinMode::IndirectBytes => {
                    // Padding instance: reuse last link slot + same bytes as row (duplicate step).
                    let last = self.link_digests.len() - 1;
                    enforce_bytes_eq_shared(
                        cs.namespace(|| "link_out_bytes_pad"),
                        "link",
                        &h_out,
                        link_shared_slice(shared, last),
                    )?;
                }
                OutPinMode::DirectWords => {}
                OutPinMode::MirrorAllocWords => {
                    let mirror: Vec<UInt32> = state_bytes_to_words(&h_out)
                        .iter()
                        .enumerate()
                        .map(|(i, &w)| {
                            UInt32::alloc(cs.namespace(|| format!("mirror_w{i}")), Some(w))
                        })
                        .collect::<Result<_, _>>()?;
                    enforce_words_eq_shared(
                        cs.namespace(|| "link_out_mirror"),
                        "link",
                        &mirror,
                        link_shared_slice(shared, link_ix),
                    )?;
                }
            }
        }
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

fn bound_style_steps_pin_out_mode(
    inputs: &[StepInput],
    digests: Vec<[u8; 32]>,
    pin_mode: OutPinMode,
) -> Vec<BoundStyleStepPinOutMode> {
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            let mode = if i == 0 { Some(pin_mode) } else { None };
            BoundStyleStepPinOutMode::new(i, input.clone(), digests.clone(), mode)
        })
        .collect()
}

/// Every step instance runs the same out-pin layout (required for Spartan2 precommitted equalize).
fn bound_style_steps_pin_out_full_layout(
    inputs: &[StepInput],
    digests: Vec<[u8; 32]>,
    pin_mode: OutPinMode,
) -> Vec<BoundStyleStepPinOutMode> {
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            BoundStyleStepPinOutMode::new(i, input.clone(), digests.clone(), Some(pin_mode))
        })
        .collect()
}

/// L4b-in: only `step_index == 1` reads `shared[0]` as `h_in`; no out-pins on any step.
#[derive(Clone, Debug)]
struct BoundStyleStepSharedInOnly {
    step_index: usize,
    input: StepInput,
    link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl BoundStyleStepSharedInOnly {
    fn new(step_index: usize, input: StepInput, link_digests: Vec<[u8; 32]>) -> Self {
        Self {
            step_index,
            input,
            link_digests,
            _p: PhantomData,
        }
    }
}

impl SpartanCircuit<E> for BoundStyleStepSharedInOnly {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_digests(cs, "step_shared", &self.link_digests)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let h_words = if self.step_index == 1 {
            u32_words_from_shared(
                cs.namespace(|| "h_in_from_shared"),
                "h_in",
                link_shared_slice(shared, 0),
            )?
        } else {
            state_bytes_to_words(&self.input.h_in)
                .iter()
                .enumerate()
                .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)))
                .collect::<Result<Vec<_>, _>>()?
        };
        let _out = synthesize_compression_for_fold_h_words(
            cs.namespace(|| "compress"),
            &h_words,
            &self.input.block,
        )?;
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

fn bound_style_steps_pin_out_single(
    inputs: &[StepInput],
    digests: Vec<[u8; 32]>,
) -> Vec<BoundStyleStepPinOutSingle> {
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| BoundStyleStepPinOutSingle::new(i, input.clone(), digests.clone()))
        .collect()
}

fn bound_style_steps_shared_in_only(
    inputs: &[StepInput],
    digests: Vec<[u8; 32]>,
) -> Vec<BoundStyleStepSharedInOnly> {
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| BoundStyleStepSharedInOnly::new(i, input.clone(), digests.clone()))
        .collect()
}

fn core_alloc_only(digests: Vec<[u8; 32]>) -> CoreSharedAllocOnly {
    CoreSharedAllocOnly {
        link_digests: digests,
        _p: PhantomData,
    }
}

/// Core: same `shared()` layout as bound steps, but **no** glue constraints (SHA padding only).
#[derive(Clone, Debug)]
struct CoreSharedAllocOnly {
    link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for CoreSharedAllocOnly {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_digests(cs, "core_shared", &self.link_digests)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let input_bits: Vec<Boolean> = (0..512)
            .map(|i| {
                AllocatedBit::alloc(cs.namespace(|| format!("core bit {i}")), Some(false))
                    .map(Boolean::from)
            })
            .collect::<Result<_, _>>()?;
        let current_hash: Vec<UInt32> = SHA256_IV.iter().map(|&v| UInt32::constant(v)).collect();
        let _next = sha256_compression_function(
            cs.namespace(|| "core sha256 compression"),
            &input_bits,
            &current_hash,
        )?;
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

fn sample_shared_values(n: usize, seed: u64) -> Vec<Scalar> {
    (0..n)
        .map(|i| Scalar::from(seed + i as u64 + 1))
        .collect()
}

#[derive(Debug)]
struct PhaseResult {
    setup_ok: bool,
    prep_ok: bool,
    prove_ok: bool,
    verify_ok: bool,
    verify_err: Option<String>,
}

fn run_neutronnova<S, C>(name: &str, step_proto: &S, core_proto: &C, steps: &[S], core: &C) -> PhaseResult
where
    S: SpartanCircuit<E>,
    C: SpartanCircuit<E>,
{
    eprintln!("\n=== {name} ===");

    let setup = NeutronNovaZkSNARK::<E>::setup(step_proto, core_proto, NUM_STEPS);
    let Ok((pk, vk)) = setup else {
        eprintln!("SETUP FAILED: {}", setup.err().expect("err"));
        return PhaseResult {
            setup_ok: false,
            prep_ok: false,
            prove_ok: false,
            verify_ok: false,
            verify_err: None,
        };
    };
    eprintln!("setup: ok");

    let prep = NeutronNovaZkSNARK::<E>::prep_prove(&pk, steps, core, true);
    let Ok(prep) = prep else {
        eprintln!("PREP_PROVE FAILED: {prep:?}");
        return PhaseResult {
            setup_ok: true,
            prep_ok: false,
            prove_ok: false,
            verify_ok: false,
            verify_err: None,
        };
    };
    eprintln!("prep_prove: ok");

    let prove = NeutronNovaZkSNARK::<E>::prove(&pk, steps, core, prep, true);
    let Ok((proof, _prep)) = prove else {
        eprintln!("PROVE FAILED: {prove:?}");
        return PhaseResult {
            setup_ok: true,
            prep_ok: true,
            prove_ok: false,
            verify_ok: false,
            verify_err: None,
        };
    };
    eprintln!("prove: ok");

    let verify = proof.verify(&vk, NUM_STEPS);
    match verify {
        Ok(_) => {
            eprintln!("verify: ok");
            PhaseResult {
                setup_ok: true,
                prep_ok: true,
                prove_ok: true,
                verify_ok: true,
                verify_err: None,
            }
        }
        Err(e) => {
            eprintln!("verify: FAILED — {e}");
            PhaseResult {
                setup_ok: true,
                prep_ok: true,
                prove_ok: true,
                verify_ok: false,
                verify_err: Some(format!("{e}")),
            }
        }
    }
}

// --- Ladder tests ----------------------------------------------------------------------------

/// Control: `shared() → []` — identical circuits to `neutronnova_replica`.
#[test]
fn ladder_0_empty_shared_baseline() {
    let step_proto = ReplicaStepCircuit::new([0u8; BLOCK_BYTES]);
    let core_proto = ReplicaCoreCircuit::new();
    let steps: Vec<_> = (0..NUM_STEPS)
        .map(|i| ReplicaStepCircuit::new([i as u8; BLOCK_BYTES]))
        .collect();
    let r = run_neutronnova("L0 empty shared", &step_proto, &core_proto, &steps, &core_proto);
    assert!(r.verify_ok, "baseline must verify: {r:?}");
}

/// One shared field element; step and core both reference it.
#[test]
fn ladder_1_one_shared_scalar() {
    let vals = sample_shared_values(1, 100);
    let step_proto = DebugStepCircuit::new(vals.clone(), [0u8; BLOCK_BYTES]);
    let core_proto = DebugCoreCircuit::new(vals.clone());
    let steps: Vec<_> = (0..NUM_STEPS)
        .map(|i| DebugStepCircuit::new(vals.clone(), [i as u8; BLOCK_BYTES]))
        .collect();
    let r = run_neutronnova("L1 one shared scalar", &step_proto, &core_proto, &steps, &core_proto);
    eprintln!("L1 result: {r:?}");
    assert!(r.verify_ok, "scalar shared witness should verify: {r:?}");
}

/// Eight shared scalars (same count as one SHA-256 link digest in bound.rs).
#[test]
fn ladder_2_eight_shared_scalars() {
    let vals = sample_shared_values(8, 200);
    let step_proto = DebugStepCircuit::new(vals.clone(), [0u8; BLOCK_BYTES]);
    let core_proto = DebugCoreCircuit::new(vals.clone());
    let steps: Vec<_> = (0..NUM_STEPS)
        .map(|i| DebugStepCircuit::new(vals.clone(), [i as u8; BLOCK_BYTES]))
        .collect();
    let r = run_neutronnova("L2 eight shared (1 digest)", &step_proto, &core_proto, &steps, &core_proto);
    eprintln!("L2 result: {r:?}");
}

/// Shared allocated but precommitted does NOT reference shared (isolate PCS vs constraints).
#[derive(Clone, Debug)]
struct SharedAllocOnlyStep {
    shared_values: Vec<Scalar>,
    block: [u8; BLOCK_BYTES],
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for SharedAllocOnlyStep {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_shared(cs.namespace(|| "shared"), "link", &self.shared_values)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let input_bits: Vec<Boolean> = self
            .block
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8 == 1u8))
            .enumerate()
            .map(|(i, b)| {
                AllocatedBit::alloc(cs.namespace(|| format!("block bit {i}")), Some(b))
                    .map(Boolean::from)
            })
            .collect::<Result<_, _>>()?;

        let current_hash: Vec<UInt32> = SHA256_IV.iter().map(|&v| UInt32::constant(v)).collect();
        let _next = sha256_compression_function(
            cs.namespace(|| "sha256 compression"),
            &input_bits,
            &current_hash,
        )?;

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct SharedAllocOnlyCore {
    shared_values: Vec<Scalar>,
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for SharedAllocOnlyCore {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_shared(cs.namespace(|| "shared"), "link", &self.shared_values)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let input_bits: Vec<Boolean> = (0..512)
            .map(|i| {
                AllocatedBit::alloc(cs.namespace(|| format!("core bit {i}")), Some(false))
                    .map(Boolean::from)
            })
            .collect::<Result<_, _>>()?;

        let current_hash: Vec<UInt32> = SHA256_IV.iter().map(|&v| UInt32::constant(v)).collect();
        let _next = sha256_compression_function(
            cs.namespace(|| "core sha256 compression"),
            &input_bits,
            &current_hash,
        )?;

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

/// 24 shared scalars + scalar equality core (no bit decomposition) — control for L4.
#[test]
fn ladder_4a_multi_link_scalar_equality_core() {
    let digests = sample_link_digests(NUM_STEPS - 1, 0x30);
    let scalars: Vec<Scalar> = digests
        .iter()
        .flat_map(|d| {
            sphincs_circuit::sha256_compress::state_bytes_to_words(d)
                .into_iter()
                .map(|w| Scalar::from(w as u64))
        })
        .collect();
    let step_proto = DebugStepCircuit::new(scalars.clone(), [0u8; BLOCK_BYTES]);
    let core_proto = DebugCoreCircuit::new(scalars.clone());
    let steps: Vec<_> = (0..NUM_STEPS)
        .map(|i| DebugStepCircuit::new(scalars.clone(), [i as u8; BLOCK_BYTES]))
        .collect();
    let r = run_neutronnova(
        "L4a 24 shared scalar-eq core",
        &step_proto,
        &core_proto,
        &steps,
        &core_proto,
    );
    eprintln!("L4a result: {r:?}");
    assert!(r.verify_ok, "scalar equality at digest width should verify: {r:?}");
}

/// Production step shared pins (`FoldStepBoundCircuit`) + core that only allocates shared (no glue).
///
/// Isolates step-side `u32_words_from_shared` / `enforce_words_eq_shared` under NeutronNova folding.
#[test]
fn ladder_4b_step_shared_pin_chain_core_alloc_only() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let steps = bound_steps_from_inputs(&inputs, NUM_STEPS, digests.clone());
    let core = CoreSharedAllocOnly {
        link_digests: digests.clone(),
        _p: PhantomData,
    };
    let r = run_neutronnova(
        "L4b step bound chain + core alloc-only",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4b result: {r:?}");
}

/// Only step 0 pins `h_out → shared[0]` (`enforce_words_eq_shared`); steps 1–3 ignore shared.
#[test]
fn ladder_4b_single_step0_out_pin_only() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let steps = bound_style_steps_pin_out_single(&inputs, digests.clone());
    let core = core_alloc_only(digests);
    let r = run_neutronnova(
        "L4b-single step0 out-pin only",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4b-single result: {r:?}");
}

/// Dump VC + step R1CS row maps (where row 132 lives vs OUT-pin rows).
#[test]
fn ladder_dump_row_map_l4b_single() {
    use sphincs_circuit::shared_link::DIGEST_WORDS;

    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let steps = bound_style_steps_pin_out_single(&inputs, digests.clone());
    let core = core_alloc_only(digests.clone());

    let setup = NeutronNovaZkSNARK::<E>::setup(&steps[0], &core, NUM_STEPS).expect("setup");
    let (pk, _vk) = setup;

    let (num_cons, num_shared, num_precommitted, num_rest) = pk.debug_step_dims();
    let num_vars = num_shared + num_precommitted + num_rest;
    let (num_rounds_b, num_rounds_x, num_rounds_y) = pk.debug_neutronnova_round_params(NUM_STEPS);

    eprintln!("\n╔══════════════════════════════════════════════════════════════════╗");
    eprintln!("║  TWO SEPARATE R1CS MATRICES (do not mix row indices)            ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════╝");

    eprintln!("\n=== MATRIX A: STEP R1CS (S_step) — prototype step_index=0 ===");
    eprintln!(
        "  num_cons={num_cons}  num_vars={num_vars}  (shared={num_shared} precommitted={num_precommitted} rest={num_rest})"
    );
    eprintln!("  witness layout: W[0..{num_shared}) = shared bus (3 links × 8 u32)");

    let _ = spartan2::debug_dump_spartan_circuit_row_sections("  step phases", &steps[0]);
    eprintln!("  precommitted sub-sections (step 0 prototype):");
    steps[0]
        .debug_dump_precommitted_milestones()
        .expect("milestones");
    eprintln!("  precommitted sub-sections (step 1 — no OUT-pin in source, same shape):");
    steps[1]
        .debug_dump_precommitted_milestones()
        .expect("milestones");

    let S_reg = pk.debug_step_shape_regular();
    let out_pin_rows: Vec<usize> = spartan2::debug_rows_touching_columns(&S_reg, 0, DIGEST_WORDS);
    eprintln!(
        "\n  OUT-pin rows = constraints touching shared link-0 columns W[0..{DIGEST_WORDS}):"
    );
    eprintln!("    row indices: {out_pin_rows:?}  (NOT row 132 — different matrix)");
    if let Some(&r) = out_pin_rows.first() {
        spartan2::debug_log_r1cs_row(&S_reg, r, "example OUT-pin row (num_eq_u32 per word)");
    }

    eprintln!("\n=== MATRIX B: VC R1CS (vc_shape_regular) — NeutronNova verifier ===");
    eprintln!(
        "  num_cons={}  (relaxed Spartan runs on this matrix; row 132 is HERE)",
        pk.debug_vc_num_cons()
    );
    let _ = spartan2::debug_dump_vc_row_sections::<E>(num_rounds_b, num_rounds_x, num_rounds_y);
    spartan2::debug_log_r1cs_row(pk.debug_vc_shape_regular(), 132, "VC row 132 (Horner, not OUT-pin)");

    eprintln!("\n=== prove run (step[1] should fail is_sat — OUT-pin rows in shape, absent in synth) ===");
    let _ = run_neutronnova(
        "L4b-single row map",
        &steps[0],
        &core,
        &steps,
        &core,
    );
}

/// Side-by-side VC row-132 witness dump: L4b-single (fails) vs L4b-in (passes).
#[test]
fn ladder_4b_compare_vc_horner_row_single_vs_in() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let core = core_alloc_only(digests.clone());

    let steps_single = bound_style_steps_pin_out_single(&inputs, digests.clone());
    let _ = run_neutronnova(
        "L4b-single (compare)",
        &steps_single[0],
        &core,
        &steps_single,
        &core,
    );

    let steps_in = bound_style_steps_shared_in_only(&inputs, digests);
    let r_in = run_neutronnova(
        "L4b-in (compare)",
        &steps_in[0],
        &core,
        &steps_in,
        &core,
    );
    assert!(
        r_in.verify_ok,
        "L4b-in baseline should verify in compare test: {r_in:?}"
    );
}

/// Only step 1 reads `shared[0]` as `h_in` (`u32_words_from_shared`); no out-pins.
#[test]
fn ladder_4b_in_step1_shared_h_in_only() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let steps = bound_style_steps_shared_in_only(&inputs, digests.clone());
    let core = core_alloc_only(digests);
    let r = run_neutronnova(
        "L4b-in step1 shared h_in only",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4b-in result: {r:?}");
    assert!(r.verify_ok, "shared h_in on step 1 should verify: {r:?}");
}

/// Out-pin via `enforce_digest_bytes_eq_words` + `enforce_bytes_eq_shared` (no direct gadget→shared).
/// Equalized layout on all step instances + padded last row (see `pad_last_step_duplicate_prev`).
#[test]
fn ladder_4c_out_pin_indirect_bytes() {
    let (mut inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    pad_last_step_duplicate_prev(&mut inputs);
    let steps =
        bound_style_steps_pin_out_full_layout(&inputs, digests.clone(), OutPinMode::IndirectBytes);
    let core = core_alloc_only(digests);
    let r = run_neutronnova(
        "L4c indirect bytes out-pin (full layout)",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4c-indirect result: {r:?}");
    assert!(r.prep_ok, "equalized indirect layout should prep_prove: {r:?}");
}

/// Out-pin via allocated `UInt32` mirror (gadget→mirror, mirror→shared).
#[test]
fn ladder_4c_out_pin_mirror_alloc_words() {
    let (mut inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    pad_last_step_duplicate_prev(&mut inputs);
    let steps = bound_style_steps_pin_out_full_layout(
        &inputs,
        digests.clone(),
        OutPinMode::MirrorAllocWords,
    );
    let core = core_alloc_only(digests);
    let r = run_neutronnova(
        "L4c mirror alloc out-pin (full layout)",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4c-mirror result: {r:?}");
    assert!(r.prep_ok, "equalized mirror layout should prep_prove: {r:?}");
}

/// Step-0-only pin (unequal precommitted) — documents prep_prove failure mode.
#[test]
fn ladder_4c_out_pin_indirect_bytes_step0_only() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let steps = bound_style_steps_pin_out_mode(&inputs, digests.clone(), OutPinMode::IndirectBytes);
    let core = core_alloc_only(digests);
    let r = run_neutronnova(
        "L4c indirect bytes step0 only (unequal)",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4c-indirect-step0-only result: {r:?}");
    assert!(!r.prep_ok, "unequal layout should fail prep_prove: {r:?}");
}

fn u32_from_uint32_bits(word: &UInt32) -> u32 {
    let mut w = 0u32;
    for (j, bit) in word.clone().into_bits().iter().enumerate() {
        if bit.get_value() == Some(true) {
            w |= 1 << j;
        }
    }
    w
}

/// Local R1CS: shared + step-0 out-pin (`enforce_words_eq_shared`) must be satisfiable.
#[test]
fn local_r1cs_l4b_single_step0_out_pin_satisfied() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let input = &inputs[0];
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let shared = alloc_all_digests(&mut cs, "shared", &digests).expect("shared");
    let h_words: Vec<UInt32> = state_bytes_to_words(&input.h_in)
        .iter()
        .enumerate()
        .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)).unwrap())
        .collect();
    let out_words = synthesize_compression_for_fold_h_words(
        &mut cs,
        &h_words,
        &input.block,
    )
    .expect("compress");
    enforce_words_eq_shared(
        &mut cs,
        "link_out_0",
        &out_words,
        link_shared_slice(&shared, 0),
    )
    .expect("out-pin");
    assert!(
        cs.is_satisfied(),
        "local step0 out-pin: {:?}",
        cs.which_is_unsatisfied()
    );
}

/// Local R1CS: step-1 `u32_words_from_shared` + compress must be satisfiable.
#[test]
fn local_r1cs_l4b_in_step1_shared_h_in_satisfied() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let input = &inputs[1];
    let mut cs = TestConstraintSystem::<Scalar>::new();
    let shared = alloc_all_digests(&mut cs, "shared", &digests).expect("shared");
    let h_words = u32_words_from_shared(
        &mut cs,
        "h_in_from_shared",
        link_shared_slice(&shared, 0),
    )
    .expect("h_in");
    let _out = synthesize_compression_for_fold_h_words(&mut cs, &h_words, &input.block).expect("compress");
    assert!(
        cs.is_satisfied(),
        "local step1 shared h_in: {:?}",
        cs.which_is_unsatisfied()
    );
}

/// L4d: scalar `aux == shared[i]` with **no** wire to gadget `UInt32` (unsound; isolation only).
#[derive(Clone, Debug)]
struct BoundStyleStepPinOutScalarDecoupled {
    step_index: usize,
    input: StepInput,
    link_digests: Vec<[u8; 32]>,
    /// When true, every step instance pins its link slot (equalized layout).
    pin_all_links: bool,
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for BoundStyleStepPinOutScalarDecoupled {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_digests(cs, "step_shared", &self.link_digests)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let h_words: Vec<UInt32> = state_bytes_to_words(&self.input.h_in)
            .iter()
            .enumerate()
            .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)))
            .collect::<Result<_, _>>()?;
        let out_words = synthesize_compression_for_fold_h_words(
            cs.namespace(|| "compress"),
            &h_words,
            &self.input.block,
        )?;
        let pin = self.pin_all_links || self.step_index == 0;
        if pin {
            let link_ix = if self.pin_all_links {
                self.step_index
                    .min(self.link_digests.len().saturating_sub(1))
            } else {
                0
            };
            for (i, (word, shared_limb)) in out_words
                .iter()
                .zip(link_shared_slice(shared, link_ix).iter())
                .enumerate()
            {
                let w = u32_from_uint32_bits(word);
                let aux = AllocatedNum::alloc(cs.namespace(|| format!("out_aux_{i}")), || {
                    Ok(Scalar::from(w as u64))
                })?;
                enforce_equal(
                    cs.namespace(|| format!("out_scalar_eq_{i}")),
                    "eq",
                    &aux,
                    shared_limb,
                )?;
            }
        }
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

fn bound_style_steps_scalar_decoupled(
    inputs: &[StepInput],
    digests: Vec<[u8; 32]>,
    pin_all_links: bool,
) -> Vec<BoundStyleStepPinOutScalarDecoupled> {
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| BoundStyleStepPinOutScalarDecoupled {
            step_index: i,
            input: input.clone(),
            link_digests: digests.clone(),
            pin_all_links,
            _p: PhantomData,
        })
        .collect()
}

/// Fold gadget + scalar `aux == shared[i]` for **all** shared limbs (like L4a, not one link).
#[derive(Clone, Debug)]
struct BoundStyleStepFoldGadgetAllSharedScalar {
    input: StepInput,
    link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for BoundStyleStepFoldGadgetAllSharedScalar {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_digests(cs, "step_shared", &self.link_digests)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let h_words: Vec<UInt32> = state_bytes_to_words(&self.input.h_in)
            .iter()
            .enumerate()
            .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)))
            .collect::<Result<_, _>>()?;
        let _out = synthesize_compression_for_fold_h_words(
            cs.namespace(|| "compress"),
            &h_words,
            &self.input.block,
        )?;
        for (i, s) in shared.iter().enumerate() {
            let aux = AllocatedNum::alloc(cs.namespace(|| format!("aux_{i}")), || {
                s.get_value().ok_or(SynthesisError::AssignmentMissing)
            })?;
            enforce_equal(cs.namespace(|| format!("eq_{i}")), "eq", &aux, s)?;
        }
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

/// L4e plus step-0 `enforce_words_eq_shared` on compression output (partial out-pin).
#[derive(Clone, Debug)]
struct BoundStyleStepAllSharedPlusOutPin {
    step_index: usize,
    input: StepInput,
    link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for BoundStyleStepAllSharedPlusOutPin {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }
    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_digests(cs, "step_shared", &self.link_digests)
    }
    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let h_words: Vec<UInt32> = state_bytes_to_words(&self.input.h_in)
            .iter()
            .enumerate()
            .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)))
            .collect::<Result<_, _>>()?;
        let out_words = synthesize_compression_for_fold_h_words(
            cs.namespace(|| "compress"),
            &h_words,
            &self.input.block,
        )?;
        for (i, s) in shared.iter().enumerate() {
            let aux = AllocatedNum::alloc(cs.namespace(|| format!("aux_{i}")), || {
                s.get_value().ok_or(SynthesisError::AssignmentMissing)
            })?;
            enforce_equal(cs.namespace(|| format!("eq_{i}")), "eq", &aux, s)?;
        }
        if self.step_index == 0 {
            enforce_words_eq_shared(
                cs.namespace(|| "link_out_0"),
                "h_out",
                &out_words,
                link_shared_slice(shared, 0),
            )?;
        }
        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }
    fn num_challenges(&self) -> usize {
        0
    }
    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

#[test]
fn ladder_4f_all_shared_scalar_eq_plus_step0_out_pin() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let steps: Vec<_> = inputs
        .iter()
        .enumerate()
        .map(|(i, input)| BoundStyleStepAllSharedPlusOutPin {
            step_index: i,
            input: input.clone(),
            link_digests: digests.clone(),
            _p: PhantomData,
        })
        .collect();
    let core = core_alloc_only(digests.clone());
    let r = run_neutronnova(
        "L4f all-shared eq + step0 out-pin",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4f result: {r:?}");
}

#[test]
fn ladder_4e_fold_gadget_all_shared_scalar_eq() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let steps: Vec<_> = inputs
        .iter()
        .map(|input| BoundStyleStepFoldGadgetAllSharedScalar {
            input: input.clone(),
            link_digests: digests.clone(),
            _p: PhantomData,
        })
        .collect();
    let core = core_alloc_only(digests.clone());
    let r = run_neutronnova(
        "L4e fold gadget + all shared scalar eq",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4e result: {r:?}");
}

/// Full layout: every step pins one link slot via decoupled scalar (no gadget wire).
#[test]
fn ladder_4d_scalar_decoupled_out_pin_full_layout() {
    let (mut inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    pad_last_step_duplicate_prev(&mut inputs);
    let steps = bound_style_steps_scalar_decoupled(&inputs, digests.clone(), true);
    let core = core_alloc_only(digests.clone());
    let r = run_neutronnova(
        "L4d scalar decoupled full layout",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4d-full result: {r:?}");
}

/// Step 0 only: decoupled scalar out-pin (same shape as L4b-single).
#[test]
fn ladder_4d_scalar_decoupled_out_pin_step0_only() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let steps = bound_style_steps_scalar_decoupled(&inputs, digests.clone(), false);
    let core = core_alloc_only(digests);
    let r = run_neutronnova(
        "L4d scalar decoupled step0 only",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4d-step0-only result: {r:?}");
}

/// One link (8 shared), step 0 out-pin only — minimal `enforce_words_eq_shared` under fold.
#[test]
fn ladder_4b_out_one_link_step0_only() {
    let (inputs, _) = build_consistent_bound_batch(NUM_STEPS);
    let digests = vec![inputs[0].h_out];
    let steps = bound_style_steps_pin_out_single(&inputs, digests.clone());
    let core = core_alloc_only(digests);
    let r = run_neutronnova(
        "L4b-out one link step0",
        &steps[0],
        &core,
        &steps,
        &core,
    );
    eprintln!("L4b-out-one-link result: {r:?}");
}

/// Three digest links (24 shared scalars) + `enforce_bytes_eq_shared` core — mirrors `FoldCoreBoundCircuit`.
#[test]
fn ladder_4_bound_style_core_bit_decomposition() {
    let digests = sample_link_digests(NUM_STEPS - 1, 0x40);
    let step_proto = BoundStyleStepAllocOnly {
        block: [0u8; BLOCK_BYTES],
        link_digests: digests.clone(),
        _p: PhantomData,
    };
    let core_proto = BoundStyleCoreCircuit {
        link_digests: digests.clone(),
        _p: PhantomData,
    };
    let steps: Vec<_> = (0..NUM_STEPS)
        .map(|i| BoundStyleStepAllocOnly {
            block: [i as u8; BLOCK_BYTES],
            link_digests: digests.clone(),
            _p: PhantomData,
        })
        .collect();
    let r = run_neutronnova(
        "L4 bound-style core (bit decomp, 3 links)",
        &step_proto,
        &core_proto,
        &steps,
        &core_proto,
    );
    eprintln!("L4 result: {r:?}");
}

/// Full `FoldStepBoundCircuit` + `FoldCoreBoundCircuit` with a consistent chained batch.
#[test]
fn ladder_5_production_bound_circuits_synthetic() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let steps = bound_steps_from_inputs(&inputs, NUM_STEPS, digests.clone());
    let core = FoldCoreBoundCircuit::new(digests);
    let r = run_neutronnova("L5 production bound circuits", &steps[0], &core, &steps, &core);
    eprintln!("L5 result: {r:?}");
}

#[test]
fn ladder_3_shared_allocated_but_unused_in_precommitted() {
    let vals = sample_shared_values(1, 300);
    let step_proto = SharedAllocOnlyStep {
        shared_values: vals.clone(),
        block: [0u8; BLOCK_BYTES],
        _p: PhantomData,
    };
    let core_proto = SharedAllocOnlyCore {
        shared_values: vals.clone(),
        _p: PhantomData,
    };
    let steps: Vec<_> = (0..NUM_STEPS)
        .map(|i| SharedAllocOnlyStep {
            shared_values: vals.clone(),
            block: [i as u8; BLOCK_BYTES],
            _p: PhantomData,
        })
        .collect();
    let r = run_neutronnova(
        "L3 shared alloc only (no precommitted refs)",
        &step_proto,
        &core_proto,
        &steps,
        &core_proto,
    );
    eprintln!("L3 result: {r:?}");
}

/// Run full ladder in one test for copy-paste debugging sessions.
#[test]
fn ladder_summary_all_phases() {
    eprintln!("\n######## NeutronNova shared-witness debug ladder ########\n");

    let l0 = {
        let step_proto = ReplicaStepCircuit::new([0u8; BLOCK_BYTES]);
        let core_proto = ReplicaCoreCircuit::new();
        let steps: Vec<_> = (0..NUM_STEPS)
            .map(|i| ReplicaStepCircuit::new([i as u8; BLOCK_BYTES]))
            .collect();
        run_neutronnova("L0", &step_proto, &core_proto, &steps, &core_proto)
    };

    let vals1 = sample_shared_values(1, 100);
    let l1 = {
        let step_proto = DebugStepCircuit::new(vals1.clone(), [0u8; BLOCK_BYTES]);
        let core_proto = DebugCoreCircuit::new(vals1.clone());
        let steps: Vec<_> = (0..NUM_STEPS)
            .map(|i| DebugStepCircuit::new(vals1.clone(), [i as u8; BLOCK_BYTES]))
            .collect();
        run_neutronnova("L1", &step_proto, &core_proto, &steps, &core_proto)
    };

    let vals8 = sample_shared_values(8, 200);
    let l2 = {
        let step_proto = DebugStepCircuit::new(vals8.clone(), [0u8; BLOCK_BYTES]);
        let core_proto = DebugCoreCircuit::new(vals8.clone());
        let steps: Vec<_> = (0..NUM_STEPS)
            .map(|i| DebugStepCircuit::new(vals8.clone(), [i as u8; BLOCK_BYTES]))
            .collect();
        run_neutronnova("L2", &step_proto, &core_proto, &steps, &core_proto)
    };

    let vals3 = sample_shared_values(1, 300);
    let l3 = {
        let step_proto = SharedAllocOnlyStep {
            shared_values: vals3.clone(),
            block: [0u8; BLOCK_BYTES],
            _p: PhantomData,
        };
        let core_proto = SharedAllocOnlyCore {
            shared_values: vals3.clone(),
            _p: PhantomData,
        };
        let steps: Vec<_> = (0..NUM_STEPS)
            .map(|i| SharedAllocOnlyStep {
                shared_values: vals3.clone(),
                block: [i as u8; BLOCK_BYTES],
                _p: PhantomData,
            })
            .collect();
        run_neutronnova("L3", &step_proto, &core_proto, &steps, &core_proto)
    };

    eprintln!("\n######## Summary ########");
    eprintln!("L0 empty shared:     verify_ok = {}", l0.verify_ok);
    eprintln!("L1 one shared:       verify_ok = {} err = {:?}", l1.verify_ok, l1.verify_err);
    eprintln!("L2 eight shared:     verify_ok = {} err = {:?}", l2.verify_ok, l2.verify_err);
    eprintln!("L3 alloc-only:       verify_ok = {} err = {:?}", l3.verify_ok, l3.verify_err);

    let digests4a = sample_link_digests(NUM_STEPS - 1, 0x30);
    let scalars4a: Vec<Scalar> = digests4a
        .iter()
        .flat_map(|d| {
            sphincs_circuit::sha256_compress::state_bytes_to_words(d)
                .into_iter()
                .map(|w| Scalar::from(w as u64))
        })
        .collect();
    let l4a = {
        let step_proto = DebugStepCircuit::new(scalars4a.clone(), [0u8; BLOCK_BYTES]);
        let core_proto = DebugCoreCircuit::new(scalars4a.clone());
        let steps: Vec<_> = (0..NUM_STEPS)
            .map(|i| DebugStepCircuit::new(scalars4a.clone(), [i as u8; BLOCK_BYTES]))
            .collect();
        run_neutronnova("L4a", &step_proto, &core_proto, &steps, &core_proto)
    };

    let digests4 = sample_link_digests(NUM_STEPS - 1, 0x40);
    let l4 = {
        let step_proto = BoundStyleStepAllocOnly {
            block: [0u8; BLOCK_BYTES],
            link_digests: digests4.clone(),
            _p: PhantomData,
        };
        let core_proto = BoundStyleCoreCircuit {
            link_digests: digests4.clone(),
            _p: PhantomData,
        };
        let steps: Vec<_> = (0..NUM_STEPS)
            .map(|i| BoundStyleStepAllocOnly {
                block: [i as u8; BLOCK_BYTES],
                link_digests: digests4.clone(),
                _p: PhantomData,
            })
            .collect();
        run_neutronnova("L4", &step_proto, &core_proto, &steps, &core_proto)
    };

    let (inputs5, digests5) = build_consistent_bound_batch(NUM_STEPS);
    let l4b = {
        let steps = bound_steps_from_inputs(&inputs5, NUM_STEPS, digests5.clone());
        let core = core_alloc_only(digests5.clone());
        run_neutronnova("L4b", &steps[0], &core, &steps, &core)
    };

    let l4b_single = {
        let steps = bound_style_steps_pin_out_single(&inputs5, digests5.clone());
        let core = core_alloc_only(digests5.clone());
        run_neutronnova("L4b-single", &steps[0], &core, &steps, &core)
    };

    let l4b_in = {
        let steps = bound_style_steps_shared_in_only(&inputs5, digests5.clone());
        let core = core_alloc_only(digests5.clone());
        run_neutronnova("L4b-in", &steps[0], &core, &steps, &core)
    };

    let l4b_out_1 = {
        let digests1 = vec![inputs5[0].h_out];
        let steps = bound_style_steps_pin_out_single(&inputs5, digests1.clone());
        let core = core_alloc_only(digests1);
        run_neutronnova("L4b-out-1link", &steps[0], &core, &steps, &core)
    };

    let l5 = {
        let steps = bound_steps_from_inputs(&inputs5, NUM_STEPS, digests5.clone());
        let core = FoldCoreBoundCircuit::new(digests5);
        run_neutronnova("L5", &steps[0], &core, &steps, &core)
    };

    let (mut inputs4c, digests4c) = build_consistent_bound_batch(NUM_STEPS);
    pad_last_step_duplicate_prev(&mut inputs4c);
    let l4c_indirect = {
        let steps = bound_style_steps_pin_out_full_layout(
            &inputs4c,
            digests4c.clone(),
            OutPinMode::IndirectBytes,
        );
        let core = core_alloc_only(digests4c.clone());
        run_neutronnova("L4c-indirect", &steps[0], &core, &steps, &core)
    };
    let l4c_mirror = {
        let steps = bound_style_steps_pin_out_full_layout(
            &inputs4c,
            digests4c.clone(),
            OutPinMode::MirrorAllocWords,
        );
        let core = core_alloc_only(digests4c);
        run_neutronnova("L4c-mirror", &steps[0], &core, &steps, &core)
    };

    eprintln!("L4a scalar 24:       verify_ok = {}", l4a.verify_ok);
    eprintln!("L4 bound core:       verify_ok = {} err = {:?}", l4.verify_ok, l4.verify_err);
    eprintln!("L4b step chain:      verify_ok = {} err = {:?}", l4b.verify_ok, l4b.verify_err);
    eprintln!("L4b-single out pin:  verify_ok = {} err = {:?}", l4b_single.verify_ok, l4b_single.verify_err);
    eprintln!("L4b-in shared h_in:  verify_ok = {} err = {:?}", l4b_in.verify_ok, l4b_in.verify_err);
    eprintln!("L4b-out 1 link:     verify_ok = {} err = {:?}", l4b_out_1.verify_ok, l4b_out_1.verify_err);
    eprintln!(
        "L4c indirect bytes: prep_ok = {} verify_ok = {} err = {:?}",
        l4c_indirect.prep_ok, l4c_indirect.verify_ok, l4c_indirect.verify_err
    );
    eprintln!(
        "L4c mirror alloc:   prep_ok = {} verify_ok = {} err = {:?}",
        l4c_mirror.prep_ok, l4c_mirror.verify_ok, l4c_mirror.verify_err
    );
    eprintln!("L5 prod bound:       verify_ok = {} err = {:?}", l5.verify_ok, l5.verify_err);

    assert!(l0.verify_ok, "L0 baseline must pass");
}

// --- L6: uniform selector-based chain binding (the fix) --------------------------------------

/// `result = sum_k sel[k] * vals[k]` (caller guarantees `sel` is one-hot or all-zero).
fn one_hot_select<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    sel: &[AllocatedNum<Scalar>],
    vals: &[AllocatedNum<Scalar>],
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    assert_eq!(sel.len(), vals.len());
    let mut prods = Vec::with_capacity(sel.len());
    for (k, (s, v)) in sel.iter().zip(vals.iter()).enumerate() {
        prods.push(s.mul(cs.namespace(|| format!("prod_{k}")), v)?);
    }
    let val: Option<Scalar> = prods
        .iter()
        .try_fold(Scalar::ZERO, |acc, p| p.get_value().map(|v| acc + v));
    let result = AllocatedNum::alloc(cs.namespace(|| "select"), || {
        val.ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "select_sum",
        |lc| {
            let mut lc = lc;
            for p in &prods {
                lc = lc + p.get_variable();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + result.get_variable(),
    );
    Ok(result)
}

/// Enforce `(1 - gate) * (link - value(word)) == 0`.
///
/// When `gate == 1` (boundary step) the equality is skipped; otherwise `link` (a shared limb)
/// must equal the numeric value of `word`.
fn enforce_cond_link_eq_u32<CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    gate: &AllocatedNum<Scalar>,
    link: &AllocatedNum<Scalar>,
    word: &UInt32,
) -> Result<(), SynthesisError> {
    let bits = word.clone().into_bits();
    assert_eq!(bits.len(), 32);
    cs.enforce(
        || "cond_link_eq",
        |lc| lc + CS::one() - gate.get_variable(),
        |lc| {
            let mut lc = lc + link.get_variable();
            let mut coeff = Scalar::ONE;
            for b in &bits {
                lc = lc - &b.lc(CS::one(), coeff);
                coeff = coeff.double();
            }
            lc
        },
        |lc| lc,
    );
    Ok(())
}

/// Uniform chain-bound step: identical R1CS shape for every instance.
///
/// A one-hot `pos` (length `num_steps`, tied to the public `step_index`) selects which shared
/// link this step reads as `h_in` (link `step_index - 1`) and writes as `h_out` (link
/// `step_index`). Boundary steps skip the missing side via the `pos[0]` / `pos[last]` gates.
#[derive(Clone, Debug)]
struct BoundStyleStepUniform {
    step_index: usize,
    num_steps: usize,
    input: StepInput,
    link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for BoundStyleStepUniform {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::from(self.step_index as u64)])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_digests(cs, "step_shared", &self.link_digests)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let num_steps = self.num_steps;
        let num_links = num_steps - 1;

        // One-hot position vector pos[i] = (i == step_index).
        let pos: Vec<AllocatedNum<Scalar>> = (0..num_steps)
            .map(|i| {
                AllocatedNum::alloc(cs.namespace(|| format!("pos_{i}")), || {
                    Ok(if i == self.step_index {
                        Scalar::ONE
                    } else {
                        Scalar::ZERO
                    })
                })
            })
            .collect::<Result<_, _>>()?;
        for (i, p) in pos.iter().enumerate() {
            cs.enforce(
                || format!("pos_bool_{i}"),
                |lc| lc + p.get_variable(),
                |lc| lc + CS::one() - p.get_variable(),
                |lc| lc,
            );
        }
        cs.enforce(
            || "pos_sum_one",
            |lc| {
                let mut lc = lc;
                for p in &pos {
                    lc = lc + p.get_variable();
                }
                lc
            },
            |lc| lc + CS::one(),
            |lc| lc + CS::one(),
        );

        // Tie the one-hot to the public step_index for soundness.
        let si = AllocatedNum::alloc(cs.namespace(|| "step_index"), || {
            Ok(Scalar::from(self.step_index as u64))
        })?;
        si.inputize(cs.namespace(|| "inputize step_index"))?;
        cs.enforce(
            || "pos_weighted_index",
            |lc| {
                let mut lc = lc;
                for (i, p) in pos.iter().enumerate() {
                    lc = lc + (Scalar::from(i as u64), p.get_variable());
                }
                lc
            },
            |lc| lc + CS::one(),
            |lc| lc + si.get_variable(),
        );

        // h_in words (free witness; bound to the selected link for non-first steps).
        let h_in_words: Vec<UInt32> = state_bytes_to_words(&self.input.h_in)
            .iter()
            .enumerate()
            .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)))
            .collect::<Result<_, _>>()?;

        let out_words = synthesize_compression_for_fold_h_words(
            cs.namespace(|| "compress"),
            &h_in_words,
            &self.input.block,
        )?;

        // Reading link k means this is step k+1; writing link k means this is step k.
        let in_sel: Vec<AllocatedNum<Scalar>> = (0..num_links).map(|k| pos[k + 1].clone()).collect();
        let out_sel: Vec<AllocatedNum<Scalar>> = (0..num_links).map(|k| pos[k].clone()).collect();

        for j in 0..DIGEST_WORDS {
            let vals: Vec<AllocatedNum<Scalar>> = (0..num_links)
                .map(|k| shared[k * DIGEST_WORDS + j].clone())
                .collect();

            let in_link = one_hot_select(cs.namespace(|| format!("in_mux_{j}")), &in_sel, &vals)?;
            enforce_cond_link_eq_u32(
                cs.namespace(|| format!("in_bind_{j}")),
                &pos[0],
                &in_link,
                &h_in_words[j],
            )?;

            let out_link = one_hot_select(cs.namespace(|| format!("out_mux_{j}")), &out_sel, &vals)?;
            enforce_cond_link_eq_u32(
                cs.namespace(|| format!("out_bind_{j}")),
                &pos[num_steps - 1],
                &out_link,
                &out_words[j],
            )?;
        }

        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<Scalar>],
        _: &[AllocatedNum<Scalar>],
        _: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

fn uniform_steps(
    inputs: &[StepInput],
    digests: &[[u8; 32]],
) -> Vec<BoundStyleStepUniform> {
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| BoundStyleStepUniform {
            step_index: i,
            num_steps: inputs.len(),
            input: input.clone(),
            link_digests: digests.to_vec(),
            _p: PhantomData,
        })
        .collect()
}

/// L6: uniform selector binding should prove **and** verify (the fix for L4b-single / L5).
#[test]
fn ladder_6_uniform_selector() {
    let (inputs, digests) = build_consistent_bound_batch(NUM_STEPS);
    let steps = uniform_steps(&inputs, &digests);
    let core = core_alloc_only(digests.clone());
    let r = run_neutronnova("L6 uniform selector", &steps[0], &core, &steps, &core);
    eprintln!("L6 result: {r:?}");
    assert!(r.verify_ok, "L6 uniform selector should verify: {r:?}");
}

/// Negative control: a tampered link digest must break verification.
#[test]
fn ladder_6_uniform_selector_rejects_bad_link() {
    let (inputs, mut digests) = build_consistent_bound_batch(NUM_STEPS);
    // Corrupt the first link so step 0's h_out no longer matches shared[0].
    digests[0][0] ^= 0x01;
    let steps = uniform_steps(&inputs, &digests);
    let core = core_alloc_only(digests.clone());
    let r = run_neutronnova("L6 uniform selector (bad link)", &steps[0], &core, &steps, &core);
    eprintln!("L6 bad-link result: {r:?}");
    assert!(
        !r.verify_ok,
        "tampered link must not verify: {r:?}"
    );
}
