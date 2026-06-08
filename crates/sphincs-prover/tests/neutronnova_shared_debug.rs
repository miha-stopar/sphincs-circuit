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
    alloc_digest_shared, enforce_bytes_eq_shared, enforce_words_eq_shared, link_shared_slice,
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

    eprintln!("L4a scalar 24:       verify_ok = {}", l4a.verify_ok);
    eprintln!("L4 bound core:       verify_ok = {} err = {:?}", l4.verify_ok, l4.verify_err);
    eprintln!("L4b step chain:      verify_ok = {} err = {:?}", l4b.verify_ok, l4b.verify_err);
    eprintln!("L4b-single out pin:  verify_ok = {} err = {:?}", l4b_single.verify_ok, l4b_single.verify_err);
    eprintln!("L4b-in shared h_in:  verify_ok = {} err = {:?}", l4b_in.verify_ok, l4b_in.verify_err);
    eprintln!("L4b-out 1 link:     verify_ok = {} err = {:?}", l4b_out_1.verify_ok, l4b_out_1.verify_err);
    eprintln!("L5 prod bound:       verify_ok = {} err = {:?}", l5.verify_ok, l5.verify_err);

    assert!(l0.verify_ok, "L0 baseline must pass");
}
