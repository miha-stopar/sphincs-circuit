//! Spartan2 sha256_neutronnova bench circuits — sanity check NeutronNova in this workspace.

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

type E = T256HyraxEngine;

const BLOCK_BYTES: usize = 64;

#[derive(Clone, Debug)]
struct Sha256StepCircuit {
    block: [u8; BLOCK_BYTES],
    _p: PhantomData<<E as Engine>::Scalar>,
}

impl Sha256StepCircuit {
    fn new(block: [u8; BLOCK_BYTES]) -> Self {
        Self {
            block,
            _p: PhantomData,
        }
    }
}

impl SpartanCircuit<E> for Sha256StepCircuit {
    fn public_values(&self) -> Result<Vec<<E as Engine>::Scalar>, SynthesisError> {
        Ok(vec![<E as Engine>::Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<<E as Engine>::Scalar>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<<E as Engine>::Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<<E as Engine>::Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<<E as Engine>::Scalar>],
    ) -> Result<Vec<AllocatedNum<<E as Engine>::Scalar>>, SynthesisError> {
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

        const IV: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let current_hash: Vec<UInt32> = IV.iter().map(|&v| UInt32::constant(v)).collect();

        let _next = sha256_compression_function(
            cs.namespace(|| "sha256 compression"),
            &input_bits,
            &current_hash,
        )?;

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(<E as Engine>::Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<<E as Engine>::Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<<E as Engine>::Scalar>],
        _: &[AllocatedNum<<E as Engine>::Scalar>],
        _: Option<&[<E as Engine>::Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct CoreCircuit(PhantomData<<E as Engine>::Scalar>);

impl CoreCircuit {
    fn new() -> Self {
        Self(PhantomData)
    }
}

impl SpartanCircuit<E> for CoreCircuit {
    fn public_values(&self) -> Result<Vec<<E as Engine>::Scalar>, SynthesisError> {
        Ok(vec![<E as Engine>::Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<<E as Engine>::Scalar>>(
        &self,
        _: &mut CS,
    ) -> Result<Vec<AllocatedNum<<E as Engine>::Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<<E as Engine>::Scalar>>(
        &self,
        cs: &mut CS,
        _: &[AllocatedNum<<E as Engine>::Scalar>],
    ) -> Result<Vec<AllocatedNum<<E as Engine>::Scalar>>, SynthesisError> {
        let input_bits: Vec<Boolean> = (0..512)
            .map(|i| {
                AllocatedBit::alloc(cs.namespace(|| format!("core bit {i}")), Some(false))
                    .map(Boolean::from)
            })
            .collect::<Result<_, _>>()?;

        const IV: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let current_hash: Vec<UInt32> = IV.iter().map(|&v| UInt32::constant(v)).collect();

        let _next = sha256_compression_function(
            cs.namespace(|| "core sha256 compression"),
            &input_bits,
            &current_hash,
        )?;

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(<E as Engine>::Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(vec![])
    }

    fn num_challenges(&self) -> usize {
        0
    }

    fn synthesize<CS: ConstraintSystem<<E as Engine>::Scalar>>(
        &self,
        _: &mut CS,
        _: &[AllocatedNum<<E as Engine>::Scalar>],
        _: &[AllocatedNum<<E as Engine>::Scalar>],
        _: Option<&[<E as Engine>::Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

#[test]
fn spartan2_sha256_neutronnova_replica() {
    const NUM_STEPS: usize = 4;
    let step_proto = Sha256StepCircuit::new([0u8; BLOCK_BYTES]);
    let core_proto = CoreCircuit::new();
    let (pk, vk) = NeutronNovaZkSNARK::<E>::setup(&step_proto, &core_proto, NUM_STEPS).unwrap();

    let step_circuits: Vec<_> = (0..NUM_STEPS)
        .map(|i| Sha256StepCircuit::new([i as u8; BLOCK_BYTES]))
        .collect();
    let core_circuit = CoreCircuit::new();

    let prep = NeutronNovaZkSNARK::<E>::prep_prove(&pk, &step_circuits, &core_circuit, true).unwrap();
    let (proof, _) =
        NeutronNovaZkSNARK::<E>::prove(&pk, &step_circuits, &core_circuit, prep, true).unwrap();
    proof.verify(&vk, NUM_STEPS).unwrap();
}
