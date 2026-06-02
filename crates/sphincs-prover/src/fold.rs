//! NeutronNova multi-fold over uniform SHA-256 compression steps.
//!
//! Follows the Spartan2 [`sha256_neutronnova`](https://github.com/microsoft/Spartan2/blob/main/benches/sha256_neutronnova.rs)
//! pattern: `N` step instances + one core circuit → `NeutronNovaZkSNARK`.

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
use sphincs_circuit::{sha256_compress, step::StepInput};

pub type E = T256HyraxEngine;
type Scalar = <E as Engine>::Scalar;

/// One folded step = one PQClean trace row (`h_in`, `block`, `h_out`).
#[derive(Clone, Debug)]
pub struct FoldStepCircuit {
    input: StepInput,
    _p: PhantomData<Scalar>,
}

impl FoldStepCircuit {
    pub fn new(input: StepInput) -> Self {
        Self {
            input,
            _p: PhantomData,
        }
    }

    pub fn from_row(h_in: [u8; 32], block: [u8; 64], h_out: [u8; 32]) -> Self {
        Self::new(StepInput { h_in, block, h_out })
    }

    pub fn input(&self) -> &StepInput {
        &self.input
    }
}

impl SpartanCircuit<E> for FoldStepCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        sha256_compress::synthesize_compression_for_fold(
            cs.namespace(|| "step"),
            &self.input.h_in,
            &self.input.block,
        )?;

        // Spartan2 requires at least one inputized witness column.
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

/// Core circuit placeholder for NeutronNova structure.
///
/// M3 follow-up: replace with `synthesize_verify_core` (hash_message → FORS →
/// hypertree → root equality) and shared witnesses linking folded step outputs.
#[derive(Clone, Debug)]
pub struct FoldCoreCircuit(PhantomData<Scalar>);

impl Default for FoldCoreCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl FoldCoreCircuit {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl SpartanCircuit<E> for FoldCoreCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        _cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        Ok(vec![])
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // Match Spartan2's sha256_neutronnova core shape (~26k constraints) so
        // `SplitR1CSShape::equalize` pads step/core witness layouts consistently.
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

        let x = AllocatedNum::alloc(cs.namespace(|| "core_x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize core_x"))?;
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

pub type FoldProverKey = spartan2::neutronnova_zk::NeutronNovaProverKey<E>;
pub type FoldVerifierKey = spartan2::neutronnova_zk::NeutronNovaVerifierKey<E>;
pub type FoldProof = NeutronNovaZkSNARK<E>;

/// Setup keys for folding `num_steps` step instances + one core circuit.
///
/// `step_proto` must use inputs that satisfy the step constraints (NeutronNova
/// shape generation runs witness synthesis). Pass a real trace row, not zeros.
/// `core_proto` must match the core used at prove time (constraint shape depends
/// on it, e.g. [`crate::FoldCoreChainCircuit`] link count).
pub fn setup_with_proto<S, C2>(step_proto: &S, core_proto: &C2, num_steps: usize) -> (FoldProverKey, FoldVerifierKey)
where
    S: SpartanCircuit<E>,
    C2: SpartanCircuit<E>,
{
    NeutronNovaZkSNARK::<E>::setup(step_proto, core_proto, num_steps).expect("NeutronNova setup")
}

/// Setup with the default SHA-256 placeholder core ([`FoldCoreCircuit`]).
pub fn setup_with_default_core(
    step_proto: &FoldStepCircuit,
    num_steps: usize,
) -> (FoldProverKey, FoldVerifierKey) {
    setup_with_proto(step_proto, &FoldCoreCircuit::new(), num_steps)
}

/// Setup with an all-zero prototype (only valid when the step circuit does not
/// pin `h_out`; see [`sha256_compress::synthesize_compression_for_fold`]).
pub fn setup(num_steps: usize) -> (FoldProverKey, FoldVerifierKey) {
    setup_with_default_core(
        &FoldStepCircuit::from_row([0u8; 32], [0u8; 64], [0u8; 32]),
        num_steps,
    )
}

/// Fold `steps` and produce a Spartan2 zk proof.
pub fn fold_and_prove<S, C2>(pk: &FoldProverKey, steps: &[S], core: &C2) -> FoldProof
where
    S: SpartanCircuit<E>,
    C2: SpartanCircuit<E>,
{
    let prep = NeutronNovaZkSNARK::<E>::prep_prove(pk, steps, core, true).expect("prep_prove");
    let (proof, _prep_back) =
        NeutronNovaZkSNARK::<E>::prove(pk, steps, core, prep, true).expect("prove");
    proof
}

/// Verify a folded proof for `num_steps` step instances.
pub fn verify_proof(vk: &FoldVerifierKey, proof: &FoldProof, num_steps: usize) {
    proof.verify(vk, num_steps).expect("verify");
}
