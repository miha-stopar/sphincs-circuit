//! Shared witness layout for offloaded verify core + folded steps in one NeutronNova proof.
//!
//! [`FoldVerifyCoreCircuit`] in [`VerifyCorePhase::Offloaded`] allocates
//! `hash_message` link digests plus all six `thash` buses via
//! [`sphincs_circuit::alloc_verify_core_offload_shared`]. Folded step circuits that
//! participate in the same proof must call the **same** allocator so `comm_W_shared`
//! column indices align.

use std::marker::PhantomData;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use spartan2::traits::{circuit::SpartanCircuit, Engine};
use sphincs_circuit::{
    alloc_verify_core_offload_shared, verify_core_buses_from_offload_shared,
    VerifyCoreOffloadWitness,
};

use crate::bound::FoldStepBoundCircuit;
use crate::fold::E;

type Scalar = <E as Engine>::Scalar;

/// `hash_message` link digests + native offloaded `thash` bus values (one per proof).
#[derive(Clone, Debug)]
pub struct OffloadSharedContext {
    pub link_digests: Vec<[u8; 32]>,
    pub offload: VerifyCoreOffloadWitness,
}

impl OffloadSharedContext {
    pub fn new(link_digests: Vec<[u8; 32]>, offload: VerifyCoreOffloadWitness) -> Self {
        Self {
            link_digests,
            offload,
        }
    }

    pub fn num_links(&self) -> usize {
        self.link_digests.len()
    }
}

/// Which contiguous F-bus region of [`VerifyCoreBuses`] a folded `thash`-F step binds to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThashFBusRegion {
    ForsF,
    Wots,
}

/// Slice the F-bus columns used by [`super::thash_fold::FoldThashFStepCircuit`] inside a
/// unified offload shared witness.
pub fn thash_f_region_columns<'a, Scalar: ff::PrimeField>(
    shared: &'a [AllocatedNum<Scalar>],
    ctx: &OffloadSharedContext,
    region: ThashFBusRegion,
) -> &'a [AllocatedNum<Scalar>] {
    let buses = verify_core_buses_from_offload_shared(shared, ctx.num_links(), &ctx.offload);
    match region {
        ThashFBusRegion::ForsF => buses.fors_f,
        ThashFBusRegion::Wots => buses.wots,
    }
}

/// [`FoldStepBoundCircuit`] with the extended shared layout required by an offloaded verify core.
#[derive(Clone, Debug)]
pub struct FoldStepBoundOffloadCircuit {
    pub bound: FoldStepBoundCircuit,
    pub offload_ctx: OffloadSharedContext,
    _p: PhantomData<Scalar>,
}

impl FoldStepBoundOffloadCircuit {
    pub fn new(
        input: sphincs_circuit::step::StepInput,
        step_index: usize,
        num_steps: usize,
        offload_ctx: OffloadSharedContext,
    ) -> Self {
        assert_eq!(offload_ctx.link_digests.len(), num_steps.saturating_sub(1));
        Self {
            bound: FoldStepBoundCircuit::new(
                input,
                step_index,
                num_steps,
                offload_ctx.link_digests.clone(),
            ),
            offload_ctx,
            _p: PhantomData,
        }
    }

    pub fn from_bound(bound: &FoldStepBoundCircuit, offload_ctx: OffloadSharedContext) -> Self {
        Self {
            bound: bound.clone(),
            offload_ctx,
            _p: PhantomData,
        }
    }
}

impl SpartanCircuit<E> for FoldStepBoundOffloadCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        self.bound.public_values()
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_verify_core_offload_shared(
            cs.namespace(|| "offload_shared"),
            &self.offload_ctx.link_digests,
            &self.offload_ctx.offload,
        )
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // Only the leading link-digest columns are used; thash bus tail is core-only for HM steps.
        self.bound
            .synthesize_precommitted_linked(cs, shared)
            .map(|_| vec![])
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

/// Pad a `thash`-F value list to `num_steps` (power of two) by duplicating the last entry.
pub fn pad_thash_f_values_to_power_of_two(
    mut values: Vec<sphincs_circuit::ThashFBusValue>,
    num_steps: usize,
) -> Vec<sphincs_circuit::ThashFBusValue> {
    assert!(num_steps.is_power_of_two());
    assert!(num_steps >= values.len());
    while values.len() < num_steps {
        values.push(values.last().expect("non-empty").clone());
    }
    values
}

/// Next power of two `>= n` (minimum 2).
pub const fn next_power_of_two_steps(n: usize) -> usize {
    let mut p = 2usize;
    while p < n {
        p <<= 1;
    }
    p
}
