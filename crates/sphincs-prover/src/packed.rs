//! One NeutronNova step instance = one PQClean **local chain** (multiple compressions, wired in-circuit).

use std::marker::PhantomData;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
use spartan2::traits::{circuit::SpartanCircuit, Engine};
use sphincs_circuit::step::{StepCircuit, StepInput};

use crate::fold::E;

type Scalar = <E as Engine>::Scalar;

/// `N` compressions in one Spartan circuit; `h_out[i]` wires feed `h_in[i+1]` directly.
#[derive(Clone, Debug)]
pub struct FoldPackedChainCircuit<const N: usize> {
    pub rows: [StepInput; N],
    _p: PhantomData<Scalar>,
}

impl<const N: usize> FoldPackedChainCircuit<N> {
    pub fn new(rows: [StepInput; N]) -> Self {
        Self {
            rows,
            _p: PhantomData,
        }
    }

    /// Build from a contiguous local-chain slice (must be exactly `N` rows).
    pub fn from_slice(rows: &[StepInput]) -> Option<Self> {
        if rows.len() != N {
            return None;
        }
        let mut fixed = [StepInput {
            h_in: [0u8; 32],
            block: [0u8; 64],
            h_out: [0u8; 32],
        }; N];
        for (i, &row) in rows.iter().enumerate() {
            fixed[i] = row;
        }
        Some(Self::new(fixed))
    }
}

impl<const N: usize> SpartanCircuit<E> for FoldPackedChainCircuit<N> {
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
        StepCircuit::synthesize_chain(cs.namespace(|| "chain"), &self.rows)?;

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
