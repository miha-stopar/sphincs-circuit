//! NeutronNova **core** circuits (M3 glue — not bulk SHA).

use std::marker::PhantomData;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
use spartan2::traits::{circuit::SpartanCircuit, Engine};
use sphincs_circuit::chain::synthesize_sha256_state_equal;

use crate::fold::E;

type Scalar = <E as Engine>::Scalar;

/// Placeholder core (~one SHA-256 compression) for shape equalization with Spartan2 bench.
pub use crate::fold::FoldCoreCircuit;

/// Core that enforces local-chain boundaries: `h_out[i] == h_in[i+1]` for each link.
///
/// Witness bytes come from the PQClean trace at prove time. This does **not** yet
/// cryptographically bind those bytes to the folded step instance witnesses; it
/// checks the prover-supplied link values are internally consistent with the
/// intended chain topology (next step: expose step `h_out`/`h_in` to core via fold IO).
#[derive(Clone, Debug)]
pub struct FoldCoreChainCircuit {
    pub links: Vec<([u8; 32], [u8; 32])>,
    _p: PhantomData<Scalar>,
}

impl FoldCoreChainCircuit {
    pub fn new(links: Vec<([u8; 32], [u8; 32])>) -> Self {
        Self {
            links,
            _p: PhantomData,
        }
    }

    pub fn num_links(&self) -> usize {
        self.links.len()
    }
}

impl SpartanCircuit<E> for FoldCoreChainCircuit {
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
        for (k, (left, right)) in self.links.iter().enumerate() {
            synthesize_sha256_state_equal(
                cs.namespace(|| format!("link_{k}")),
                left,
                right,
            )?;
        }

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
