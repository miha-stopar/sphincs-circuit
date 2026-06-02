//! Cross-circuit binding between **folded steps** and a **separate** NeutronNova core.
//!
//! For how Spartan2 combines step fold + core in one proof (without automatic wire linking), see
//! [FOLDING.md §2.4](../../docs/FOLDING.md) and test `fold_split_step_core`.
//!
//! ## Workaround: [`FoldPackedCoreBoundCircuit`]
//!
//! Puts boundary glue inside `C_step` because empty `shared()` cannot link to `C_core` wires.
//!
//! ## Target (split): [`FoldStepBoundCircuit`] + [`FoldCoreBoundCircuit`]
//!
//! Uses Spartan2 **shared witness** slots (`8 × (num_steps − 1)` field elements) so step
//! compressions and core trace checks reference the same variables. This is the intended
//! split-circuit design from [`docs/FOLDING.md`](../../docs/FOLDING.md) §2.3, but NeutronNova
//! prove/verify on Spartan2 **0.9.0** currently fails (`InvalidSumcheckProof` / commitment length
//! errors) once `num_shared > 0`. See ignored test `fold_bound_shared_links`.

use std::marker::PhantomData;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
use spartan2::traits::{circuit::SpartanCircuit, Engine};
use bellpepper::gadgets::uint32::UInt32;
use sphincs_circuit::{
    alloc_digest_shared, enforce_bytes_eq_shared, enforce_words_eq_shared, link_shared_slice,
    sha256_compress::{state_bytes_to_words, synthesize_compression_for_fold_h_words},
    step::StepInput,
    u32_words_from_shared, DIGEST_WORDS,
};

use crate::fold::E;

type Scalar = <E as Engine>::Scalar;

fn alloc_all_link_digests<Scalar, CS>(
    mut cs: CS,
    link_digests: &[[u8; 32]],
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mut nums = Vec::with_capacity(link_digests.len() * DIGEST_WORDS);
    for (k, digest) in link_digests.iter().enumerate() {
        nums.extend(alloc_digest_shared(
            cs.namespace(|| format!("link_{k}")),
            "link",
            *digest,
        )?);
    }
    Ok(nums)
}

/// One folded step with optional pins to shared link digests.
#[derive(Clone, Debug)]
pub struct FoldStepBoundCircuit {
    pub input: StepInput,
    /// Index in the batch (`0 .. num_steps`).
    pub step_index: usize,
    /// Total step instances in this fold (including padding).
    pub num_steps: usize,
    /// `link_digests[k]` is the shared witness for the boundary between step `k` and `k+1`.
    pub link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl FoldStepBoundCircuit {
    pub fn new(
        input: StepInput,
        step_index: usize,
        num_steps: usize,
        link_digests: Vec<[u8; 32]>,
    ) -> Self {
        assert!(num_steps >= 2);
        assert_eq!(link_digests.len(), num_steps - 1);
        Self {
            input,
            step_index,
            num_steps,
            link_digests,
            _p: PhantomData,
        }
    }

    pub fn from_row(
        input: StepInput,
        step_index: usize,
        num_steps: usize,
        link_digests: Vec<[u8; 32]>,
    ) -> Self {
        Self::new(input, step_index, num_steps, link_digests)
    }

    fn link_in_index(&self) -> Option<usize> {
        if self.step_index > 0 {
            Some(self.step_index - 1)
        } else {
            None
        }
    }

    fn link_out_index(&self) -> Option<usize> {
        if self.step_index + 1 < self.num_steps {
            Some(self.step_index)
        } else {
            None
        }
    }

    /// Full step↔shared wiring (currently breaks NeutronNova verify on Spartan2 0.9.0).
    #[allow(dead_code)]
    fn synthesize_precommitted_linked<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<(), SynthesisError> {
        let h_words = if let Some(ix) = self.link_in_index() {
            u32_words_from_shared(
                cs.namespace(|| "h_in_from_shared"),
                "h_in",
                link_shared_slice(shared, ix),
            )?
        } else {
            let words = state_bytes_to_words(&self.input.h_in);
            words
                .iter()
                .enumerate()
                .map(|(i, &w)| {
                    UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w))
                })
                .collect::<Result<_, _>>()?
        };

        let out_words = synthesize_compression_for_fold_h_words(
            cs.namespace(|| "compress"),
            &h_words,
            &self.input.block,
        )?;

        if let Some(ix) = self.link_out_index() {
            enforce_words_eq_shared(
                cs.namespace(|| "link_out"),
                "h_out",
                &out_words,
                link_shared_slice(shared, ix),
            )?;
        }

        let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(Scalar::ZERO))?;
        x.inputize(cs.namespace(|| "inputize x"))?;
        Ok(())
    }
}

impl SpartanCircuit<E> for FoldStepBoundCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_all_link_digests(cs.namespace(|| "shared_links"), &self.link_digests)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        self.synthesize_precommitted_linked(cs, shared)?;
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

/// Core: each shared link limb equals the trace boundary digest (binds glue to PQClean topology).
#[derive(Clone, Debug)]
pub struct FoldCoreBoundCircuit {
    pub link_digests: Vec<[u8; 32]>,
    _p: PhantomData<Scalar>,
}

impl FoldCoreBoundCircuit {
    pub fn new(link_digests: Vec<[u8; 32]>) -> Self {
        Self {
            link_digests,
            _p: PhantomData,
        }
    }

    pub fn from_boundary_links(links: Vec<([u8; 32], [u8; 32])>) -> Self {
        let digests: Vec<_> = links.into_iter().map(|(left, _)| left).collect();
        Self::new(digests)
    }
}

impl SpartanCircuit<E> for FoldCoreBoundCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // Mirror step layout so `SplitR1CSShape::equalize` aligns shared columns.
        alloc_all_link_digests(cs.namespace(|| "core_shared_links"), &self.link_digests)
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

/// Packed local chain: step wires + in-step core boundary checks (sound on Spartan2 0.9.0).
#[derive(Clone, Debug)]
pub struct FoldPackedCoreBoundCircuit<const N: usize> {
    pub rows: [StepInput; N],
    pub links: Vec<([u8; 32], [u8; 32])>,
    _p: PhantomData<Scalar>,
}

impl<const N: usize> FoldPackedCoreBoundCircuit<N> {
    pub fn new(rows: [StepInput; N], links: Vec<([u8; 32], [u8; 32])>) -> Self {
        assert_eq!(links.len(), N - 1);
        Self {
            rows,
            links,
            _p: PhantomData,
        }
    }

    pub fn from_slice(rows: &[StepInput], links: Vec<([u8; 32], [u8; 32])>) -> Option<Self> {
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
        Some(Self::new(fixed, links))
    }
}

impl<const N: usize> SpartanCircuit<E> for FoldPackedCoreBoundCircuit<N> {
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
        let triples: Vec<_> = self
            .rows
            .iter()
            .map(|r| (r.h_in, r.block, r.h_out))
            .collect();
        sphincs_circuit::synthesize_compression_chain_for_fold_with_links(
            cs.namespace(|| "chain_core"),
            &triples,
            &self.links,
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
        _cs: &mut CS,
        _shared: &[AllocatedNum<Scalar>],
        _precommitted: &[AllocatedNum<Scalar>],
        _challenges: Option<&[Scalar]>,
    ) -> Result<(), SynthesisError> {
        Ok(())
    }
}

/// Build bound step circuits for a batch (same `link_digests` on every instance).
pub fn bound_steps_from_inputs(
    inputs: &[StepInput],
    num_steps: usize,
    link_digests: Vec<[u8; 32]>,
) -> Vec<FoldStepBoundCircuit> {
    inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            FoldStepBoundCircuit::new(input.clone(), i, num_steps, link_digests.clone())
        })
        .collect()
}
