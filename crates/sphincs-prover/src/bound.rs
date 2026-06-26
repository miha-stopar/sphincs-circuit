//! Cross-circuit binding between **folded steps** and a **separate** NeutronNova core.
//!
//! For how Spartan2 combines step fold + core in one proof (without automatic wire linking), see
//! [FOLDING.md §2.4](../../docs/FOLDING.md) and test `fold_split_step_core`.
//!
//! ## Workaround: [`FoldPackedCoreBoundCircuit`]
//!
//! Puts boundary glue inside `C_step` because empty `shared()` cannot link to `C_core` wires.
//!
//! ## Split design: [`FoldStepBoundCircuit`] + [`FoldCoreBoundCircuit`]
//!
//! Uses Spartan2 **shared witness** slots (`8 × (num_steps − 1)` field elements) so step
//! compressions and core trace checks reference the same variables (see
//! [`docs/FOLDING.md`](../../docs/FOLDING.md) §2.3).
//!
//! NeutronNova folds every step instance against a **single** R1CS shape (the setup prototype
//! `steps[0]`), so all instances must synthesize identical constraints over identical witness
//! columns. The earlier per-step pin (`if step_index == k { enforce_words_eq_shared(link k) }`)
//! produced a different shape per instance, so steps `1..n` were unsatisfiable and verify failed
//! with `InvalidSumcheckProof` (`docs/SHARED_WITNESS_DEBUG.md` L4b-single).
//!
//! [`FoldStepBoundCircuit`] now uses a **uniform** selector binding: a one-hot `pos` vector
//! (tied to the public `step_index`) picks which shared link each step reads as `h_in` and
//! writes as `h_out`, keeping the shape identical across instances. Prove and verify both
//! succeed — test `fold_bound_shared_links_prove_and_verify`.

use std::marker::PhantomData;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
use spartan2::traits::{circuit::SpartanCircuit, Engine};
use bellpepper::gadgets::uint32::UInt32;
use sphincs_circuit::{
    alloc_digest_shared, enforce_bytes_eq_shared, enforce_cond_link_eq_u32, link_shared_slice,
    one_hot_select,
    sha256_compress::{state_bytes_to_words, synthesize_compression_for_fold_h_words},
    step::StepInput,
    DIGEST_WORDS,
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

    /// Uniform step↔shared wiring: identical R1CS shape for every folded instance.
    ///
    /// NeutronNova folds all step instances against a **single** R1CS shape (taken from the
    /// setup prototype `steps[0]`), so every instance must synthesize the exact same constraints
    /// referencing the exact same witness columns. A circuit that branches on `step_index` (or
    /// pins to a per-step link slot) produces a different shape per instance, which makes every
    /// non-prototype instance unsatisfiable and breaks NeutronNova verify.
    ///
    /// Instead we keep the structure constant and move the per-step variation into the witness:
    /// a one-hot `pos` vector (length `num_steps`, tied to the public `step_index`) selects which
    /// shared link this step reads as `h_in` (link `step_index - 1`) and writes as `h_out`
    /// (link `step_index`). Boundary steps skip the absent side via the `pos[0]` / `pos[last]`
    /// gates.
    /// Uniform step↔shared wiring (see module docs). Exposed for [`super::offload_shared::FoldStepBoundOffloadCircuit`].
    pub(crate) fn synthesize_precommitted_linked<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<(), SynthesisError> {
        let num_steps = self.num_steps;
        let num_links = num_steps - 1;

        // One-hot position vector: pos[i] = (i == step_index).
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

        // Bind the one-hot to the public `step_index` (soundness: selectors can't be forged).
        let step_index = AllocatedNum::alloc(cs.namespace(|| "step_index"), || {
            Ok(Scalar::from(self.step_index as u64))
        })?;
        step_index.inputize(cs.namespace(|| "inputize step_index"))?;
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
            |lc| lc + step_index.get_variable(),
        );

        // h_in words: free witness, bound to the selected link for non-first steps.
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

        // Reading link k ⇒ this is step k+1; writing link k ⇒ this is step k.
        let in_sel: Vec<AllocatedNum<Scalar>> =
            (0..num_links).map(|k| pos[k + 1].clone()).collect();
        let out_sel: Vec<AllocatedNum<Scalar>> = (0..num_links).map(|k| pos[k].clone()).collect();

        for j in 0..DIGEST_WORDS {
            let vals: Vec<AllocatedNum<Scalar>> = (0..num_links)
                .map(|k| link_shared_slice(shared, k)[j].clone())
                .collect();

            let in_link =
                one_hot_select(cs.namespace(|| format!("in_mux_{j}")), &in_sel, &vals)?;
            enforce_cond_link_eq_u32(
                cs.namespace(|| format!("in_bind_{j}")),
                &pos[0],
                &in_link,
                &h_in_words[j],
            )?;

            let out_link =
                one_hot_select(cs.namespace(|| format!("out_mux_{j}")), &out_sel, &vals)?;
            enforce_cond_link_eq_u32(
                cs.namespace(|| format!("out_bind_{j}")),
                &pos[num_steps - 1],
                &out_link,
                &out_words[j],
            )?;
        }

        Ok(())
    }
}

impl SpartanCircuit<E> for FoldStepBoundCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::from(self.step_index as u64)])
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
