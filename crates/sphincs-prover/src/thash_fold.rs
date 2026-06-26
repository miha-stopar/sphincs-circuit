//! NeutronNova fold of WOTS+ chain `thash`-F compressions.
//!
//! Each [`FoldThashFStepCircuit`] proves **one** offloaded `thash`-F compression
//! (`Compress(seeded_state, addr‖in‖pad)`); `N` of them are folded. A separate
//! [`FoldThashFCoreCircuit`] holds only the WOTS chain *glue* (no SHA) and links
//! to the folded steps through a shared `addr/in/out` bus.
//!
//! This is the prover-side counterpart of `sphincs_circuit::thash_link`: it proves
//! the offload works end-to-end through the real Spartan2 fold protocol
//! (commitments + sum-check), not just as a single-CS satisfiability model.
//!
//! ## Uniform step shape
//!
//! NeutronNova folds every step instance against **one** R1CS shape, so the step
//! circuit must be identical across instances (see [`super::FoldStepBoundCircuit`]).
//! A one-hot `pos` vector (tied to the public `step_index`) selects which bus slot
//! this step binds its `addr/in/out` to, keeping the shape constant.

use std::marker::PhantomData;

use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::Field;
use spartan2::traits::{circuit::SpartanCircuit, Engine};
use sphincs_circuit::{
    alloc_thash_f_bus, alloc_thash_h_bus, compute_root_bits_linked, compute_root_h_bus_values,
    enforce_num_eq_be_bits, gen_chain_linked, one_hot_select, seeded_state,
    thash::{alloc_input_bits, enforce_bits_equal_bytes, ADDR_BYTES, SPX_N},
    thash_f_chain_bus_values, thash_f_step_values, thash_h_step_values, ThashFBusValue,
    ThashHBusValue, THASH_F_SLOT_LEN, THASH_H_SLOT_LEN,
};

use crate::fold::E;

type Scalar = <E as Engine>::Scalar;

/// Allocate the uniform one-hot step selector `pos` (length `num_steps`,
/// `pos[i] = (i == step_index)`), enforce it is boolean and sums to one, and bind
/// `Σ i·pos[i]` to the public `step_index`. Returns `pos` for slot muxing.
///
/// This is the per-instance witness variation that keeps the folded R1CS shape
/// identical across instances (see `bound.rs` / `docs/SHARED_WITNESS_DEBUG.md`).
fn alloc_step_selector<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    step_index: usize,
    num_steps: usize,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    let pos: Vec<AllocatedNum<Scalar>> = (0..num_steps)
        .map(|i| {
            AllocatedNum::alloc(cs.namespace(|| format!("pos_{i}")), || {
                Ok(if i == step_index {
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
    let idx = AllocatedNum::alloc(cs.namespace(|| "step_index"), || {
        Ok(Scalar::from(step_index as u64))
    })?;
    idx.inputize(cs.namespace(|| "inputize step_index"))?;
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
        |lc| lc + idx.get_variable(),
    );
    Ok(pos)
}

/// Bind a step's witness `bits` to the `field`-th column of its (selector-selected)
/// bus slot: `selected = Σ_k pos[k]·shared[k·slot_len + field]`, then `selected == bits`.
fn bind_muxed_column<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    pos: &[AllocatedNum<Scalar>],
    shared: &[AllocatedNum<Scalar>],
    slot_len: usize,
    field: usize,
    bits: &[bellpepper_core::boolean::Boolean],
) -> Result<(), SynthesisError> {
    let num_steps = pos.len();
    let vals: Vec<AllocatedNum<Scalar>> = (0..num_steps)
        .map(|k| shared[k * slot_len + field].clone())
        .collect();
    let selected = one_hot_select(cs.namespace(|| format!("mux_{field}")), pos, &vals)?;
    enforce_num_eq_be_bits(cs.namespace(|| format!("bind_{field}")), &selected, bits)
}

/// One folded `thash`-F step: proves a single offloaded compression and binds its
/// `addr/in/out` to bus slot `step_index` via a one-hot selector.
#[derive(Clone, Debug)]
pub struct FoldThashFStepCircuit {
    /// Seeded SHA-256 state `S` (constant for the proof's `pub_seed`).
    pub seeded: [u8; 32],
    /// All bus values in the fold (so every instance allocates an identical shared bus).
    pub values: Vec<ThashFBusValue>,
    /// Which step / bus slot this instance proves.
    pub step_index: usize,
    _p: PhantomData<Scalar>,
}

impl FoldThashFStepCircuit {
    pub fn new(seeded: [u8; 32], values: Vec<ThashFBusValue>, step_index: usize) -> Self {
        assert!(step_index < values.len());
        Self {
            seeded,
            values,
            step_index,
            _p: PhantomData,
        }
    }

    fn num_steps(&self) -> usize {
        self.values.len()
    }
}

impl SpartanCircuit<E> for FoldThashFStepCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::from(self.step_index as u64)])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_thash_f_bus(cs.namespace(|| "thash_f_bus"), &self.values)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let pos = alloc_step_selector(cs, self.step_index, self.num_steps())?;

        // Compute this instance's compression bits (uses its own addr/in).
        let own = &self.values[self.step_index];
        let (addr_bits, in_bits, out_bits) = thash_f_step_values(
            cs.namespace(|| "compute"),
            &self.seeded,
            &own.addr,
            &own.input,
        )?;

        // Bind each field to the selector-muxed bus column (uniform shape).
        for (field, bits) in [(0usize, &addr_bits), (1, &in_bits), (2, &out_bits)] {
            bind_muxed_column(cs, &pos, shared, THASH_F_SLOT_LEN, field, bits)?;
        }
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

/// Core for a single WOTS+ chain: holds the chain glue (no SHA) and links to the
/// folded `thash`-F steps via the shared bus.
#[derive(Clone, Debug)]
pub struct FoldThashFCoreCircuit {
    pub addr_base: [u8; ADDR_BYTES],
    pub chain_in: [u8; SPX_N],
    pub start: u32,
    pub steps: u32,
    pub final_out: [u8; SPX_N],
    pub values: Vec<ThashFBusValue>,
    _p: PhantomData<Scalar>,
}

impl FoldThashFCoreCircuit {
    pub fn new(
        addr_base: [u8; ADDR_BYTES],
        chain_in: [u8; SPX_N],
        start: u32,
        steps: u32,
        final_out: [u8; SPX_N],
        values: Vec<ThashFBusValue>,
    ) -> Self {
        Self {
            addr_base,
            chain_in,
            start,
            steps,
            final_out,
            values,
            _p: PhantomData,
        }
    }
}

impl SpartanCircuit<E> for FoldThashFCoreCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        // Identical bus layout to the step (so shared columns align under equalize).
        alloc_thash_f_bus(cs.namespace(|| "thash_f_bus"), &self.values)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let in_bits = alloc_input_bits(&mut cs.namespace(|| "chain_in"), "v", &self.chain_in)?;
        let top = gen_chain_linked(
            cs.namespace(|| "chain"),
            &self.addr_base,
            &in_bits,
            self.start,
            self.steps,
            shared,
        )?;
        enforce_bits_equal_bytes(cs.namespace(|| "final_out"), &top, &self.final_out)?;

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

/// Build the folded step set + core for one WOTS+ chain of `steps` `thash`-F calls.
///
/// `steps` should be a power of two (NeutronNova folds a power-of-two batch).
pub fn thash_f_chain_fold(
    pub_seed: &[u8; SPX_N],
    addr_base: &[u8; ADDR_BYTES],
    chain_in: &[u8; SPX_N],
    start: u32,
    steps: u32,
) -> (Vec<FoldThashFStepCircuit>, FoldThashFCoreCircuit) {
    let (values, final_out) = thash_f_chain_bus_values(pub_seed, addr_base, chain_in, start, steps);
    let seeded = seeded_state(pub_seed);
    let step_circuits: Vec<FoldThashFStepCircuit> = (0..values.len())
        .map(|i| FoldThashFStepCircuit::new(seeded, values.clone(), i))
        .collect();
    let core = FoldThashFCoreCircuit::new(
        *addr_base,
        *chain_in,
        start,
        steps,
        final_out,
        values,
    );
    (step_circuits, core)
}

// ===========================================================================
// thash-H fold (Merkle / FORS node compressions)
// ===========================================================================

/// One folded `thash`-H step: proves a single Merkle/FORS node compression and
/// binds its `addr/in0/in1/out` to bus slot `step_index` via a one-hot selector.
#[derive(Clone, Debug)]
pub struct FoldThashHStepCircuit {
    pub seeded: [u8; 32],
    pub values: Vec<ThashHBusValue>,
    pub step_index: usize,
    _p: PhantomData<Scalar>,
}

impl FoldThashHStepCircuit {
    pub fn new(seeded: [u8; 32], values: Vec<ThashHBusValue>, step_index: usize) -> Self {
        assert!(step_index < values.len());
        Self {
            seeded,
            values,
            step_index,
            _p: PhantomData,
        }
    }
}

impl SpartanCircuit<E> for FoldThashHStepCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::from(self.step_index as u64)])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_thash_h_bus(cs.namespace(|| "thash_h_bus"), &self.values)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let pos = alloc_step_selector(cs, self.step_index, self.values.len())?;
        let own = &self.values[self.step_index];
        let (addr_bits, in0_bits, in1_bits, out_bits) = thash_h_step_values(
            cs.namespace(|| "compute"),
            &self.seeded,
            &own.addr,
            &own.in0,
            &own.in1,
        )?;
        for (field, bits) in [
            (0usize, &addr_bits),
            (1, &in0_bits),
            (2, &in1_bits),
            (3, &out_bits),
        ] {
            bind_muxed_column(cs, &pos, shared, THASH_H_SLOT_LEN, field, bits)?;
        }
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

/// Core for one Merkle `compute_root`: holds the walk glue (no SHA) and links to
/// the folded `thash`-H steps via the shared bus, enforcing the recovered root.
#[derive(Clone, Debug)]
pub struct FoldThashHCoreCircuit {
    pub addr_base: [u8; ADDR_BYTES],
    pub leaf: [u8; SPX_N],
    pub leaf_idx: u32,
    pub idx_offset: u32,
    pub auth_path: Vec<u8>,
    pub tree_height: u32,
    pub root: [u8; SPX_N],
    pub values: Vec<ThashHBusValue>,
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for FoldThashHCoreCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_thash_h_bus(cs.namespace(|| "thash_h_bus"), &self.values)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let leaf_bits = alloc_input_bits(&mut cs.namespace(|| "leaf"), "v", &self.leaf)?;
        let root = compute_root_bits_linked(
            cs.namespace(|| "walk"),
            &self.addr_base,
            &leaf_bits,
            self.leaf_idx,
            self.idx_offset,
            &self.auth_path,
            self.tree_height,
            shared,
        )?;
        enforce_bits_equal_bytes(cs.namespace(|| "root"), &root, &self.root)?;

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

/// Build the folded step set + core for one Merkle `compute_root` of `tree_height`
/// `thash`-H levels (use a power-of-two `tree_height` for the fold batch).
pub fn thash_h_compute_root_fold(
    pub_seed: &[u8; SPX_N],
    addr_base: &[u8; ADDR_BYTES],
    leaf: &[u8; SPX_N],
    leaf_idx: u32,
    idx_offset: u32,
    auth_path: &[u8],
    tree_height: u32,
) -> (Vec<FoldThashHStepCircuit>, FoldThashHCoreCircuit) {
    let (values, root) = compute_root_h_bus_values(
        pub_seed, addr_base, leaf, leaf_idx, idx_offset, auth_path, tree_height,
    );
    let seeded = seeded_state(pub_seed);
    let step_circuits: Vec<FoldThashHStepCircuit> = (0..values.len())
        .map(|i| FoldThashHStepCircuit::new(seeded, values.clone(), i))
        .collect();
    let core = FoldThashHCoreCircuit {
        addr_base: *addr_base,
        leaf: *leaf,
        leaf_idx,
        idx_offset,
        auth_path: auth_path.to_vec(),
        tree_height,
        root,
        values,
        _p: PhantomData,
    };
    (step_circuits, core)
}
