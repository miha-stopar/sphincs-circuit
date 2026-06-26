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

use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{
    boolean::Boolean, num::AllocatedNum, ConstraintSystem, SynthesisError,
};
use ff::Field;
use spartan2::traits::{circuit::SpartanCircuit, Engine};
use sphincs_circuit::{
    alloc_thash_f_bus, alloc_thash_h_bus, alloc_thash_m_bus, compute_root_bits_linked,
    compute_root_h_bus_values, enforce_cond_link_eq_u32, enforce_num_eq_be_bits, gen_chain_linked,
    one_hot_select, seeded_state, sha256_compress::{
        sha256_state_words_to_bits_be, state_bytes_to_words, synthesize_compression_for_fold_h_words,
    },
    thash::{alloc_input_bits, enforce_bits_equal_bytes, ADDR_BYTES, SPX_N},
    thash_f_chain_bus_values, thash_f_step_values, thash_h_step_values, thash_m_bus_value,
    thash_m_core_link, thash_m_link_count, thash_m_padded_blocks,
    thash_m_variable_compression_count, ThashFBusValue, ThashHBusValue, ThashMBusValue,
    DIGEST_WORDS, THASH_F_SLOT_LEN, THASH_H_SLOT_LEN,
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

// ===========================================================================
// thash-M fold (multi-block FORS-pk / WOTS-pk compressions)
// ===========================================================================

fn thash_m_link_slice<'a, Scalar: ff::PrimeField>(
    bus: &'a [AllocatedNum<Scalar>],
    inblocks: usize,
    link_index: usize,
) -> &'a [AllocatedNum<Scalar>] {
    let base = 1 + inblocks + link_index * DIGEST_WORDS;
    &bus[base..base + DIGEST_WORDS]
}

/// When `gate == 1`, enforce `num` packs `bits`; when `gate == 0`, skip.
fn enforce_when_num_eq_be_bits<Scalar, CS>(
    mut cs: CS,
    gate: &AllocatedNum<Scalar>,
    num: &AllocatedNum<Scalar>,
    bits: &[Boolean],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    cs.enforce(
        || "when_num_eq_be_bits",
        |lc| lc + gate.get_variable(),
        |lc| {
            let mut lc = lc + num.get_variable();
            let mut coeff = Scalar::ONE;
            for b in bits.iter().rev() {
                lc = lc - &b.lc(CS::one(), coeff);
                coeff = coeff.double();
            }
            lc
        },
        |lc| lc,
    );
    Ok(())
}

/// Uniform folded `thash`-M compression step (identical R1CS across instances).
fn synthesize_thash_m_step_fold<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    h_in: &[u8; 32],
    block: &[u8; 64],
    step_index: usize,
    num_steps: usize,
    inblocks: usize,
    bus: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError> {
    let var_count = thash_m_variable_compression_count(inblocks);
    let num_links = thash_m_link_count(inblocks);
    assert!(num_steps >= var_count);
    assert!(step_index < num_steps);

    let pos = alloc_step_selector(cs, step_index, num_steps)?;

    let h_in_words: Vec<UInt32> = state_bytes_to_words(h_in)
        .iter()
        .enumerate()
        .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)))
        .collect::<Result<_, _>>()?;

    let out_words = synthesize_compression_for_fold_h_words(
        cs.namespace(|| "compress"),
        &h_in_words,
        block,
    )?;

    let in_sel: Vec<AllocatedNum<Scalar>> =
        (0..num_links).map(|k| pos[k + 1].clone()).collect();
    for j in 0..DIGEST_WORDS {
        let vals: Vec<AllocatedNum<Scalar>> = (0..num_links)
            .map(|k| thash_m_link_slice(bus, inblocks, k)[j].clone())
            .collect();
        let in_link =
            one_hot_select(cs.namespace(|| format!("in_mux_{j}")), &in_sel, &vals)?;
        enforce_cond_link_eq_u32(
            cs.namespace(|| format!("in_bind_{j}")),
            &pos[0],
            &in_link,
            &h_in_words[j],
        )?;
    }

    let out_sel: Vec<AllocatedNum<Scalar>> = (0..num_links).map(|k| pos[k].clone()).collect();
    let last = &pos[var_count - 1];
    for j in 0..DIGEST_WORDS {
        let vals: Vec<AllocatedNum<Scalar>> = (0..num_links)
            .map(|k| thash_m_link_slice(bus, inblocks, k)[j].clone())
            .collect();
        let out_link =
            one_hot_select(cs.namespace(|| format!("out_mux_{j}")), &out_sel, &vals)?;
        enforce_cond_link_eq_u32(
            cs.namespace(|| format!("out_link_{j}")),
            last,
            &out_link,
            &out_words[j],
        )?;
    }

    let out_bits: Vec<Boolean> = sha256_state_words_to_bits_be(&out_words[..4]);
    let out_field = &bus[bus.len() - 1];
    enforce_when_num_eq_be_bits(
        cs.namespace(|| "out_field"),
        last,
        out_field,
        &out_bits,
    )?;
    Ok(())
}

fn thash_m_step_h_in(seeded: &[u8; 32], value: &ThashMBusValue, step_index: usize) -> [u8; 32] {
    if step_index == 0 {
        *seeded
    } else {
        value.links[step_index - 1]
    }
}

/// One folded `thash`-M step: proves one variable compression in a multi-block chain.
#[derive(Clone, Debug)]
pub struct FoldThashMStepCircuit {
    pub seeded: [u8; 32],
    pub value: ThashMBusValue,
    pub h_in: [u8; 32],
    pub block: [u8; 64],
    pub inblocks: usize,
    pub step_index: usize,
    pub num_steps: usize,
    _p: PhantomData<Scalar>,
}

impl FoldThashMStepCircuit {
    pub fn new(
        seeded: [u8; 32],
        value: ThashMBusValue,
        h_in: [u8; 32],
        block: [u8; 64],
        inblocks: usize,
        step_index: usize,
        num_steps: usize,
    ) -> Self {
        assert!(step_index < num_steps);
        Self {
            seeded,
            value,
            h_in,
            block,
            inblocks,
            step_index,
            num_steps,
            _p: PhantomData,
        }
    }
}

impl SpartanCircuit<E> for FoldThashMStepCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::from(self.step_index as u64)])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_thash_m_bus(cs.namespace(|| "thash_m_bus"), &self.value)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        synthesize_thash_m_step_fold(
            cs,
            &self.h_in,
            &self.block,
            self.step_index,
            self.num_steps,
            self.inblocks,
            shared,
        )?;
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

/// Core for one `thash`-M call: glue only (no SHA), links to the folded steps via the bus.
#[derive(Clone, Debug)]
pub struct FoldThashMCoreCircuit {
    pub value: ThashMBusValue,
    pub inblocks: usize,
    _p: PhantomData<Scalar>,
}

impl SpartanCircuit<E> for FoldThashMCoreCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::ZERO])
    }

    fn shared<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        alloc_thash_m_bus(cs.namespace(|| "thash_m_bus"), &self.value)
    }

    fn precommitted<CS: ConstraintSystem<Scalar>>(
        &self,
        cs: &mut CS,
        shared: &[AllocatedNum<Scalar>],
    ) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
        let in_bits = alloc_input_bits(
            &mut cs.namespace(|| "in"),
            "v",
            &self.value.input,
        )?;
        let out_bits = thash_m_core_link(
            cs.namespace(|| "core"),
            &self.value.addr,
            &in_bits,
            self.inblocks,
            shared,
        )?;
        enforce_bits_equal_bytes(cs.namespace(|| "out"), &out_bits, &self.value.out)?;

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

/// Build folded step instances + core for one `thash`-M call.
///
/// `num_steps` must be a power of two and `>= thash_m_variable_compression_count(inblocks)`.
pub fn thash_m_single_call_fold(
    pub_seed: &[u8; SPX_N],
    addr: &[u8; ADDR_BYTES],
    input: &[u8],
    num_steps: usize,
) -> (Vec<FoldThashMStepCircuit>, FoldThashMCoreCircuit) {
    let inblocks = input.len() / SPX_N;
    let var_count = thash_m_variable_compression_count(inblocks);
    assert_eq!(
        num_steps, var_count,
        "thash-M fold batch must equal variable compression count ({var_count}); padding TBD"
    );
    assert!(num_steps.is_power_of_two());

    let value = thash_m_bus_value(pub_seed, addr, input);
    let seeded = seeded_state(pub_seed);
    let blocks = thash_m_padded_blocks(pub_seed, &value.addr, &value.input);
    let step_circuits: Vec<FoldThashMStepCircuit> = (0..num_steps)
        .map(|i| {
            let h_in = thash_m_step_h_in(&seeded, &value, i);
            let block = blocks[i + 1];
            FoldThashMStepCircuit::new(
                seeded,
                value.clone(),
                h_in,
                block,
                inblocks,
                i,
                num_steps,
            )
        })
        .collect();
    let core = FoldThashMCoreCircuit {
        value,
        inblocks,
        _p: PhantomData,
    };
    (step_circuits, core)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use spartan2::traits::Engine;
    use sphincs_circuit::{thash_m_synthesize_steps, FORS_PK_INBLOCKS};

    type Fr = <crate::fold::E as Engine>::Scalar;

    #[test]
    fn thash_m_step_fold_matches_synthesize_steps() {
        let pub_seed = [0x33u8; 16];
        let mut addr = [0u8; 22];
        addr[9] = 3;
        let input: Vec<u8> = (0..FORS_PK_INBLOCKS * 16).map(|i| (i % 200) as u8).collect();
        let value = thash_m_bus_value(&pub_seed, &addr, &input);
        let inblocks = input.len() / SPX_N;
        let var_count = thash_m_variable_compression_count(inblocks);
        let seeded = seeded_state(&pub_seed);
        let blocks = thash_m_padded_blocks(&pub_seed, &value.addr, &value.input);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let bus = alloc_thash_m_bus(cs.namespace(|| "bus"), &value).unwrap();
        for i in 0..var_count {
            let h_in = thash_m_step_h_in(&seeded, &value, i);
            synthesize_thash_m_step_fold(
                &mut cs.namespace(|| format!("fold_{i}")),
                &h_in,
                &blocks[i + 1],
                i,
                var_count,
                inblocks,
                &bus,
            )
            .unwrap();
        }
        assert!(
            cs.is_satisfied(),
            "fold steps unsat: {:?}",
            cs.which_is_unsatisfied()
        );

        let mut cs2 = TestConstraintSystem::<Fr>::new();
        let bus2 = alloc_thash_m_bus(cs2.namespace(|| "bus"), &value).unwrap();
        thash_m_synthesize_steps(cs2.namespace(|| "steps"), &pub_seed, &value, &bus2).unwrap();
        assert!(cs2.is_satisfied());
    }
}
