//! Uniform mega-step for one NeutronNova fold batch mixing HM + thash families.
//!
//! NeutronNova requires every folded instance to share one R1CS shape. [`FoldOffloadMegaStepCircuit`]
//! always synthesizes gated HM, F, H, and M bodies; exactly one kind gate is active per instance.

use ff::Field;

use std::marker::PhantomData;

use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use spartan2::traits::{circuit::SpartanCircuit, Engine};
use sphincs_circuit::{
    alloc_verify_core_offload_shared, enforce_cond_link_eq_u32, link_shared_slice,
    sha256_compress::{state_bytes_to_words, synthesize_compression_for_fold_h_words},
    step::StepInput,
    thash_f_step_values, thash_h_step_values, thash_m_padded_blocks,
    thash_m_variable_compression_count, verify_core_fors_f_bus_len, verify_core_fors_h_bus_len,
    seeded_state, ThashFBusValue, ThashHBusValue, ThashMBusValue, DIGEST_WORDS, FORS_PK_INBLOCKS,
    THASH_F_SLOT_LEN, THASH_H_SLOT_LEN, WOTS_PK_INBLOCKS,
};

use crate::fold::E;
use crate::offload_shared::{
    pad_link_digests_for_steps, thash_f_region_columns, thash_h_region_columns,
    thash_m_region_columns, OffloadSharedContext, ThashFBusRegion, ThashHBusRegion,
    ThashMBusRegion,
};
use crate::thash_fold::{synthesize_thash_m_step_fold, thash_m_step_h_in};
use crate::uniform::{
    alloc_bus_active_gate, alloc_kind_selector, alloc_step_pos, and_gate, bind_muxed_column_gated,
};

type Scalar = <E as Engine>::Scalar;

/// Kind id encoded in public `kind_id` (one-hot in-circuit).
pub const MEGA_KIND_HASH_MESSAGE: usize = 0;
pub const MEGA_KIND_THASH_F: usize = 1;
pub const MEGA_KIND_THASH_H: usize = 2;
pub const MEGA_KIND_THASH_M: usize = 3;
pub const MEGA_KIND_COUNT: usize = 4;

/// Per-instance payload (exactly one variant is semantically active).
#[derive(Clone, Debug)]
pub enum MegaStepPayload {
    HashMessage {
        input: StepInput,
        hm_step_index: usize,
    },
    ThashF {
        seeded: [u8; 32],
        value: ThashFBusValue,
        region: ThashFBusRegion,
        bus_slot: usize,
    },
    ThashH {
        seeded: [u8; 32],
        value: ThashHBusValue,
        region: ThashHBusRegion,
        bus_slot: usize,
    },
    ThashM {
        seeded: [u8; 32],
        value: ThashMBusValue,
        h_in: [u8; 32],
        block: [u8; 64],
        inblocks: usize,
        region: ThashMBusRegion,
        compression_index: usize,
    },
}

impl MegaStepPayload {
    pub fn kind_id(&self) -> usize {
        match self {
            MegaStepPayload::HashMessage { .. } => MEGA_KIND_HASH_MESSAGE,
            MegaStepPayload::ThashF { .. } => MEGA_KIND_THASH_F,
            MegaStepPayload::ThashH { .. } => MEGA_KIND_THASH_H,
            MegaStepPayload::ThashM { .. } => MEGA_KIND_THASH_M,
        }
    }
}

/// One uniform folded step: HM, `thash`-F/H/M, or padding duplicate.
#[derive(Clone, Debug)]
pub struct FoldOffloadMegaStepCircuit {
    pub batch_index: usize,
    pub num_steps: usize,
    /// Padded HM sub-chain length (power of two, `<= num_steps`).
    pub hm_num_steps: usize,
    pub payload: MegaStepPayload,
    pub offload_ctx: OffloadSharedContext,
    _p: PhantomData<Scalar>,
}

impl FoldOffloadMegaStepCircuit {
    pub fn new(
        batch_index: usize,
        num_steps: usize,
        hm_num_steps: usize,
        payload: MegaStepPayload,
        offload_ctx: OffloadSharedContext,
    ) -> Self {
        assert!(num_steps.is_power_of_two());
        assert!(hm_num_steps.is_power_of_two());
        assert!(hm_num_steps <= num_steps);
        assert!(batch_index < num_steps);
        assert_eq!(
            offload_ctx.link_digests.len(),
            num_steps.saturating_sub(1)
        );
        Self {
            batch_index,
            num_steps,
            hm_num_steps,
            payload,
            offload_ctx,
            _p: PhantomData,
        }
    }
}

fn bus_slots_f(region: ThashFBusRegion, ctx: &OffloadSharedContext) -> usize {
    match region {
        ThashFBusRegion::ForsF => verify_core_fors_f_bus_len() / THASH_F_SLOT_LEN,
        ThashFBusRegion::Wots => ctx.offload.wots.len(),
    }
}

fn bus_slots_h(region: ThashHBusRegion, ctx: &OffloadSharedContext) -> usize {
    match region {
        ThashHBusRegion::ForsH => verify_core_fors_h_bus_len() / THASH_H_SLOT_LEN,
        ThashHBusRegion::MerkleH => ctx.offload.merkle_h.len(),
    }
}

fn alloc_const_gate<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    name: &str,
    skip: bool,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let g = AllocatedNum::alloc(cs.namespace(|| name), || {
        Ok(if skip {
            Scalar::ONE
        } else {
            Scalar::ZERO
        })
    })?;
    cs.enforce(
        || format!("{name}_bool"),
        |lc| lc + g.get_variable(),
        |lc| lc + CS::one() - g.get_variable(),
        |lc| lc,
    );
    Ok(g)
}

fn synthesize_hash_message_gated<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    hm_active: bool,
    num_steps: usize,
    hm_num_steps: usize,
    hm_step_index: usize,
    input: &StepInput,
    shared: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError> {
    assert!(hm_step_index < hm_num_steps);
    let num_links = num_steps - 1;
    let pos = alloc_step_pos(cs, hm_step_index, num_steps)?;

    let h_in_words: Vec<UInt32> = state_bytes_to_words(&input.h_in)
        .iter()
        .enumerate()
        .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("hm_h_in_w{i}")), Some(w)))
        .collect::<Result<_, _>>()?;

    let out_words = synthesize_compression_for_fold_h_words(
        cs.namespace(|| "hm_compress"),
        &h_in_words,
        &input.block,
    )?;

    let in_sel: Vec<AllocatedNum<Scalar>> =
        (0..num_links).map(|k| pos[k + 1].clone()).collect();
    let out_sel: Vec<AllocatedNum<Scalar>> = (0..num_links).map(|k| pos[k].clone()).collect();

    let in_gate = alloc_const_gate(
        cs,
        "hm_in_gate",
        !hm_active || hm_step_index == 0,
    )?;
    let out_gate = alloc_const_gate(
        cs,
        "hm_out_gate",
        !hm_active || hm_step_index + 1 == hm_num_steps,
    )?;

    for j in 0..DIGEST_WORDS {
        let vals: Vec<AllocatedNum<Scalar>> = (0..num_links)
            .map(|k| link_shared_slice(shared, k)[j].clone())
            .collect();
        let in_link = sphincs_circuit::one_hot_select(
            cs.namespace(|| format!("hm_in_mux_{j}")),
            &in_sel,
            &vals,
        )?;
        enforce_cond_link_eq_u32(
            cs.namespace(|| format!("hm_in_bind_{j}")),
            &in_gate,
            &in_link,
            &h_in_words[j],
        )?;

        let out_link = sphincs_circuit::one_hot_select(
            cs.namespace(|| format!("hm_out_mux_{j}")),
            &out_sel,
            &vals,
        )?;
        enforce_cond_link_eq_u32(
            cs.namespace(|| format!("hm_out_bind_{j}")),
            &out_gate,
            &out_link,
            &out_words[j],
        )?;
    }
    Ok(())
}

fn synthesize_thash_f_gated<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    gate: &AllocatedNum<Scalar>,
    num_steps: usize,
    bus_slot: usize,
    seeded: &[u8; 32],
    value: &ThashFBusValue,
    region: ThashFBusRegion,
    ctx: &OffloadSharedContext,
    shared: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError> {
    let pos = alloc_step_pos(cs, bus_slot, num_steps)?;
    let (addr_bits, in_bits, out_bits) = thash_f_step_values(
        cs.namespace(|| "f_compute"),
        seeded,
        &value.addr,
        &value.input,
    )?;
    let f_bus = thash_f_region_columns(shared, ctx, region);
    let bus_slots = bus_slots_f(region, ctx);
    let bus_active = alloc_bus_active_gate(cs, &pos, bus_slots)?;
    let active = and_gate(cs, "f_kind", gate, &bus_active)?;
    for (field, bits) in [(0usize, &addr_bits), (1, &in_bits), (2, &out_bits)] {
        bind_muxed_column_gated(
            cs, &active, &pos, f_bus, THASH_F_SLOT_LEN, field, bits, bus_slots,
        )?;
    }
    Ok(())
}

fn synthesize_thash_h_gated<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    gate: &AllocatedNum<Scalar>,
    num_steps: usize,
    bus_slot: usize,
    seeded: &[u8; 32],
    value: &ThashHBusValue,
    region: ThashHBusRegion,
    ctx: &OffloadSharedContext,
    shared: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError> {
    let pos = alloc_step_pos(cs, bus_slot, num_steps)?;
    let (addr_bits, in0_bits, in1_bits, out_bits) = thash_h_step_values(
        cs.namespace(|| "h_compute"),
        seeded,
        &value.addr,
        &value.in0,
        &value.in1,
    )?;
    let h_bus = thash_h_region_columns(shared, ctx, region);
    let bus_slots = bus_slots_h(region, ctx);
    let bus_active = alloc_bus_active_gate(cs, &pos, bus_slots)?;
    let active = and_gate(cs, "h_kind", gate, &bus_active)?;
    for (field, bits) in [
        (0usize, &addr_bits),
        (1, &in0_bits),
        (2, &in1_bits),
        (3, &out_bits),
    ] {
        bind_muxed_column_gated(
            cs, &active, &pos, h_bus, THASH_H_SLOT_LEN, field, bits, bus_slots,
        )?;
    }
    Ok(())
}

fn synthesize_thash_m_gated<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    m_active: bool,
    m_kind: &AllocatedNum<Scalar>,
    num_steps: usize,
    compression_index: usize,
    h_in: &[u8; 32],
    block: &[u8; 64],
    ctx: &OffloadSharedContext,
    shared: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError> {
    let var_count = thash_m_variable_compression_count(WOTS_PK_INBLOCKS);
    let m_bus = thash_m_region_columns(shared, ctx, ThashMBusRegion::WotsPkM(0));
    let m_inactive = alloc_const_gate(cs, "m_inactive", !m_active)?;
    synthesize_thash_m_step_fold(
        cs,
        h_in,
        block,
        compression_index,
        num_steps,
        WOTS_PK_INBLOCKS,
        m_bus,
        Some(var_count),
        m_kind,
        if m_active { None } else { Some(&m_inactive) },
        true,
    )
}

impl SpartanCircuit<E> for FoldOffloadMegaStepCircuit {
    fn public_values(&self) -> Result<Vec<Scalar>, SynthesisError> {
        Ok(vec![Scalar::from(self.payload.kind_id() as u64)])
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
        let kind_id = self.payload.kind_id();
        let kind = alloc_kind_selector(cs, kind_id, MEGA_KIND_COUNT)?;

        let hm_active = matches!(self.payload, MegaStepPayload::HashMessage { .. });
        let hm_step_index = match &self.payload {
            MegaStepPayload::HashMessage { hm_step_index, .. } => *hm_step_index,
            _ => 0,
        };

        let dummy_step = StepInput {
            h_in: [0u8; 32],
            block: [0u8; 64],
            h_out: [0u8; 32],
        };
        let dummy_f = ThashFBusValue {
            addr: [0u8; 22],
            input: [0u8; 16],
            out: [0u8; 16],
        };
        let dummy_h = ThashHBusValue {
            addr: [0u8; 22],
            in0: [0u8; 16],
            in1: [0u8; 16],
            out: [0u8; 16],
        };
        let dummy_m = ThashMBusValue {
            addr: [0u8; 22],
            input: vec![0u8; FORS_PK_INBLOCKS * 16],
            links: vec![[0u8; 32]; 9],
            out: [0u8; 16],
        };

        let (hm_in, f_val, f_reg, f_slot, h_val, h_reg, h_slot, _m_val, m_h_in, m_block, _m_inblocks, m_comp, seeded_f, seeded_h) =
            match &self.payload {
                MegaStepPayload::HashMessage { input, .. } => (
                    input,
                    &dummy_f,
                    ThashFBusRegion::ForsF,
                    0,
                    &dummy_h,
                    ThashHBusRegion::ForsH,
                    0,
                    &dummy_m,
                    [0u8; 32],
                    [0u8; 64],
                    WOTS_PK_INBLOCKS,
                    0,
                    [0u8; 32],
                    [0u8; 32],
                ),
                MegaStepPayload::ThashF {
                    seeded,
                    value,
                    region,
                    bus_slot,
                } => (
                    &dummy_step,
                    value,
                    *region,
                    *bus_slot,
                    &dummy_h,
                    ThashHBusRegion::ForsH,
                    0,
                    &dummy_m,
                    [0u8; 32],
                    [0u8; 64],
                    FORS_PK_INBLOCKS,
                    0,
                    *seeded,
                    [0u8; 32],
                ),
                MegaStepPayload::ThashH {
                    seeded,
                    value,
                    region,
                    bus_slot,
                } => (
                    &dummy_step,
                    &dummy_f,
                    ThashFBusRegion::ForsF,
                    0,
                    value,
                    *region,
                    *bus_slot,
                    &dummy_m,
                    [0u8; 32],
                    [0u8; 64],
                    WOTS_PK_INBLOCKS,
                    0,
                    [0u8; 32],
                    *seeded,
                ),
                MegaStepPayload::ThashM {
                    seeded,
                    value,
                    h_in,
                    block,
                    inblocks,
                    region: _region,
                    compression_index,
                } => (
                    &dummy_step,
                    &dummy_f,
                    ThashFBusRegion::ForsF,
                    0,
                    &dummy_h,
                    ThashHBusRegion::ForsH,
                    0,
                    value,
                    *h_in,
                    *block,
                    *inblocks,
                    *compression_index,
                    [0u8; 32],
                    *seeded,
                ),
            };

        synthesize_hash_message_gated(
            &mut cs.namespace(|| "hm"),
            hm_active,
            self.num_steps,
            self.hm_num_steps,
            hm_step_index,
            hm_in,
            shared,
        )?;
        synthesize_thash_f_gated(
            &mut cs.namespace(|| "f"),
            &kind[MEGA_KIND_THASH_F],
            self.num_steps,
            f_slot,
            &seeded_f,
            f_val,
            f_reg,
            &self.offload_ctx,
            shared,
        )?;
        synthesize_thash_h_gated(
            &mut cs.namespace(|| "h"),
            &kind[MEGA_KIND_THASH_H],
            self.num_steps,
            h_slot,
            &seeded_h,
            h_val,
            h_reg,
            &self.offload_ctx,
            shared,
        )?;
        let m_active = matches!(self.payload, MegaStepPayload::ThashM { .. });
        synthesize_thash_m_gated(
            &mut cs.namespace(|| "m"),
            m_active,
            &kind[MEGA_KIND_THASH_M],
            self.num_steps,
            m_comp,
            &m_h_in,
            &m_block,
            &self.offload_ctx,
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

/// Pad a mega batch to `num_steps` by duplicating the last entry.
pub fn build_offload_mega_steps(
    mut steps: Vec<FoldOffloadMegaStepCircuit>,
    num_steps: usize,
) -> Vec<FoldOffloadMegaStepCircuit> {
    assert!(num_steps.is_power_of_two());
    assert!(steps.len() <= num_steps);
    let pad = steps.last().expect("non-empty batch").clone();
    while steps.len() < num_steps {
        let mut dup = pad.clone();
        dup.batch_index = steps.len();
        dup.payload = pad.payload.clone();
        steps.push(dup);
    }
    steps
}

/// Build HM rows + FORS-F `thash` slots in one mega batch (batch indices assigned sequentially).
#[cfg(feature = "pqclean")]
pub fn mega_batch_hash_message_and_fors_f(
    hm_inputs: Vec<StepInput>,
    pub_seed: &[u8; 16],
    fors_f_values: &[ThashFBusValue],
    mut ctx: OffloadSharedContext,
    num_steps: usize,
) -> Vec<FoldOffloadMegaStepCircuit> {
    let hm_num_steps = crate::offload_shared::next_power_of_two_steps(hm_inputs.len());
    ctx.link_digests = pad_link_digests_for_steps(ctx.link_digests, num_steps);
    let seeded = seeded_state(pub_seed);
    let mut steps = Vec::new();
    for (hm_step_index, input) in hm_inputs.into_iter().enumerate() {
        let batch_index = steps.len();
        steps.push(FoldOffloadMegaStepCircuit::new(
            batch_index,
            num_steps,
            hm_num_steps,
            MegaStepPayload::HashMessage {
                input,
                hm_step_index,
            },
            ctx.clone(),
        ));
    }
    for (bus_slot, value) in fors_f_values.iter().enumerate() {
        let batch_index = steps.len();
        steps.push(FoldOffloadMegaStepCircuit::new(
            batch_index,
            num_steps,
            hm_num_steps,
            MegaStepPayload::ThashF {
                seeded,
                value: value.clone(),
                region: ThashFBusRegion::ForsF,
                bus_slot,
            },
            ctx.clone(),
        ));
    }
    build_offload_mega_steps(steps, num_steps)
}

/// One `thash`-M compression mega step.
pub fn mega_step_thash_m(
    batch_index: usize,
    num_steps: usize,
    pub_seed: &[u8; 16],
    value: ThashMBusValue,
    compression_index: usize,
    inblocks: usize,
    region: ThashMBusRegion,
    ctx: OffloadSharedContext,
) -> FoldOffloadMegaStepCircuit {
    let seeded = seeded_state(pub_seed);
    let blocks = thash_m_padded_blocks(pub_seed, &value.addr, &value.input);
    let var_count = thash_m_variable_compression_count(inblocks);
    let eff = compression_index.min(var_count.saturating_sub(1));
    let h_in = thash_m_step_h_in(&seeded, &value, eff);
    let block = blocks[eff + 1];
    FoldOffloadMegaStepCircuit::new(
        batch_index,
        num_steps,
        2,
        MegaStepPayload::ThashM {
            seeded,
            value,
            h_in,
            block,
            inblocks,
            region,
            compression_index,
        },
        ctx,
    )
}
