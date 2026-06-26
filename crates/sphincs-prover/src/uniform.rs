//! Uniform selector + gated binding helpers for NeutronNova folded steps.
//!
//! Every folded instance must synthesize the **same** R1CS shape; per-instance
//! variation lives in the witness (one-hot selectors, kind gates).

use bellpepper_core::{
    boolean::Boolean, num::AllocatedNum, ConstraintSystem, SynthesisError,
};
use ff::Field;
use sphincs_circuit::{enforce_num_eq_be_bits, one_hot_select};

use crate::fold::E;

type Scalar = <E as spartan2::traits::Engine>::Scalar;

/// One-hot `pos[i] = (i == step_index)` tied to public `step_index`.
pub fn alloc_step_selector<CS: ConstraintSystem<Scalar>>(
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

/// One-hot position vector without public-input binding (nested in mega-step bodies).
pub fn alloc_step_pos<CS: ConstraintSystem<Scalar>>(
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
    Ok(pos)
}

/// One-hot kind selector tied to public `kind_id` (`0 .. num_kinds`).
pub fn alloc_kind_selector<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    kind_id: usize,
    num_kinds: usize,
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError> {
    let sel: Vec<AllocatedNum<Scalar>> = (0..num_kinds)
        .map(|k| {
            AllocatedNum::alloc(cs.namespace(|| format!("kind_{k}")), || {
                Ok(if k == kind_id {
                    Scalar::ONE
                } else {
                    Scalar::ZERO
                })
            })
        })
        .collect::<Result<_, _>>()?;
    for (k, g) in sel.iter().enumerate() {
        cs.enforce(
            || format!("kind_bool_{k}"),
            |lc| lc + g.get_variable(),
            |lc| lc + CS::one() - g.get_variable(),
            |lc| lc,
        );
    }
    cs.enforce(
        || "kind_sum_one",
        |lc| {
            let mut lc = lc;
            for g in &sel {
                lc = lc + g.get_variable();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + CS::one(),
    );
    let kid = AllocatedNum::alloc(cs.namespace(|| "kind_id"), || {
        Ok(Scalar::from(kind_id as u64))
    })?;
    kid.inputize(cs.namespace(|| "inputize kind_id"))?;
    cs.enforce(
        || "kind_weighted_id",
        |lc| {
            let mut lc = lc;
            for (k, g) in sel.iter().enumerate() {
                lc = lc + (Scalar::from(k as u64), g.get_variable());
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + kid.get_variable(),
    );
    Ok(sel)
}

/// Boolean AND of two `{0,1}` witness gates (`c = a·b`).
pub fn and_gate<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    ns: &str,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let c = AllocatedNum::alloc(cs.namespace(|| format!("{ns}_and")), || {
        Ok(a.get_value()
            .zip(b.get_value())
            .map(|(x, y)| x * y)
            .unwrap_or(Scalar::ZERO))
    })?;
    cs.enforce(
        || format!("{ns}_and_mul"),
        |lc| lc + a.get_variable(),
        |lc| lc + b.get_variable(),
        |lc| lc + c.get_variable(),
    );
    Ok(c)
}

/// Boolean OR of two `{0,1}` witness gates (`c = a + b - a·b`).
pub fn or_gate<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    ns: &str,
    a: &AllocatedNum<Scalar>,
    b: &AllocatedNum<Scalar>,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let ab = and_gate(cs, &format!("{ns}_ab"), a, b)?;
    let c = AllocatedNum::alloc(cs.namespace(|| format!("{ns}_or")), || {
        Ok(a.get_value()
            .zip(b.get_value())
            .map(|(x, y)| x + y - x * y)
            .unwrap_or(Scalar::ZERO))
    })?;
    cs.enforce(
        || format!("{ns}_or_sum"),
        |lc| lc + c.get_variable(),
        |lc| lc + a.get_variable() + b.get_variable(),
        |lc| lc + ab.get_variable(),
    );
    Ok(c)
}

/// `active = 1` iff `step_index < bus_slots` (sum of `pos[0..bus_slots]`).
pub fn alloc_bus_active_gate<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    pos: &[AllocatedNum<Scalar>],
    bus_slots: usize,
) -> Result<AllocatedNum<Scalar>, SynthesisError> {
    let active = AllocatedNum::alloc(cs.namespace(|| "bus_active"), || {
        let on = pos
            .iter()
            .take(bus_slots)
            .any(|p| p.get_value() == Some(Scalar::ONE));
        Ok(if on { Scalar::ONE } else { Scalar::ZERO })
    })?;
    cs.enforce(
        || "bus_active_sum",
        |lc| {
            let mut lc = lc;
            for p in pos.iter().take(bus_slots) {
                lc = lc + p.get_variable();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + active.get_variable(),
    );
    Ok(active)
}

/// When `gate == 1`, enforce `num` packs `bits`; when `gate == 0`, skip.
pub fn enforce_when_num_eq_be_bits<Scalar, CS>(
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

pub fn bind_muxed_column<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    pos: &[AllocatedNum<Scalar>],
    shared: &[AllocatedNum<Scalar>],
    slot_len: usize,
    field: usize,
    bits: &[Boolean],
) -> Result<(), SynthesisError> {
    let num_steps = pos.len();
    let vals: Vec<AllocatedNum<Scalar>> = (0..num_steps)
        .map(|k| shared[k * slot_len + field].clone())
        .collect();
    let selected = one_hot_select(cs.namespace(|| format!("mux_{field}")), pos, &vals)?;
    enforce_num_eq_be_bits(cs.namespace(|| format!("bind_{field}")), &selected, bits)
}

pub fn bind_muxed_column_gated<CS: ConstraintSystem<Scalar>>(
    cs: &mut CS,
    active: &AllocatedNum<Scalar>,
    pos: &[AllocatedNum<Scalar>],
    shared: &[AllocatedNum<Scalar>],
    slot_len: usize,
    field: usize,
    bits: &[Boolean],
    bus_slots: usize,
) -> Result<(), SynthesisError> {
    let num_steps = pos.len();
    let last_slot = bus_slots.saturating_sub(1);
    let vals: Vec<AllocatedNum<Scalar>> = (0..num_steps)
        .map(|k| {
            let slot = k.min(last_slot);
            shared[slot * slot_len + field].clone()
        })
        .collect();
    let selected = one_hot_select(cs.namespace(|| format!("mux_{field}")), pos, &vals)?;
    enforce_when_num_eq_be_bits(cs.namespace(|| format!("bind_{field}")), active, &selected, bits)
}
