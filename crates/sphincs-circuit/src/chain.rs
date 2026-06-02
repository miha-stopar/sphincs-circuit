//! SHA-256 state linking for M3 core glue (`h_out[i] == h_in[i+1]` within a local chain).
//!
//! Used by [`sphincs_prover::FoldCoreChainCircuit`] to check boundary digests supplied
//! from the trace. Sound linkage to folded step witnesses is a follow-up (see
//! [`docs/FOLDING.md`](../../docs/FOLDING.md) §2.3).

use bellpepper::gadgets::boolean::Boolean;
use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{ConstraintSystem, SynthesisError};

use crate::sha256_compress::state_bytes_to_words;

/// Constrain two allocated SHA state word vectors (8 `u32` limbs) to be equal.
pub fn enforce_sha256_words_equal<Scalar, CS>(
    mut cs: CS,
    left: &[UInt32],
    right: &[UInt32],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(left.len(), 8);
    assert_eq!(right.len(), 8);
    for (i, (l, r)) in left.iter().zip(right.iter()).enumerate() {
        for (j, (a, b)) in l
            .clone()
            .into_bits_be()
            .iter()
            .zip(r.clone().into_bits_be().iter())
            .enumerate()
        {
            Boolean::enforce_equal(cs.namespace(|| format!("w_eq_{i}_{j}")), a, b)?;
        }
    }
    Ok(())
}

/// Constrain compression output words to a trace-supplied 32-byte digest (witness).
pub fn enforce_digest_bytes_eq_words<Scalar, CS>(
    mut cs: CS,
    label: &str,
    words: &[UInt32],
    bytes: &[u8; 32],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let expected = state_bytes_to_words(bytes);
    let allocated: Vec<UInt32> = expected
        .iter()
        .enumerate()
        .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("{label}_exp_w{i}")), Some(w)))
        .collect::<Result<_, _>>()?;
    enforce_sha256_words_equal(cs.namespace(|| label), words, &allocated)
}

/// Constrain two 32-byte SHA states (8 big-endian `u32` words) to be equal.
///
/// Both sides are allocated witnesses (NeutronNova-safe). Used for local-chain
/// boundary checks in the core circuit.
pub fn synthesize_sha256_state_equal<Scalar, CS>(
    mut cs: CS,
    left: &[u8; 32],
    right: &[u8; 32],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let left_words = state_bytes_to_words(left);
    let right_words = state_bytes_to_words(right);

    for (i, (&lw, &rw)) in left_words.iter().zip(right_words.iter()).enumerate() {
        let l = UInt32::alloc(cs.namespace(|| format!("left_w{i}")), Some(lw))?;
        let r = UInt32::alloc(cs.namespace(|| format!("right_w{i}")), Some(rw))?;
        for (j, (a, b)) in l
            .into_bits_be()
            .iter()
            .zip(r.into_bits_be().iter())
            .enumerate()
        {
            Boolean::enforce_equal(cs.namespace(|| format!("eq_{i}_{j}")), a, b)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;

    #[test]
    fn equal_states_satisfied() {
        let s = [0xabu8; 32];
        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_sha256_state_equal(&mut cs, &s, &s).unwrap();
        assert!(cs.is_satisfied());
    }

    #[test]
    fn unequal_states_unsatisfied() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let mut cs = TestConstraintSystem::<Fr>::new();
        synthesize_sha256_state_equal(&mut cs, &a, &b).unwrap();
        assert!(!cs.is_satisfied());
    }
}
