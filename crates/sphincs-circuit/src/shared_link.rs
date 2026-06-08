//! NeutronNova **shared witness** slots for SHA-256 chain link digests (32 bytes / 8 `u32` words).
//!
//! Step and core circuits allocate the same shared variables (one per `u32` limb). Each folded
//! step instance constrains its compression I/O against the appropriate slot; the core
//! re-checks those slots against trace-supplied boundary bytes.

use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use ff::PrimeField;

use crate::sha256_compress::state_bytes_to_words;

/// `u32` limbs per link digest in the shared witness.
pub const DIGEST_WORDS: usize = 8;

/// Allocate one link digest (8 field elements, one per big-endian SHA state word).
pub fn alloc_digest_shared<Scalar, CS>(
    mut cs: CS,
    label: &str,
    bytes: [u8; 32],
) -> Result<Vec<AllocatedNum<Scalar>>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let words = state_bytes_to_words(&bytes);
    words
        .iter()
        .enumerate()
        .map(|(i, &w)| {
            AllocatedNum::alloc(cs.namespace(|| format!("{label}_w{i}")), || {
                Ok(Scalar::from(w as u64))
            })
        })
        .collect()
}

/// Shared slice for link index `k` inside a flat `shared` vector (`8 * num_links` elements).
pub fn link_shared_slice<'a, Scalar: PrimeField>(
    shared: &'a [AllocatedNum<Scalar>],
    link_index: usize,
) -> &'a [AllocatedNum<Scalar>] {
    let start = link_index * DIGEST_WORDS;
    let end = start + DIGEST_WORDS;
    &shared[start..end]
}

/// Constrain allocated SHA state words to equal shared link limbs (wire–wire).
pub fn enforce_words_eq_shared<Scalar, CS>(
    mut cs: CS,
    label: &str,
    words: &[UInt32],
    shared_limbs: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(words.len(), DIGEST_WORDS);
    assert_eq!(shared_limbs.len(), DIGEST_WORDS);
    for (i, (word, num)) in words.iter().zip(shared_limbs.iter()).enumerate() {
        enforce_num_eq_u32(cs.namespace(|| format!("{label}_eq_{i}")), num, word)?;
    }
    Ok(())
}

/// Constrain a byte witness digest to shared limbs (core ↔ trace glue).
pub fn enforce_bytes_eq_shared<Scalar, CS>(
    mut cs: CS,
    label: &str,
    bytes: &[u8; 32],
    shared_limbs: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let words = state_bytes_to_words(bytes);
    for (i, (&w, num)) in words.iter().zip(shared_limbs.iter()).enumerate() {
        let word = UInt32::alloc(cs.namespace(|| format!("{label}_w{i}")), Some(w))?;
        enforce_num_eq_u32(cs.namespace(|| format!("{label}_eq_{i}")), num, &word)?;
    }
    Ok(())
}

/// `shared` scalar equals the numeric value of `word` (32-bit, LE bit packing).
///
/// Reconstruct `sum_j word.bits[j] * 2^j` and enforce it equals `num`. This avoids
/// decomposing the full field element and matches `UInt32`'s internal LE bit order.
fn enforce_num_eq_u32<Scalar, CS>(
    mut cs: CS,
    num: &AllocatedNum<Scalar>,
    word: &UInt32,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let word_bits = word.clone().into_bits();
    assert_eq!(word_bits.len(), 32);

    cs.enforce(
        || "num_eq_u32",
        |lc| {
            let mut acc = lc + num.get_variable();
            let mut coeff = Scalar::ONE;
            for bit in word_bits.iter() {
                acc = acc - &bit.lc(CS::one(), coeff);
                coeff = coeff.double();
            }
            acc
        },
        |lc| lc + CS::one(),
        |lc| lc,
    );
    Ok(())
}

/// Build `UInt32` SHA limbs wired to shared link slots (same variables as `alloc_digest_shared`).
pub fn u32_words_from_shared<Scalar, CS>(
    mut cs: CS,
    label: &str,
    shared_limbs: &[AllocatedNum<Scalar>],
) -> Result<Vec<UInt32>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(shared_limbs.len(), DIGEST_WORDS);
    shared_limbs
        .iter()
        .enumerate()
        .map(|(i, num)| {
            let w = num
                .get_value()
                .map(u32_from_scalar)
                .ok_or(SynthesisError::AssignmentMissing)?;
            let word = UInt32::alloc(cs.namespace(|| format!("{label}_w{i}")), Some(w))?;
            enforce_num_eq_u32(cs.namespace(|| format!("{label}_eq_{i}")), num, &word)?;
            Ok(word)
        })
        .collect()
}

fn u32_from_scalar<Scalar: PrimeField>(s: Scalar) -> u32 {
    let repr = s.to_repr();
    let bytes = repr.as_ref();
    u32::from_le_bytes(bytes[0..4].try_into().expect("u32 limb"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    #[test]
    fn enforce_bytes_eq_shared_is_satisfied_on_allocated_digest() {
        type Scalar = blstrs::Scalar;
        let digest = {
            let mut d = [0u8; 32];
            d[0] = 0x6a;
            d[1] = 0x09;
            d[4] = 0xe6; // non-trivial limb 1
            d
        };
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let shared = alloc_digest_shared(&mut cs, "s", digest).unwrap();
        enforce_bytes_eq_shared(&mut cs, "core", &digest, &shared).unwrap();
        assert!(
            cs.is_satisfied(),
            "bytes glue unsatisfied: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn enforce_words_eq_shared_is_satisfied_on_allocated_digest() {
        type Scalar = blstrs::Scalar;
        let digest = {
            let mut d = [0u8; 32];
            d[0] = 0x40;
            d[31] = 2;
            d
        };
        let words: Vec<UInt32> = state_bytes_to_words(&digest)
            .iter()
            .map(|&w| UInt32::constant(w))
            .collect();
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let shared = alloc_digest_shared(&mut cs, "s", digest).unwrap();
        enforce_words_eq_shared(&mut cs, "step", &words, &shared).unwrap();
        assert!(
            cs.is_satisfied(),
            "words glue unsatisfied: {:?}",
            cs.which_is_unsatisfied()
        );
    }
}
