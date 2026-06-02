//! NeutronNova **shared witness** slots for SHA-256 chain link digests (32 bytes / 8 `u32` words).
//!
//! Step and core circuits allocate the same shared variables (one per `u32` limb). Each folded
//! step instance constrains its compression I/O against the appropriate slot; the core
//! re-checks those slots against trace-supplied boundary bytes.

use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{
    boolean::Boolean,
    num::AllocatedNum,
    ConstraintSystem, SynthesisError,
};
use ff::{PrimeField, PrimeFieldBits};

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
    Scalar: PrimeField + PrimeFieldBits,
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
    Scalar: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    let words = state_bytes_to_words(bytes);
    for (i, (&w, num)) in words.iter().zip(shared_limbs.iter()).enumerate() {
        let word = UInt32::alloc(cs.namespace(|| format!("{label}_w{i}")), Some(w))?;
        enforce_num_eq_u32(cs.namespace(|| format!("{label}_eq_{i}")), num, &word)?;
    }
    Ok(())
}

fn enforce_num_eq_u32<Scalar, CS>(
    mut cs: CS,
    num: &AllocatedNum<Scalar>,
    word: &UInt32,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField + PrimeFieldBits,
    CS: ConstraintSystem<Scalar>,
{
    let num_bits = num.to_bits_le(cs.namespace(|| "num_bits"))?;
    let word_bits = word.clone().into_bits_be();
    assert_eq!(word_bits.len(), 32);
    for (j, (a, b)) in num_bits.iter().take(32).zip(word_bits.iter()).enumerate() {
        Boolean::enforce_equal(cs.namespace(|| format!("bit_{j}")), a, b)?;
    }
    Ok(())
}

/// Build `UInt32` SHA limbs wired to shared link slots (same variables as `alloc_digest_shared`).
pub fn u32_words_from_shared<Scalar, CS>(
    mut cs: CS,
    label: &str,
    shared_limbs: &[AllocatedNum<Scalar>],
) -> Result<Vec<UInt32>, SynthesisError>
where
    Scalar: PrimeField + PrimeFieldBits,
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
