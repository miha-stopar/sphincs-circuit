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

/// One-hot multiplexer: returns `sum_k sel[k] * vals[k]`.
///
/// Caller must guarantee `sel` is one-hot (exactly one `1`) or all-zero; this is what makes the
/// result equal a single selected `vals[k]` (or `0`). Used to pick a shared link slot for a
/// folded step whose position is encoded as a witness selector, keeping the R1CS shape identical
/// across all NeutronNova step instances.
pub fn one_hot_select<Scalar, CS>(
    mut cs: CS,
    sel: &[AllocatedNum<Scalar>],
    vals: &[AllocatedNum<Scalar>],
) -> Result<AllocatedNum<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(sel.len(), vals.len());
    let mut prods = Vec::with_capacity(sel.len());
    for (k, (s, v)) in sel.iter().zip(vals.iter()).enumerate() {
        prods.push(s.mul(cs.namespace(|| format!("prod_{k}")), v)?);
    }
    let val: Option<Scalar> = prods
        .iter()
        .try_fold(Scalar::ZERO, |acc, p| p.get_value().map(|v| acc + v));
    let result = AllocatedNum::alloc(cs.namespace(|| "select"), || {
        val.ok_or(SynthesisError::AssignmentMissing)
    })?;
    cs.enforce(
        || "select_sum",
        |lc| {
            let mut lc = lc;
            for p in &prods {
                lc = lc + p.get_variable();
            }
            lc
        },
        |lc| lc + CS::one(),
        |lc| lc + result.get_variable(),
    );
    Ok(result)
}

/// Enforce `(1 - gate) * (link - value(word)) == 0`.
///
/// When `gate == 1` (a boundary step that has no link on this side) the equality is skipped;
/// otherwise the shared limb `link` must equal the numeric value of the 32-bit `word`.
pub fn enforce_cond_link_eq_u32<Scalar, CS>(
    mut cs: CS,
    gate: &AllocatedNum<Scalar>,
    link: &AllocatedNum<Scalar>,
    word: &UInt32,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let bits = word.clone().into_bits();
    assert_eq!(bits.len(), 32);
    cs.enforce(
        || "cond_link_eq",
        |lc| lc + CS::one() - gate.get_variable(),
        |lc| {
            let mut lc = lc + link.get_variable();
            let mut coeff = Scalar::ONE;
            for b in &bits {
                lc = lc - &b.lc(CS::one(), coeff);
                coeff = coeff.double();
            }
            lc
        },
        |lc| lc,
    );
    Ok(())
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

    const SHA256_IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    #[test]
    fn enforce_words_eq_shared_compress_gadget_output_is_satisfied() {
        use crate::sha256_compress::{
            state_bytes_to_words, synthesize_compression_for_fold_h_words,
        };

        type Scalar = blstrs::Scalar;
        let mut h_in = [0u8; 32];
        for (i, &w) in SHA256_IV.iter().enumerate() {
            h_in[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        let block = [0u8; 64];
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let h_words: Vec<UInt32> = state_bytes_to_words(&h_in)
            .iter()
            .enumerate()
            .map(|(i, &w)| {
                UInt32::alloc(cs.namespace(|| format!("h_in_w{i}")), Some(w)).unwrap()
            })
            .collect();
        let out_words =
            synthesize_compression_for_fold_h_words(&mut cs, &h_words, &block).unwrap();
        let mut h_out = [0u8; 32];
        for (i, word) in out_words.iter().enumerate() {
            let mut w = 0u32;
            for (j, bit) in word.clone().into_bits().iter().enumerate() {
                if bit.get_value() == Some(true) {
                    w |= 1 << j;
                }
            }
            h_out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        let shared = alloc_digest_shared(&mut cs, "s", h_out).unwrap();
        enforce_words_eq_shared(&mut cs, "step", &out_words, &shared).unwrap();
        assert!(
            cs.is_satisfied(),
            "gadget out-pin unsatisfied: {:?}",
            cs.which_is_unsatisfied()
        );
    }

    #[test]
    fn u32_words_from_shared_then_compress_is_satisfied() {
        use crate::sha256_compress::synthesize_compression_for_fold_h_words;

        type Scalar = blstrs::Scalar;
        let mut h_in = [0u8; 32];
        for (i, &w) in SHA256_IV.iter().enumerate() {
            h_in[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        let block = [1u8; 64];
        let mut cs = TestConstraintSystem::<Scalar>::new();
        let shared = alloc_digest_shared(&mut cs, "link0", h_in).unwrap();
        let h_words = u32_words_from_shared(&mut cs, "h_in", &shared).unwrap();
        let _out =
            synthesize_compression_for_fold_h_words(&mut cs, &h_words, &block).unwrap();
        assert!(
            cs.is_satisfied(),
            "shared h_in compress unsatisfied: {:?}",
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
