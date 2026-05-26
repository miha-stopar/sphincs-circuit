//! One SHA-256 compression: `h_out = Compress(h_in, block)` (PQClean / RFC 6234 semantics).

use bellpepper::gadgets::boolean::Boolean;
use bellpepper::gadgets::sha256::sha256_compression_function;
use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{ConstraintSystem, SynthesisError};

/// Statistics from synthesizing a single step instance (requires `Comparable` CS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepStats {
    pub num_constraints: usize,
}

/// Parse 32-byte big-endian SHA state into eight `u32` words (PQClean layout).
pub fn state_bytes_to_words(bytes: &[u8; 32]) -> [u32; 8] {
    let mut words = [0u32; 8];
    for (i, word) in words.iter_mut().enumerate() {
        let start = i * 4;
        *word = u32::from_be_bytes(bytes[start..start + 4].try_into().expect("word"));
    }
    words
}

fn block_to_block_bits(block: &[u8; 64]) -> Vec<Boolean> {
    let mut bits = Vec::with_capacity(512);
    for byte in block {
        for bit_i in (0..8).rev() {
            bits.push(Boolean::constant((byte >> bit_i) & 1 == 1));
        }
    }
    bits
}

fn words_from_state_bytes<Scalar, CS>(
    mut cs: CS,
    label: &str,
    bytes: &[u8; 32],
) -> Result<Vec<UInt32>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let words = state_bytes_to_words(bytes);
    words
        .iter()
        .enumerate()
        .map(|(i, &w)| UInt32::alloc(cs.namespace(|| format!("{label}_w{i}")), Some(w)))
        .collect()
}

fn enforce_state_equal<Scalar, CS>(
    mut cs: CS,
    computed: &[UInt32],
    expected_bytes: &[u8; 32],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let expected_words = state_bytes_to_words(expected_bytes);
    for (i, (c, &e)) in computed.iter().zip(expected_words.iter()).enumerate() {
        let exp = UInt32::constant(e);
        for (j, (a, b)) in c
            .clone()
            .into_bits_be()
            .iter()
            .zip(exp.into_bits_be().iter())
            .enumerate()
        {
            Boolean::enforce_equal(cs.namespace(|| format!("h_out_{i}_{j}")), a, b)?;
        }
    }
    Ok(())
}

/// Synthesize `C_step`: constrain `h_out = Compress(h_in, block)`.
pub fn synthesize_compression<Scalar, CS>(
    mut cs: CS,
    h_in: &[u8; 32],
    block: &[u8; 64],
    h_out: &[u8; 32],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let h_words = words_from_state_bytes(cs.namespace(|| "h_in"), "h_in", h_in)?;
    let block_bits = block_to_block_bits(block);

    let out_words = sha256_compression_function(
        cs.namespace(|| "compress"),
        &block_bits,
        &h_words,
    )?;

    enforce_state_equal(
        cs.namespace(|| "h_out_eq"),
        &out_words,
        h_out,
    )
}

/// Like [`synthesize_compression`], also return constraint count (test / bench helper).
pub fn synthesize_compression_with_stats<Scalar, CS>(
    mut cs: CS,
    h_in: &[u8; 32],
    block: &[u8; 64],
    h_out: &[u8; 32],
) -> Result<StepStats, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar> + bellpepper_core::Comparable<Scalar>,
{
    let before = cs.num_constraints();
    synthesize_compression(&mut cs, h_in, block, h_out)?;
    Ok(StepStats {
        num_constraints: cs.num_constraints() - before,
    })
}
