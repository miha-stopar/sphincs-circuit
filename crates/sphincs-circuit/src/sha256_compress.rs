//! One SHA-256 compression: `h_out = Compress(h_in, block)` (PQClean / RFC 6234 semantics).

use bellpepper::gadgets::boolean::Boolean;
use bellpepper::gadgets::sha256::sha256_compression_function;
use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{
    boolean::AllocatedBit,
    ConstraintSystem, SynthesisError,
};

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

fn block_to_allocated_bits<Scalar, CS>(
    mut cs: CS,
    block: &[u8; 64],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    block
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1 == 1))
        .enumerate()
        .map(|(i, b)| {
            AllocatedBit::alloc(cs.namespace(|| format!("block bit {i}")), Some(b)).map(Boolean::from)
        })
        .collect()
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

/// Like [`enforce_state_equal`], but expected output words are allocated witnesses.
///
/// NeutronNova requires output pins to be witnesses, not constants (see
/// `synthesize_compression_allocated_block`).
fn enforce_state_equal_allocated<Scalar, CS>(
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
        let exp = UInt32::alloc(cs.namespace(|| format!("h_out_w{i}")), Some(e))?;
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

/// NeutronNova step synthesis: allocated `h_in` + block bits; output follows from compression.
///
/// Omits explicit `h_out` equality because pinning digest bytes breaks NeutronNova verify
/// (Spartan2 0.9.0); output is still uniquely determined by `(h_in, block)`.
pub fn synthesize_compression_for_fold<Scalar, CS>(
    cs: CS,
    h_in: &[u8; 32],
    block: &[u8; 64],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let _out_words = synthesize_compression_for_fold_with_out(cs, h_in, block)?;
    Ok(())
}

/// Like [`synthesize_compression_for_fold`], but return the compression output words for glue.
pub fn synthesize_compression_for_fold_with_out<Scalar, CS>(
    mut cs: CS,
    h_in: &[u8; 32],
    block: &[u8; 64],
) -> Result<Vec<UInt32>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let h_words = words_from_state_bytes(cs.namespace(|| "h_in"), "h_in", h_in)?;
    synthesize_compression_for_fold_h_words(cs, &h_words, block)
}

/// One compression with caller-supplied `h_in` words (for shared-link chaining).
pub fn synthesize_compression_for_fold_h_words<Scalar, CS>(
    mut cs: CS,
    h_words: &[UInt32],
    block: &[u8; 64],
) -> Result<Vec<UInt32>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(h_words.len(), 8);
    let block_bits = block_to_allocated_bits(cs.namespace(|| "block"), block)?;
    sha256_compression_function(
        cs.namespace(|| "compress"),
        &block_bits,
        h_words,
    )
}

/// One PQClean trace row in core glue: allocated block + enforced `h_out` witness.
///
/// # SOUNDNESS WARNING
///
/// `h_in` and `block` are **free witnesses** (only `h_out == Compress(h_in, block)` is enforced).
/// This does **not** bind the compression input to any statement, so it must not be used to prove
/// `hash_message` over a fixed message. `hash_message` reconstructs the seed blocks from
/// `(R, PK, M)` instead — see [`crate::hash_message_trace`] and `docs/SOUNDNESS_AUDIT.md` BUG-1.
/// Kept only for generic compression-chain experiments where the inputs are bound elsewhere.
pub fn synthesize_compression_trace_row_for_fold<Scalar, CS>(
    mut cs: CS,
    row: &crate::step::StepInput,
) -> Result<Vec<UInt32>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    use crate::chain::enforce_sha256_words_equal;

    let h_words = words_from_state_bytes(cs.namespace(|| "h_in"), "h_in", &row.h_in)?;
    let block_bits = block_to_allocated_bits(cs.namespace(|| "block"), &row.block)?;
    let out_words = sha256_compression_function(
        cs.namespace(|| "compress"),
        &block_bits,
        &h_words,
    )?;
    let expected = words_from_state_bytes(cs.namespace(|| "h_out"), "h_out", &row.h_out)?;
    enforce_sha256_words_equal(cs.namespace(|| "h_out_eq"), &out_words, &expected)?;
    Ok(out_words)
}

/// Like [`synthesize_compression_for_fold`], but wire `h_out[i] == h_in[i+1]` between rows.
///
/// Row `i+1` uses the compression output wires of row `i` as `h_in` (sound in-circuit chain).
/// `rows` must have length ≥ 2. Each tuple is `(h_in, block, h_out)`.
pub fn synthesize_compression_chain_for_fold<Scalar, CS>(
    mut cs: CS,
    rows: &[([u8; 32], [u8; 64], [u8; 32])],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    use crate::chain::enforce_sha256_words_equal;

    assert!(rows.len() >= 2);

    let block_bits_0 = block_to_allocated_bits(cs.namespace(|| "block_0"), &rows[0].1)?;
    let mut h_words = words_from_state_bytes(cs.namespace(|| "h_in_0"), "h_in_0", &rows[0].0)?;
    let mut out_words = sha256_compression_function(
        cs.namespace(|| "compress_0"),
        &block_bits_0,
        &h_words,
    )?;

    for (i, row) in rows.iter().enumerate().skip(1) {
        h_words = out_words;
        let block_bits =
            block_to_allocated_bits(cs.namespace(|| format!("block_{i}")), &row.1)?;
        out_words = sha256_compression_function(
            cs.namespace(|| format!("compress_{i}")),
            &block_bits,
            &h_words,
        )?;
    }

    let expected = words_from_state_bytes(
        cs.namespace(|| "h_out_last"),
        "h_out_last",
        &rows[rows.len() - 1].2,
    )?;
    enforce_sha256_words_equal(cs.namespace(|| "last_out_eq"), &out_words, &expected)?;

    Ok(())
}

/// Like [`synthesize_compression_chain_for_fold`], plus **core glue**: at each internal
/// boundary `i`, the compression output wires for row `i` equal `links[i].0` and `links[i].1`
/// (trace-supplied). Row `i+1` already uses those wires as `h_in`, so this binds the core’s
/// boundary witnesses to the folded step wires in one Spartan circuit.
pub fn synthesize_compression_chain_for_fold_with_links<Scalar, CS>(
    mut cs: CS,
    rows: &[([u8; 32], [u8; 64], [u8; 32])],
    links: &[([u8; 32], [u8; 32])],
) -> Result<(), SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    use crate::chain::{enforce_digest_bytes_eq_words, enforce_sha256_words_equal};

    assert!(rows.len() >= 2);
    assert_eq!(links.len(), rows.len() - 1);

    let block_bits_0 = block_to_allocated_bits(cs.namespace(|| "block_0"), &rows[0].1)?;
    let mut h_words = words_from_state_bytes(cs.namespace(|| "h_in_0"), "h_in_0", &rows[0].0)?;
    let mut out_words = sha256_compression_function(
        cs.namespace(|| "compress_0"),
        &block_bits_0,
        &h_words,
    )?;

    for (i, row) in rows.iter().enumerate().skip(1) {
        let (left, right) = &links[i - 1];
        enforce_digest_bytes_eq_words(
            cs.namespace(|| format!("core_link_{}_out", i - 1)),
            "wire_out",
            &out_words,
            left,
        )?;
        enforce_digest_bytes_eq_words(
            cs.namespace(|| format!("core_link_{}_in", i - 1)),
            "wire_in",
            &out_words,
            right,
        )?;

        h_words = out_words;
        let block_bits =
            block_to_allocated_bits(cs.namespace(|| format!("block_{i}")), &row.1)?;
        out_words = sha256_compression_function(
            cs.namespace(|| format!("compress_{i}")),
            &block_bits,
            &h_words,
        )?;
    }

    let expected = words_from_state_bytes(
        cs.namespace(|| "h_out_last"),
        "h_out_last",
        &rows[rows.len() - 1].2,
    )?;
    enforce_sha256_words_equal(cs.namespace(|| "last_out_eq"), &out_words, &expected)?;

    Ok(())
}

/// Like [`synthesize_compression_chain_for_fold`], but internal boundaries are wired to
/// NeutronNova `shared` link limbs (same variables as [`FoldStepBoundCircuit`]).
///
/// Returns the final compression output words (SHA-256 state after the last row).
///
/// # SOUNDNESS WARNING
///
/// As with [`synthesize_compression_trace_row_for_fold`], the per-row `h_in` / `block` are free
/// witnesses. Do **not** use this for `hash_message`; it does not bind the hashed bytes to the
/// statement. See `docs/SOUNDNESS_AUDIT.md` BUG-1.
pub fn synthesize_compression_chain_for_fold_with_shared<Scalar, CS>(
    mut cs: CS,
    rows: &[crate::step::StepInput],
    shared: &[bellpepper_core::num::AllocatedNum<Scalar>],
) -> Result<Vec<UInt32>, SynthesisError>
where
    Scalar: ff::PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    use crate::chain::enforce_sha256_words_equal;
    use crate::shared_link::{enforce_words_eq_shared, link_shared_slice, DIGEST_WORDS};

    assert!(rows.len() >= 2);
    assert_eq!(shared.len(), (rows.len() - 1) * DIGEST_WORDS);

    let block_bits_0 = block_to_allocated_bits(cs.namespace(|| "block_0"), &rows[0].block)?;
    let mut h_words = words_from_state_bytes(cs.namespace(|| "h_in_0"), "h_in_0", &rows[0].h_in)?;
    let mut out_words = sha256_compression_function(
        cs.namespace(|| "compress_0"),
        &block_bits_0,
        &h_words,
    )?;

    for (i, row) in rows.iter().enumerate().skip(1) {
        enforce_words_eq_shared(
            cs.namespace(|| format!("shared_link_{}", i - 1)),
            "h_out",
            &out_words,
            link_shared_slice(shared, i - 1),
        )?;
        h_words = out_words;
        let block_bits =
            block_to_allocated_bits(cs.namespace(|| format!("block_{i}")), &row.block)?;
        out_words = sha256_compression_function(
            cs.namespace(|| format!("compress_{i}")),
            &block_bits,
            &h_words,
        )?;
    }

    let expected = words_from_state_bytes(
        cs.namespace(|| "h_out_last"),
        "h_out_last",
        &rows[rows.len() - 1].h_out,
    )?;
    enforce_sha256_words_equal(cs.namespace(|| "last_out_eq"), &out_words, &expected)?;

    Ok(out_words)
}

/// Big-endian bit decomposition of eight SHA state `u32` limbs (256 bits).
pub fn sha256_state_words_to_bits_be(words: &[UInt32]) -> Vec<Boolean> {
    let mut bits = Vec::with_capacity(256);
    for word in words {
        bits.extend(word.clone().into_bits_be());
    }
    bits
}

/// Like [`synthesize_compression`], but allocate the 512 block bits as witnesses.
///
/// Uses allocated expected `h_out` words (for oracle tests on T256). Not compatible
/// with NeutronNova prove/verify in Spartan2 0.9.0 — use [`synthesize_compression_for_fold`].
pub fn synthesize_compression_allocated_block<Scalar, CS>(
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
    let block_bits = block_to_allocated_bits(cs.namespace(|| "block"), block)?;

    let out_words = sha256_compression_function(
        cs.namespace(|| "compress"),
        &block_bits,
        &h_words,
    )?;

    enforce_state_equal_allocated(
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
