//! Spartan **public IO** encoding for [`circuit_spec::VerifyPublic`].
//!
//! # Layout
//!
//! `public_values()` / `inputize` order for [`sphincs_prover::FoldVerifyCoreCircuit`] when
//! `public_io = true` (see `docs/VERIFY_CORE.md`):
//!
//! ```text
//! scalar[0]           = mlen
//! scalar[1..9]        = pk as 8 big-endian SHA state u32 words (32 bytes)
//! scalar[9..1033]     = message in 128 × 32-byte chunks, 8 words each
//! ```
//!
//! Total: [`circuit_spec::VERIFY_PUBLIC_NUM_SCALARS`] (= 1033).
//!
//! # Scope (Phase 2c step 1)
//!
//! - **Fixed `mlen` per circuit instance** — `mlen` is a public scalar but the `hash_message`
//!   gadget still uses synthesis-time `mlen` for SHA preimage length. Variable public `mlen` in
//!   one universal circuit is a later step (muxed preimage).
//! - With `public_io`, [`crate::hash_msg::synthesize_hash_message_parsed_public`] wires the SHA
//!   preimage from public `pk` / `message` columns (not separate witness bytes).
//!
//! # Testing
//!
//! ```bash
//! cargo test -p sphincs-circuit verify_public_io::
//! cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message_public_io
//! ```

use bellpepper::gadgets::boolean::Boolean;
use bellpepper::gadgets::uint32::UInt32;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circuit_spec::{
    MESSAGE_MAX_BYTES, SPHINCS_PK_BYTES, VERIFY_PUBLIC_MSG_SCALARS, VERIFY_PUBLIC_MLEN_SCALARS,
    VERIFY_PUBLIC_NUM_SCALARS, VERIFY_PUBLIC_PK_SCALARS,
};
use ff::PrimeField;

use crate::sha256_compress::state_bytes_to_words;

/// Inputized Spartan public columns for `(mlen, pk, message_padded)`.
pub struct InputizedVerifyPublic<Scalar: PrimeField> {
    pub mlen: AllocatedNum<Scalar>,
    pub pk_words: [AllocatedNum<Scalar>; VERIFY_PUBLIC_PK_SCALARS],
    pub message_words: Vec<AllocatedNum<Scalar>>,
}

/// Pack `(pk, message, mlen)` into Spartan public scalars (native, no R1CS).
pub fn pack_verify_public<Scalar: PrimeField>(
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8; MESSAGE_MAX_BYTES],
    mlen: usize,
) -> Vec<Scalar> {
    assert!(mlen <= MESSAGE_MAX_BYTES);
    let mut out = Vec::with_capacity(VERIFY_PUBLIC_NUM_SCALARS);
    out.push(Scalar::from(mlen as u64));
    for w in state_bytes_to_words(pk) {
        out.push(Scalar::from(w as u64));
    }
    for chunk in message.chunks_exact(32) {
        let mut block = [0u8; 32];
        block.copy_from_slice(chunk);
        for w in state_bytes_to_words(&block) {
            out.push(Scalar::from(w as u64));
        }
    }
    assert_eq!(out.len(), VERIFY_PUBLIC_NUM_SCALARS);
    out
}

/// Allocate + `inputize` each public scalar (witness must equal `public_values()` at prove time).
pub fn inputize_verify_public<Scalar, CS>(
    mut cs: CS,
    public: &[Scalar],
) -> Result<InputizedVerifyPublic<Scalar>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(public.len(), VERIFY_PUBLIC_NUM_SCALARS);

    let mlen = AllocatedNum::alloc(cs.namespace(|| "pub_mlen"), || Ok(public[0]))?;
    mlen.inputize(cs.namespace(|| "inputize pub_mlen"))?;

    let mut pk_words = Vec::with_capacity(VERIFY_PUBLIC_PK_SCALARS);
    for i in 0..VERIFY_PUBLIC_PK_SCALARS {
        let num = AllocatedNum::alloc(cs.namespace(|| format!("pub_pk_{i}")), || {
            Ok(public[VERIFY_PUBLIC_MLEN_SCALARS + i])
        })?;
        num.inputize(cs.namespace(|| format!("inputize pub_pk_{i}")))?;
        pk_words.push(num);
    }

    let msg_base = VERIFY_PUBLIC_MLEN_SCALARS + VERIFY_PUBLIC_PK_SCALARS;
    let mut message_words = Vec::with_capacity(VERIFY_PUBLIC_MSG_SCALARS);
    for i in 0..VERIFY_PUBLIC_MSG_SCALARS {
        let num = AllocatedNum::alloc(cs.namespace(|| format!("pub_msg_{i}")), || {
            Ok(public[msg_base + i])
        })?;
        num.inputize(cs.namespace(|| format!("inputize pub_msg_{i}")))?;
        message_words.push(num);
    }

    Ok(InputizedVerifyPublic {
        mlen,
        pk_words: pk_words.try_into().expect("pk word count"),
        message_words,
    })
}

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

/// Tie inputized public columns to the byte buffers used by verify gadgets.
///
/// Call **after** padding check when `mlen` is fixed per instance (synthesis-time constant in
/// `hash_message_bits` must match public `mlen` scalar).
pub fn enforce_public_matches_statement<Scalar, CS>(
    mut cs: CS,
    input: &InputizedVerifyPublic<Scalar>,
    pk: &[u8; SPHINCS_PK_BYTES],
    message: &[u8; MESSAGE_MAX_BYTES],
    mlen: usize,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert!(mlen <= MESSAGE_MAX_BYTES);

    let mlen_word = UInt32::alloc(cs.namespace(|| "stmt_mlen"), Some(mlen as u32))?;
    enforce_num_eq_u32(cs.namespace(|| "mlen_eq"), &input.mlen, &mlen_word)?;

    let pk_native = state_bytes_to_words(pk);
    for (i, &w) in pk_native.iter().enumerate() {
        let word = UInt32::alloc(cs.namespace(|| format!("stmt_pk_{i}")), Some(w))?;
        enforce_num_eq_u32(
            cs.namespace(|| format!("pk_eq_{i}")),
            &input.pk_words[i],
            &word,
        )?;
    }

    let mut word_idx = 0;
    for (chunk_i, chunk) in message.chunks_exact(32).enumerate() {
        let mut block = [0u8; 32];
        block.copy_from_slice(chunk);
        for (j, w) in state_bytes_to_words(&block).iter().enumerate() {
            let word = UInt32::alloc(cs.namespace(|| format!("stmt_msg_{chunk_i}_{j}")), Some(*w))?;
            enforce_num_eq_u32(
                cs.namespace(|| format!("msg_eq_{chunk_i}_{j}")),
                &input.message_words[word_idx],
                &word,
            )?;
            word_idx += 1;
        }
    }
    assert_eq!(word_idx, VERIFY_PUBLIC_MSG_SCALARS);

    Ok(())
}

fn scalar_u32_hint<Scalar: PrimeField>(s: Scalar) -> Option<u32> {
    let repr = s.to_repr();
    let bytes = repr.as_ref();
    let mut v = 0u64;
    for (i, b) in bytes.iter().take(8).enumerate() {
        v |= (*b as u64) << (8 * i);
    }
    (v <= u32::MAX as u64).then(|| v as u32)
}

/// Reconstruct public `mlen` as a constrained `UInt32` limb tied to `input.mlen`.
pub fn public_mlen_as_u32<Scalar, CS>(
    mut cs: CS,
    input: &InputizedVerifyPublic<Scalar>,
) -> Result<UInt32, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let hint = input.mlen.get_value().and_then(scalar_u32_hint);
    let word = UInt32::alloc(cs.namespace(|| "pub_mlen_u32"), hint)?;
    enforce_num_eq_u32(cs.namespace(|| "pub_mlen_u32_eq"), &input.mlen, &word)?;
    Ok(word)
}

/// Enforce `0 ≤ public mlen ≤ MESSAGE_MAX_BYTES` (4096 for v1).
///
/// Step B toward variable public `mlen` — does **not** remove the fixed synthesis-time `mlen`
/// on [`sphincs_prover::FoldVerifyCoreCircuit`]; it hardens the public scalar before mux work.
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-circuit enforce_public_mlen_in_range
/// ```
pub fn enforce_public_mlen_in_range<Scalar, CS>(
    mut cs: CS,
    input: &InputizedVerifyPublic<Scalar>,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mlen = public_mlen_as_u32(cs.namespace(|| "mlen_word"), input)?;
    let bits = mlen.into_bits();
    assert_eq!(bits.len(), 32);

    // `mlen` must fit in 13 bits (reject `mlen >= 8192`).
    for (i, bit) in bits.iter().enumerate().skip(13) {
        Boolean::enforce_equal(
            cs.namespace(|| format!("mlen_hi_zero_{i}")),
            bit,
            &Boolean::constant(false),
        )?;
    }

    // If bit 12 is set (`mlen >= 4096`), lower bits must be zero (`mlen == 4096` exactly).
    let bit12 = bits[12].clone();
    let mut lower_active = bits[0].clone();
    for (i, bit) in bits.iter().enumerate().take(12).skip(1) {
        lower_active = Boolean::or(
            cs.namespace(|| format!("mlen_lower_or_{i}")),
            &lower_active,
            bit,
        )?;
    }
    let overflow = Boolean::and(cs.namespace(|| "mlen_overflow_4096"), &bit12, &lower_active)?;
    Boolean::enforce_equal(
        cs.namespace(|| "mlen_not_overflow"),
        &overflow,
        &Boolean::constant(false),
    )?;

    Ok(())
}

/// Public `mlen < 16` — PQClean short `hash_message` seed path (`48 + mlen < 64`).
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-circuit public_mlen_is_short_path
/// ```
pub fn public_mlen_is_short_path<Scalar, CS>(
    mut cs: CS,
    input: &InputizedVerifyPublic<Scalar>,
) -> Result<Boolean, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let mlen = public_mlen_as_u32(cs.namespace(|| "mlen_short"), input)?;
    let bits = mlen.into_bits();
    let mut is_short = Boolean::constant(true);
    for (i, bit) in bits.iter().enumerate().skip(4) {
        is_short = Boolean::and(
            cs.namespace(|| format!("mlen_short_bit_{i}")),
            &is_short,
            &bit.not(),
        )?;
    }
    Ok(is_short)
}

/// SHA-256 preimage bit order (MSB-first per byte) for one big-endian `u32` limb.
fn u32_word_sha_bits(word: &UInt32) -> Vec<Boolean> {
    let le = word.clone().into_bits();
    (0..32).rev().map(|i| le[i].clone()).collect()
}

/// Public `pk` columns → 256 SHA preimage bits, tied to `pk_words` and assignment bytes `pk`.
pub fn public_pk_sha_bits<Scalar, CS>(
    mut cs: CS,
    pk_words: &[AllocatedNum<Scalar>; VERIFY_PUBLIC_PK_SCALARS],
    pk: &[u8; SPHINCS_PK_BYTES],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let words = state_bytes_to_words(pk);
    let mut bits = Vec::with_capacity(SPHINCS_PK_BYTES * 8);
    for (i, &w) in words.iter().enumerate() {
        let word = UInt32::alloc(cs.namespace(|| format!("pk_w{i}")), Some(w))?;
        enforce_num_eq_u32(
            cs.namespace(|| format!("pk_eq_{i}")),
            &pk_words[i],
            &word,
        )?;
        bits.extend(u32_word_sha_bits(&word));
    }
    Ok(bits)
}

/// Public padded `message` columns → `MESSAGE_MAX_BYTES × 8` SHA preimage bits.
pub fn public_message_sha_bits<Scalar, CS>(
    mut cs: CS,
    message_words: &[AllocatedNum<Scalar>],
    message: &[u8; MESSAGE_MAX_BYTES],
) -> Result<Vec<Boolean>, SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert_eq!(message_words.len(), VERIFY_PUBLIC_MSG_SCALARS);
    let mut bits = Vec::with_capacity(MESSAGE_MAX_BYTES * 8);
    for (chunk_i, chunk) in message.chunks_exact(32).enumerate() {
        let mut block = [0u8; 32];
        block.copy_from_slice(chunk);
        let words = state_bytes_to_words(&block);
        for (j, &w) in words.iter().enumerate() {
            let idx = chunk_i * 8 + j;
            let word = UInt32::alloc(cs.namespace(|| format!("msg_w_{chunk_i}_{j}")), Some(w))?;
            enforce_num_eq_u32(
                cs.namespace(|| format!("msg_eq_{chunk_i}_{j}")),
                &message_words[idx],
                &word,
            )?;
            bits.extend(u32_word_sha_bits(&word));
        }
    }
    Ok(bits)
}

/// Enforce `message[mlen..MESSAGE_MAX_BYTES] == 0` on **inputized public** message words.
///
/// Works on full 32-byte chunks wholly at or after `mlen` (v1 padded-message policy). The
/// partial final active chunk still relies on [`enforce_public_matches_statement`] tying public
/// bytes to the honest padded buffer until variable public `mlen` mux lands.
///
/// # Testing
///
/// ```bash
/// cargo test -p sphincs-circuit enforce_public_inactive_chunks_zero
/// ```
pub fn enforce_public_inactive_chunks_zero<Scalar, CS>(
    mut cs: CS,
    input: &InputizedVerifyPublic<Scalar>,
    mlen: usize,
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    assert!(mlen <= MESSAGE_MAX_BYTES);
    let chunks = MESSAGE_MAX_BYTES / 32;
    let words_per_chunk = VERIFY_PUBLIC_MSG_SCALARS / chunks;

    for chunk in 0..chunks {
        if chunk * 32 < mlen {
            continue;
        }
        let base = chunk * words_per_chunk;
        let zero = UInt32::constant(0);
        for j in 0..words_per_chunk {
            enforce_num_eq_u32(
                cs.namespace(|| format!("inactive_zero_{chunk}_{j}")),
                &input.message_words[base + j],
                &zero,
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bellpepper_core::test_cs::TestConstraintSystem;
    use blstrs::Scalar as Fr;
    use circuit_spec::VerifyPublic;

    #[test]
    fn pack_len_matches_layout_constant() {
        let stmt = VerifyPublic::from_message([0xabu8; 32], b"pack test");
        let packed = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, stmt.mlen);
        assert_eq!(packed.len(), VERIFY_PUBLIC_NUM_SCALARS);
        assert_eq!(packed[0], Fr::from(stmt.mlen as u64));
    }

    #[test]
    fn inputize_and_enforce_satisfies_for_honest_statement() {
        let stmt = VerifyPublic::from_message([0x22u8; 32], b"public io roundtrip");
        let public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, stmt.mlen);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let input = inputize_verify_public(&mut cs, &public).expect("inputize");
        enforce_public_matches_statement(
            &mut cs,
            &input,
            &stmt.pk,
            &stmt.message,
            stmt.mlen,
        )
        .expect("enforce");
        assert!(cs.is_satisfied());
    }

    /// Wrong public `mlen` scalar must not satisfy statement bytes.
    #[test]
    fn wrong_public_mlen_unsatisfies() {
        let stmt = VerifyPublic::from_message([0x33u8; 32], b"mlen mismatch");
        let mut public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, stmt.mlen);
        public[0] = Fr::from((stmt.mlen + 1) as u64);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let input = inputize_verify_public(&mut cs, &public).expect("inputize");
        enforce_public_matches_statement(
            &mut cs,
            &input,
            &stmt.pk,
            &stmt.message,
            stmt.mlen,
        )
        .expect("enforce");
        assert!(!cs.is_satisfied());
    }

    #[test]
    fn enforce_public_inactive_chunks_zero_accepts_honest_padding() {
        let stmt = VerifyPublic::from_message([0x44u8; 32], b"tail must be zero on public M");
        let public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, stmt.mlen);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let input = inputize_verify_public(&mut cs, &public).expect("inputize");
        enforce_public_inactive_chunks_zero(&mut cs, &input, stmt.mlen).expect("tail");
        assert!(cs.is_satisfied());
    }

    #[test]
    fn enforce_public_inactive_chunks_zero_rejects_nonzero_tail_chunk() {
        let mut stmt = VerifyPublic::from_message([0x55u8; 32], b"short");
        // Corrupt a byte in an inactive full chunk (chunk 1 starts at byte 32; mlen=5).
        stmt.message[64] = 0x01;
        let public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, stmt.mlen);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let input = inputize_verify_public(&mut cs, &public).expect("inputize");
        enforce_public_inactive_chunks_zero(&mut cs, &input, stmt.mlen).expect("tail");
        assert!(!cs.is_satisfied());
    }

    #[test]
    fn enforce_public_mlen_in_range_accepts_max_and_honest() {
        let stmt = VerifyPublic::from_message([0x77u8; 32], b"mlen range ok");
        let public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, stmt.mlen);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let input = inputize_verify_public(&mut cs, &public).expect("inputize");
        enforce_public_mlen_in_range(&mut cs, &input).expect("range");
        assert!(cs.is_satisfied());

        let mut max_msg = [0u8; MESSAGE_MAX_BYTES];
        max_msg[..4].copy_from_slice(b"max=");
        let max_public = pack_verify_public::<Fr>(&stmt.pk, &max_msg, MESSAGE_MAX_BYTES);
        let mut cs_max = TestConstraintSystem::<Fr>::new();
        let input_max = inputize_verify_public(&mut cs_max, &max_public).expect("inputize");
        enforce_public_mlen_in_range(&mut cs_max, &input_max).expect("range");
        assert!(cs_max.is_satisfied());
    }

    #[test]
    fn enforce_public_mlen_in_range_rejects_too_large() {
        let stmt = VerifyPublic::from_message([0x88u8; 32], b"x");
        let mut public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, stmt.mlen);
        public[0] = Fr::from((MESSAGE_MAX_BYTES + 1) as u64);

        let mut cs = TestConstraintSystem::<Fr>::new();
        let input = inputize_verify_public(&mut cs, &public).expect("inputize");
        enforce_public_mlen_in_range(&mut cs, &input).expect("range");
        assert!(!cs.is_satisfied());
    }

    #[test]
    fn public_mlen_is_short_path_detects_boundary() {
        let pk = [0x99u8; SPHINCS_PK_BYTES];
        for &(mlen, expect_short) in &[(5usize, true), (15, true), (16, false), (100, false)] {
            let stmt = VerifyPublic::from_message(pk, &vec![0u8; mlen]);
            let public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, mlen);
            let mut cs = TestConstraintSystem::<Fr>::new();
            let input = inputize_verify_public(&mut cs, &public).expect("inputize");
            let is_short = public_mlen_is_short_path(&mut cs, &input).expect("path");
            assert_eq!(
                is_short.get_value().unwrap_or(false),
                expect_short,
                "mlen={mlen}"
            );
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn public_pk_sha_bits_matches_native() {
        let pk = [0x66u8; SPHINCS_PK_BYTES];
        let stmt = VerifyPublic::from_message(pk, b"");
        let public = pack_verify_public::<Fr>(&stmt.pk, &stmt.message, stmt.mlen);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let input = inputize_verify_public(&mut cs, &public).expect("inputize");
        let bits = public_pk_sha_bits(&mut cs, &input.pk_words, &pk).expect("pk bits");
        assert_eq!(bits.len(), SPHINCS_PK_BYTES * 8);
        assert!(cs.is_satisfied());
    }
}
