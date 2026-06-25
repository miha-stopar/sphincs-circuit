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
//! - Public inputs are **constrained to match** the bytes passed into verify gadgets at setup;
//!   the verifier learns `(PK, M_padded, mlen)` per [DECISIONS.md](../../docs/DECISIONS.md).
//!
//! # Testing
//!
//! ```bash
//! cargo test -p sphincs-circuit verify_public_io::
//! cargo test -p sphincs-prover --features pqclean --test fold_verify_core_hash_message_public_io
//! ```

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
}
