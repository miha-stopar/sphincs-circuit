//! PQClean trace ↔ `hash_message` compression span (variable-`mlen` step E).
//!
//! Locates the seed-SHA and MGF1 local chains in a verify trace and provides
//! exact compression counts from SHA-256 padding math (validated against PQClean).

use bellpepper::gadgets::boolean::Boolean;
use bellpepper_core::{num::AllocatedNum, ConstraintSystem, SynthesisError};
use circuit_spec::{Sha256Compression, SPHINCS_PK_BYTES};
use ff::PrimeField;

use crate::hash_msg::{
    hash_message_seed_path, hash_message_tail_message_bytes, mgf1_digest_bits, HashMessageSeedPath,
    HASH_MESSAGE_INBUF_BYTES, HASH_MESSAGE_PREFIX_BYTES, SPX_DGST_BYTES, SPX_PK_BYTES,
};
use crate::thash::enforce_bits_equal_bytes;
use crate::sha256_compress::{
    sha256_state_words_to_bits_be, synthesize_compression_chain_for_fold_with_shared,
};
use crate::step::StepInput;
use crate::thash::SPX_N;
use crate::witness::LocalChain;

/// Number of SHA-256 compressions for one-shot digest of `byte_len` bytes from the IV.
pub fn sha256_compression_count_fresh(byte_len: usize) -> usize {
    let mut total = byte_len + 1 + 8;
    while total % 64 != 0 {
        total += 1;
    }
    total / 64
}

/// Compressions for `sha256_inc_finalize` after one full 64-byte `inc_blocks` absorb.
pub fn sha256_compression_count_after_full_block(tail_byte_len: usize) -> usize {
    let stream_len = HASH_MESSAGE_INBUF_BYTES + tail_byte_len;
    sha256_compression_count_fresh(stream_len).saturating_sub(1)
}

/// Seed-SHA compressions in PQClean `hash_message` for message length `mlen`.
pub fn hash_message_seed_compression_count(mlen: usize) -> usize {
    match hash_message_seed_path(mlen) {
        HashMessageSeedPath::ShortFinalize => {
            sha256_compression_count_fresh(HASH_MESSAGE_PREFIX_BYTES + mlen)
        }
        HashMessageSeedPath::LongBlockThenFinalize => {
            1 + sha256_compression_count_after_full_block(hash_message_tail_message_bytes(mlen))
        }
    }
}

/// MGF1 compressions for 128s (`SPX_DGST_BYTES` = 30 → one truncated SHA-256 on 52 bytes).
pub fn hash_message_mgf1_compression_count() -> usize {
    sha256_compression_count_fresh(48 + 4)
}

/// Exact `hash_message` compression count (seed + MGF1) for folding / trace alignment.
pub fn hash_message_compression_count_exact(mlen: usize) -> usize {
    hash_message_seed_compression_count(mlen) + hash_message_mgf1_compression_count()
}

/// Contiguous seed-SHA + MGF1 compression ranges inside a verify trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMessageTraceSpan {
    pub seed: LocalChain,
    pub mgf1: LocalChain,
}

impl HashMessageTraceSpan {
    pub fn total_compressions(&self) -> usize {
        self.seed.len + self.mgf1.len
    }

    /// Contiguous trace indices covering seed-SHA and MGF1.
    pub fn full_chain(&self) -> LocalChain {
        LocalChain {
            start: self.seed.start,
            end: self.mgf1.end,
            len: self.total_compressions(),
        }
    }
}

fn pk_seed_bytes(pk: &[u8; SPHINCS_PK_BYTES]) -> [u8; SPX_N] {
    let mut out = [0u8; SPX_N];
    out.copy_from_slice(&pk[..SPX_N]);
    out
}

fn block_starts_with_hash_message_seed(
    block: &[u8; 64],
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
) -> bool {
    block[..SPX_N] == *r && block[SPX_N..SPX_N + SPX_PK_BYTES] == pk[..]
}

/// MGF1 preimage starts with `R ‖ pk_seed ‖ seed_hash[0..16]` (not `PK.root` at bytes 32–48).
fn block_starts_with_mgf1_seed(
    block: &[u8; 64],
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
) -> bool {
    let pk_seed = pk_seed_bytes(pk);
    block[..SPX_N] == *r
        && block[SPX_N..2 * SPX_N] == pk_seed
        && block[2 * SPX_N..SPX_N + SPX_PK_BYTES] != pk[SPX_N..]
}

fn extend_local_chain(compressions: &[Sha256Compression], start: usize) -> LocalChain {
    let mut end = start;
    while end + 1 < compressions.len() && compressions[end].h_out == compressions[end + 1].h_in {
        end += 1;
    }
    LocalChain {
        start,
        end,
        len: end - start + 1,
    }
}

/// Locate `hash_message` seed + MGF1 chains in a PQClean verify compression trace.
///
/// Returns the **first** span whose seed chain is immediately followed by an MGF1 round-0 block.
/// When `mlen` is known, prefer [`locate_hash_message_trace_span_for_mlen`] to disambiguate
/// rare collisions (e.g. all-zero 16-byte message on the long-path boundary).
pub fn locate_hash_message_trace_span(
    compressions: &[Sha256Compression],
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
) -> Option<HashMessageTraceSpan> {
    for (i, row) in compressions.iter().enumerate() {
        if !block_starts_with_hash_message_seed(&row.block, r, pk) {
            continue;
        }

        let seed = extend_local_chain(compressions, i);
        let mgf_start = seed.end + 1;
        if mgf_start >= compressions.len() {
            continue;
        }
        let mgf_row = &compressions[mgf_start];
        if !block_starts_with_mgf1_seed(&mgf_row.block, r, pk) {
            continue;
        }
        let mgf_len = hash_message_mgf1_compression_count();
        if mgf_start + mgf_len > compressions.len() {
            continue;
        }
        let mgf1 = LocalChain {
            start: mgf_start,
            end: mgf_start + mgf_len - 1,
            len: mgf_len,
        };
        return Some(HashMessageTraceSpan { seed, mgf1 });
    }
    None
}

/// Locate span and verify compression counts match [`hash_message_compression_count_exact`].
pub fn locate_hash_message_trace_span_for_mlen(
    compressions: &[Sha256Compression],
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
    mlen: usize,
) -> Option<HashMessageTraceSpan> {
    let span = locate_hash_message_trace_span(compressions, r, pk)?;
    if span.seed.len != hash_message_seed_compression_count(mlen) {
        return None;
    }
    if span.mgf1.len != hash_message_mgf1_compression_count() {
        return None;
    }
    Some(span)
}

fn constant_bits(bytes: &[u8]) -> Vec<Boolean> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).rev().map(move |i| Boolean::constant((byte >> i) & 1 == 1)))
        .collect()
}

/// `hash_message` with seed-SHA from folded trace rows wired to NeutronNova `shared` links.
///
/// MGF1 still uses the one-shot bellpepper SHA gadget. `seed_rows.len()` must be ≥ 2 and
/// `shared.len() == (seed_rows.len() - 1) * DIGEST_WORDS`.
pub fn synthesize_hash_message_with_seed_trace<Scalar, CS>(
    mut cs: CS,
    r: &[u8; SPX_N],
    pk: &[u8; SPHINCS_PK_BYTES],
    seed_rows: &[StepInput],
    expected_mgf: &[u8; SPX_DGST_BYTES],
    shared: &[AllocatedNum<Scalar>],
) -> Result<(), SynthesisError>
where
    Scalar: PrimeField,
    CS: ConstraintSystem<Scalar>,
{
    let final_words = synthesize_compression_chain_for_fold_with_shared(
        cs.namespace(|| "seed_chain"),
        seed_rows,
        shared,
    )?;

    let mut seed_bits = constant_bits(r);
    seed_bits.extend(constant_bits(&pk[..SPX_N]));
    seed_bits.extend(sha256_state_words_to_bits_be(&final_words));

    let mgf_bits = mgf1_digest_bits(cs.namespace(|| "mgf1"), &seed_bits, SPX_DGST_BYTES)?;
    enforce_bits_equal_bytes(cs.namespace(|| "mgf_out"), &mgf_bits, expected_mgf)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sphincs_ref::{sign_deterministic, verify_with_trace, CRYPTO_SEEDBYTES};

    fn trace_rows(msg: &[u8]) -> ([u8; SPHINCS_PK_BYTES], [u8; SPX_N], Vec<Sha256Compression>) {
        let seed = [0x2au8; CRYPTO_SEEDBYTES];
        let (pk, sig) = sign_deterministic(&seed, msg).expect("sign");
        let trace = verify_with_trace(&pk, msg, &sig).expect("trace");
        let r: [u8; SPX_N] = sig[..SPX_N].try_into().expect("R");
        let rows: Vec<Sha256Compression> = trace
            .compressions
            .into_iter()
            .map(|r| Sha256Compression {
                index: r.index,
                h_in: r.h_in,
                block: r.block,
                h_out: r.h_out,
            })
            .collect();
        (pk, r, rows)
    }

    #[test]
    fn sha256_compression_count_fresh_known_values() {
        assert_eq!(sha256_compression_count_fresh(0), 1);
        assert_eq!(sha256_compression_count_fresh(55), 1);
        assert_eq!(sha256_compression_count_fresh(56), 2);
        assert_eq!(sha256_compression_count_fresh(64), 2);
    }

    #[test]
    fn hash_message_seed_count_short_long_boundary() {
        assert_eq!(hash_message_seed_compression_count(15), 2);
        assert_eq!(hash_message_seed_compression_count(16), 2);
        assert_eq!(
            crate::hash_msg::hash_message_first_block_message_bytes(16),
            HASH_MESSAGE_INBUF_BYTES - HASH_MESSAGE_PREFIX_BYTES
        );
    }

    #[test]
    fn hash_message_compression_count_exact_matches_pqclean_trace() {
        for (msg, mlen) in [
            (b"short".as_slice(), 5usize),
            (vec![0u8; 15].as_slice(), 15usize),
            (vec![0u8; 33].as_slice(), 33usize),
            (vec![0xabu8; 512].as_slice(), 512usize),
        ] {
            let (pk, r, rows) = trace_rows(msg);
            let span =
                locate_hash_message_trace_span_for_mlen(&rows, &r, &pk, mlen).expect("locate");
            assert_eq!(
                span.total_compressions(),
                hash_message_compression_count_exact(mlen),
                "mlen={mlen}"
            );
            assert_eq!(span.mgf1.len, hash_message_mgf1_compression_count());
        }
    }

    #[test]
    fn hash_message_compression_count_grows_with_mlen() {
        assert!(
            hash_message_compression_count_exact(0) < hash_message_compression_count_exact(128)
        );
        assert!(
            hash_message_compression_count_exact(128) <= hash_message_compression_count_exact(512)
        );
    }

    #[test]
    fn hash_message_seed_trace_linked_satisfies() {
        use bellpepper_core::test_cs::TestConstraintSystem;
        use blstrs::Scalar as Fr;
        use crate::hash_msg::hash_message_mgf_buf;
        use crate::shared_link::alloc_digest_shared;
        use crate::witness::step_input_from_row;

        let msg = vec![0u8; 15];
        let (pk, r, rows) = trace_rows(&msg);
        let span = locate_hash_message_trace_span_for_mlen(&rows, &r, &pk, 15).expect("span");
        let seed_inputs: Vec<StepInput> = rows[span.seed.start..=span.seed.end]
            .iter()
            .map(step_input_from_row)
            .collect();
        assert_eq!(seed_inputs.len(), 2);

        let hm_mgf = hash_message_mgf_buf(&r, &pk, &msg, 15);
        let link = rows[span.seed.start].h_out;

        let mut cs = TestConstraintSystem::<Fr>::new();
        let shared = alloc_digest_shared(&mut cs, "link0", link).expect("shared");
        synthesize_hash_message_with_seed_trace(
            &mut cs,
            &r,
            &pk,
            &seed_inputs,
            &hm_mgf,
            &shared,
        )
        .expect("synth");
        assert!(cs.is_satisfied());
    }

    #[test]
    fn hash_message_exact_within_rough_budget() {
        use crate::hash_msg::hash_message_compression_budget;
        for mlen in [0usize, 15, 16, 33, 128, 512] {
            let exact = hash_message_compression_count_exact(mlen);
            let budget = hash_message_compression_budget(mlen);
            assert!(
                exact <= budget + 1,
                "mlen={mlen} exact={exact} budget={budget}"
            );
        }
    }
}
